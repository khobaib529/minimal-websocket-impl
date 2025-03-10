// realtime_file_monitor.cpp
//
// This program monitors changes in a specified file and updates a webpage in
// real-time. It leverages the inotify API to detect file modifications and runs
// an HTTP server that serves the file content. WebSocket connections are used
// to push live updates to the webpage.
//
// Usage: realtime_file_monitor <file-path>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <list>
#include <sstream>
#include <string>
#include <vector>

#define PORT 8080
#define BUFFER_SIZE 1024
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))
#define WEBSOCKET_MAGIC "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Global variables
std::list<int> Clients;
std::string FileContent;

// SHA-1 context structure
struct Sha1Ctx {
  uint32_t state[5];
  uint32_t count[2];
  unsigned char buffer[64];
};

// Function prototypes
void SendWsMessage(int sock, const std::string& data);
void HandleHandshake(int sock, const std::string& clientKey);
std::string Base64Encode(const unsigned char* input, int input_len);
bool LoadFile(const std::string& path);
void BroadcastToClients(const std::string& message);
void AddClient(int sock);
void RemoveClient(int sock);
void ProcessNewConnection(int server_fd, const std::string& filePath);
void ProcessClientMessages(fd_set* fds);
std::string GenerateHtmlResponse();

// SHA-1 function prototypes
void Sha1Transform(uint32_t state[5], const unsigned char buffer[64]);
void Sha1Init(Sha1Ctx* context);
void Sha1Update(Sha1Ctx* context, const unsigned char* data, uint32_t len);
void Sha1Final(unsigned char digest[20], Sha1Ctx* context);

// -------------------------------------------------------------------------
// SendWsMessage: Sends a WebSocket text frame to the given socket.
// -------------------------------------------------------------------------
void SendWsMessage(int sock, const std::string& data) {
  unsigned char header[4];
  size_t headerLen = 2;
  header[0] = 0x81;  // FIN set and text frame opcode

  size_t len = data.size();
  if (len <= 125) {
    header[1] = static_cast<unsigned char>(len);
  } else {
    header[1] = 126;
    uint16_t len16 = htons(static_cast<uint16_t>(len));
    std::memcpy(header + 2, &len16, sizeof(uint16_t));
    headerLen = 4;
  }
  send(sock, header, headerLen, 0);
  send(sock, data.c_str(), len, 0);
}

// -------------------------------------------------------------------------
// HandleHandshake: Performs WebSocket handshake using SHA-1 and Base64.
// -------------------------------------------------------------------------
void HandleHandshake(int sock, const std::string& clientKey) {
  std::string combined = clientKey + WEBSOCKET_MAGIC;

  unsigned char sha1Result[20];
  Sha1Ctx ctx;
  Sha1Init(&ctx);
  Sha1Update(&ctx, reinterpret_cast<const unsigned char*>(combined.c_str()),
             combined.size());
  Sha1Final(sha1Result, &ctx);

  std::string b64 = Base64Encode(sha1Result, 20);

  char response[256];
  std::snprintf(response, sizeof(response),
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n\r\n",
                b64.c_str());
  send(sock, response, std::strlen(response), 0);
}

// -------------------------------------------------------------------------
// Base64Encode: Encodes input bytes into a Base64 string.
// -------------------------------------------------------------------------
std::string Base64Encode(const unsigned char* input, int input_len) {
  const char base64_chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string output;
  int i = 0;
  unsigned char char_array_3[3], char_array_4[4];

  while (input_len--) {
    char_array_3[i++] = *(input++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] =
          ((char_array_3[0] & 0x03) << 4) | ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] =
          ((char_array_3[1] & 0x0f) << 2) | ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;
      for (i = 0; i < 4; i++) output.push_back(base64_chars[char_array_4[i]]);
      i = 0;
    }
  }
  if (i) {
    for (int j = i; j < 3; j++) char_array_3[j] = '\0';
    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] =
        ((char_array_3[0] & 0x03) << 4) | ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] =
        ((char_array_3[1] & 0x0f) << 2) | ((char_array_3[2] & 0xc0) >> 6);
    for (int j = 0; j < i + 1; j++)
      output.push_back(base64_chars[char_array_4[j]]);
    while (i++ < 3) output.push_back('=');
  }
  return output;
}

// -------------------------------------------------------------------------
// LoadFile: Loads the entire file into memory and updates global FileContent.
// -------------------------------------------------------------------------
bool LoadFile(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) return false;
  std::ostringstream oss;
  oss << file.rdbuf();
  FileContent = oss.str();
  return true;
}

// -------------------------------------------------------------------------
// BroadcastToClients: Sends a message to all connected WebSocket clients.
// -------------------------------------------------------------------------
void BroadcastToClients(const std::string& message) {
  for (int sock : Clients) {
    SendWsMessage(sock, message);
  }
}

// -------------------------------------------------------------------------
// AddClient: Adds a new client socket to the list.
// -------------------------------------------------------------------------
void AddClient(int sock) { Clients.push_back(sock); }

// -------------------------------------------------------------------------
// RemoveClient: Removes a client socket from the list and closes it.
// -------------------------------------------------------------------------
void RemoveClient(int sock) {
  Clients.remove(sock);
  close(sock);
}

// -------------------------------------------------------------------------
// GenerateHtmlResponse: Dynamically generates HTML with current file content.
// -------------------------------------------------------------------------
std::string GenerateHtmlResponse() {
  const char* html_template =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html\r\n"
      "Connection: close\r\n"
      "\r\n"
      "<html>\n"
      "<head>\n"
      "  <meta charset=\"UTF-8\">\n"
      "  <title>File Monitor</title>\n"
      "  <style>\n"
      "    body { margin: 0; padding: 0; display: flex; align-items: center; "
      "justify-content: center; height: 100vh; background-color: #f7f7f7; "
      "font-family: Arial, sans-serif; }\n"
      "    .container { width: 80%%; max-width: 800px; text-align: center; }\n"
      "    pre { background: #eee; padding: 20px; border: 1px solid #ccc; "
      "overflow: auto; text-align: left; }\n"
      "  </style>\n"
      "</head>\n"
      "<body>\n"
      "  <div class=\"container\">\n"
      "    <h1>File Monitor</h1>\n"
      "    <pre id=\"content\">%s</pre>\n"
      "  </div>\n"
      "  <script>\n"
      "    const ws = new WebSocket('ws://' + location.host);\n"
      "    ws.onmessage = e => document.getElementById('content').textContent "
      "= e.data;\n"
      "  </script>\n"
      "</body>\n"
      "</html>\n";

  int size_needed =
      std::snprintf(nullptr, 0, html_template, FileContent.c_str());
  std::vector<char> response(size_needed + 1);
  std::snprintf(response.data(), response.size(), html_template,
                FileContent.c_str());
  return std::string(response.data());
}

// -------------------------------------------------------------------------
// ProcessNewConnection: Accepts a new connection, performs a WebSocket
// handshake if requested, or serves the HTML page with file content.
// -------------------------------------------------------------------------
void ProcessNewConnection(int server_fd, const std::string& filePath) {
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  int client_fd = accept(
      server_fd, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
  if (client_fd < 0) return;

  char buffer[BUFFER_SIZE];
  ssize_t bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
  if (bytes <= 0) {
    close(client_fd);
    return;
  }
  buffer[bytes] = '\0';

  std::string request(buffer);
  // Check if the request is a WebSocket upgrade
  if (request.find("Upgrade: websocket") != std::string::npos) {
    size_t pos = request.find("Sec-WebSocket-Key: ");
    if (pos != std::string::npos) {
      pos += std::strlen("Sec-WebSocket-Key: ");
      size_t end = request.find("\r", pos);
      if (end != std::string::npos) {
        std::string key = request.substr(pos, end - pos);
        HandleHandshake(client_fd, key);
        AddClient(client_fd);
        return;
      }
    }
  }
  // Serve the HTML page with initial file content
  std::string htmlResponse = GenerateHtmlResponse();
  send(client_fd, htmlResponse.c_str(), htmlResponse.size(), 0);
  close(client_fd);
}

// -------------------------------------------------------------------------
// ProcessClientMessages: Handles messages from connected clients and removes
// any that have disconnected.
// -------------------------------------------------------------------------
void ProcessClientMessages(fd_set* fds) {
  for (auto it = Clients.begin(); it != Clients.end();) {
    int sock = *it;
    if (FD_ISSET(sock, fds)) {
      char buffer[128];
      if (recv(sock, buffer, sizeof(buffer), 0) <= 0) {
        close(sock);
        it = Clients.erase(it);
        continue;
      }
    }
    ++it;
  }
}

// -------------------------------------------------------------------------
// SHA-1 Implementation
// -------------------------------------------------------------------------
#define SHA1_ROTL(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))

void Sha1Transform(uint32_t state[5], const unsigned char buffer[64]) {
  uint32_t a, b, c, d, e, temp, w[80];
  int i;
  for (i = 0; i < 16; i++) {
    w[i] = ((uint32_t)buffer[i * 4] << 24) |
           ((uint32_t)buffer[i * 4 + 1] << 16) |
           ((uint32_t)buffer[i * 4 + 2] << 8) | ((uint32_t)buffer[i * 4 + 3]);
  }
  for (i = 16; i < 80; i++)
    w[i] = SHA1_ROTL(1, w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

  for (i = 0; i < 80; i++) {
    if (i < 20)
      temp = SHA1_ROTL(5, a) + ((b & c) | ((~b) & d)) + e + 0x5A827999 + w[i];
    else if (i < 40)
      temp = SHA1_ROTL(5, a) + (b ^ c ^ d) + e + 0x6ED9EBA1 + w[i];
    else if (i < 60)
      temp = SHA1_ROTL(5, a) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDC +
             w[i];
    else
      temp = SHA1_ROTL(5, a) + (b ^ c ^ d) + e + 0xCA62C1D6 + w[i];

    e = d;
    d = c;
    c = SHA1_ROTL(30, b);
    b = a;
    a = temp;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

void Sha1Init(Sha1Ctx* context) {
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
  context->state[4] = 0xC3D2E1F0;
  context->count[0] = context->count[1] = 0;
}

void Sha1Update(Sha1Ctx* context, const unsigned char* data, uint32_t len) {
  uint32_t i, j = (context->count[0] >> 3) & 63;
  if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
  context->count[1] += (len >> 29);

  if (j + len > 63) {
    uint32_t part_len = 64 - j;
    std::memcpy(&context->buffer[j], data, part_len);
    Sha1Transform(context->state, context->buffer);
    for (i = part_len; i + 63 < len; i += 64)
      Sha1Transform(context->state, &data[i]);
    j = 0;
  } else {
    i = 0;
  }
  std::memcpy(&context->buffer[j], &data[i], len - i);
}

void Sha1Final(unsigned char digest[20], Sha1Ctx* context) {
  unsigned char final_count[8];
  for (int i = 0; i < 8; i++)
    final_count[i] = static_cast<unsigned char>(
        (context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);

  Sha1Update(context, reinterpret_cast<const unsigned char*>("\x80"), 1);
  while ((context->count[0] & 504) != 448)
    Sha1Update(context, reinterpret_cast<const unsigned char*>("\0"), 1);
  Sha1Update(context, final_count, 8);
  for (int i = 0; i < 20; i++)
    digest[i] = static_cast<unsigned char>(
        (context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
}

// -------------------------------------------------------------------------
// main: Entry point. Initializes server, inotify, and handles events.
// -------------------------------------------------------------------------
int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <file-path>" << std::endl;
    return 1;
  }
  std::string filePath = argv[1];

  // Create server socket
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("socket");
    return 1;
  }
  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(server_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) <
      0) {
    perror("bind");
    return 1;
  }
  if (listen(server_fd, 5) < 0) {
    perror("listen");
    return 1;
  }

  // Initialize inotify for file monitoring
  int inotify_fd = inotify_init();
  if (inotify_fd < 0) {
    perror("inotify_init");
    return 1;
  }
  int wd = inotify_add_watch(inotify_fd, filePath.c_str(), IN_MODIFY);
  if (wd < 0) {
    perror("inotify_add_watch");
    return 1;
  }

  if (!LoadFile(filePath)) {
    std::cerr << "Error loading file: " << filePath << std::endl;
    return 1;
  }

  std::cout << "Monitoring " << filePath << " on port " << PORT << std::endl;

  // Main loop: wait for events from the server socket, inotify, or clients.
  while (true) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(server_fd, &fds);
    FD_SET(inotify_fd, &fds);
    int max_fd = std::max(server_fd, inotify_fd);

    // Add client sockets
    for (int sock : Clients) {
      FD_SET(sock, &fds);
      if (sock > max_fd) max_fd = sock;
    }

    int ret = select(max_fd + 1, &fds, nullptr, nullptr, nullptr);
    if (ret < 0) {
      perror("select");
      continue;
    }

    // Process file change events
    if (FD_ISSET(inotify_fd, &fds)) {
      char event_buf[EVENT_BUF_LEN];
      int len = read(inotify_fd, event_buf, EVENT_BUF_LEN);
      if (len > 0) {
        if (LoadFile(filePath)) {
          BroadcastToClients(FileContent);
        }
      }
    }

    // Process new incoming connection
    if (FD_ISSET(server_fd, &fds)) ProcessNewConnection(server_fd, filePath);

    // Process messages from connected clients
    ProcessClientMessages(&fds);
  }

  close(server_fd);
  close(inotify_fd);
  return 0;
}
