#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "core.h"
#include "util.h"

// --- WebSocket Handshake ---
bool DoHandshake(int sock, const char* server_ip, int server_port) {
  // Prepare handshake request
  std::ostringstream request;
  std::string sec_websocket_key = "dGhlIHNhbXBsZSBub25jZQ==";
  request << "GET /chat HTTP/1.1\r\n"
          << "Host: " << server_ip << ":" << server_port << "\r\n"
          << "Upgrade: websocket\r\n"
          << "Connection: Upgrade\r\n"
          << "Sec-WebSocket-Key: " << sec_websocket_key << "\r\n"
          << "Sec-WebSocket-Version: 13\r\n\r\n";
  std::string handshake_request = request.str();
  send(sock, handshake_request.c_str(), handshake_request.size(), 0);

  char buffer[4096];
  memset(buffer, 0, sizeof(buffer));

  ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
  if (n <= 0) {
    std::cerr << "Handshake failed: no response.\n";
    return false;
  }

  std::string response(buffer);
  std::string res_ws_accept_key =
      ExtractHTTPHeaderValue(response, "Sec-WebSocket-Accept");

  // Check for 101 Switching Protocols
  if (response.find("101 Switching Protocols") == std::string::npos) {
    std::cerr << "Handshake failed:\n" << response << "\n";
    return false;
  }

  // Check for accept key
  const std::string magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::string concatenated_key = sec_websocket_key + magicGUID;
  std::string sha1_hash = ComputeSHA1Hash(concatenated_key);
  std::string expected_accept_key = EncodeBase64(sha1_hash);
  if (res_ws_accept_key != expected_accept_key) {
    std::cerr << "Handshake failed: accept key doesn't match\n";
    return false;
  }

  std::cout << "Handshake successful.\n";
  return true;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <username>\n";
    return 1;
  }
  std::string username(argv[1]);

  const char* server_ip = "127.0.0.1";
  const int server_port = 8080;
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    perror("socket");
    return 1;
  }
  sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(server_port);
  if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
    perror("inet_pton");
    close(sock);
    return 1;
  }
  if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr),
              sizeof(server_addr)) < 0) {
    perror("connect");
    close(sock);
    return 1;
  }
  std::cout << "Connected to " << server_ip << ":" << server_port << "\n";
  if (!DoHandshake(sock, server_ip, server_port)) {
    close(sock);
    return 1;
  }
  std::cout << "Enter messages to send to the server. Type /quit to exit.\n";

  fd_set read_fds;
  int max_fd = (sock > STDIN_FILENO ? sock : STDIN_FILENO) + 1;
  char sock_buffer[4096];
  while (true) {
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    FD_SET(STDIN_FILENO, &read_fds);
    int activity = select(max_fd, &read_fds, nullptr, nullptr, nullptr);
    if (activity < 0) {
      perror("select");
      break;
    }
    // Check for data from the server
    if (FD_ISSET(sock, &read_fds)) {
      ssize_t n = recv(sock, sock_buffer, sizeof(sock_buffer), 0);
      if (n <= 0) {
        std::cout << "Server disconnected.\n";
        break;
      }
      std::vector<uint8_t> data(sock_buffer, sock_buffer + n);
      std::string msg = ParseWSFrame(data);
      if (!msg.empty()) std::cout << msg << "\n";
    }
    // Check for user input from the command line
    if (FD_ISSET(STDIN_FILENO, &read_fds)) {
      std::string input;
      std::getline(std::cin, input);
      if (input == "/quit") {
        // Send a close frame and exit.
        std::vector<uint8_t> closeFrame = BuildWSFrame("", WSOpcode::CLOSE);
        send(sock, reinterpret_cast<const char*>(closeFrame.data()),
             closeFrame.size(), 0);
        std::cout << "Closing connection...\n";
        break;
      }

      // Create a payload: 4 bytes username length (network order) | username |
      // message
      uint32_t nameLen = username.size();
      uint32_t nameLenNetwork = htonl(nameLen);
      std::string payload;
      payload.append(reinterpret_cast<const char*>(&nameLenNetwork),
                     sizeof(nameLenNetwork));
      payload.append(username);
      payload.append(input);

      // Build and send the WebSocket frame with the custom payload.
      std::vector<uint8_t> frame = BuildWSFrame(payload, WSOpcode::TEXT);
      send(sock, reinterpret_cast<const char*>(frame.data()), frame.size(), 0);
    }
  }
  close(sock);
  return 0;
}
