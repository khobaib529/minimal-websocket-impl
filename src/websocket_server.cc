#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>

#include "core.h"
#include "util.h"

// --- WebSocket Handshake ---
// Handles the WebSocket handshake process with the client by receiving the
// request, generating the correct accept key, and sending the appropriate
// response.
bool DoHandshake(int client_socket)
{
  const int buffer_size = 2048;
  char buffer[buffer_size];
  memset(buffer, 0, buffer_size);

  // Receive the WebSocket handshake request
  int bytes_received = recv(client_socket, buffer, buffer_size - 1, 0);
  if (bytes_received <= 0)
  {
    std::cerr << "Failed to receive handshake request from client.\n";
    return false;
  }

  std::string request(buffer);

  // Extract the Sec-WebSocket-Key from the request headers
  std::string websocket_key =
      ExtractHTTPHeaderValue(request, "Sec-WebSocket-Key");
  if (websocket_key.empty())
  {
    std::cerr << "WebSocket key not found in handshake request.\n";
    return false;
  }

  // Generate the WebSocket accept key
  const std::string magic_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::string accept_source = websocket_key + magic_guid;
  std::string sha1_hash = ComputeSHA1Hash(accept_source);
  std::string accept_key = EncodeBase64(sha1_hash);

  // Prepare the handshake response
  std::ostringstream response;
  response << "HTTP/1.1 101 Switching Protocols\r\n"
           << "Upgrade: websocket\r\n"
           << "Connection: Upgrade\r\n"
           << "Sec-WebSocket-Accept: " << accept_key << "\r\n\r\n";
  std::string response_str = response.str();

  // Send the WebSocket handshake response to the client
  send(client_socket, response_str.c_str(), response_str.size(), 0);
  return true;
}

int main()
{
  const int port = 8080;
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1)
  {
    perror("socket");
    return 1;
  }
  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  memset(addr.sin_zero, 0, sizeof(addr.sin_zero));
  if (bind(server_fd, (struct sockaddr*) &addr, sizeof(addr)) == -1)
  {
    perror("bind");
    close(server_fd);
    return 1;
  }
  if (listen(server_fd, 5) == -1)
  {
    perror("listen");
    close(server_fd);
    return 1;
  }
  std::cout << "WebSocket server listening on port " << port << "...\n";

  int client_fd = accept(server_fd, nullptr, nullptr);
  if (client_fd == -1)
  {
    perror("accept");
    close(server_fd);
    return 1;
  }
  std::cout << "Client connected.\n";
  if (!DoHandshake(client_fd))
  {
    std::cerr << "Handshake failed.\n";
    close(client_fd);
    close(server_fd);
    return 1;
  }
  std::cout << "Handshake successful. Type messages on the server console to "
               "send to the client. Type /quit to exit.\n";

  // --- Messaging loop ---
  fd_set read_fds;
  int max_fd = (client_fd > STDIN_FILENO ? client_fd : STDIN_FILENO) + 1;
  char sock_buffer[4096];
  while (true)
  {
    FD_ZERO(&read_fds);
    FD_SET(client_fd, &read_fds);
    FD_SET(STDIN_FILENO, &read_fds);
    int activity = select(max_fd, &read_fds, nullptr, nullptr, nullptr);
    if (activity < 0)
    {
      perror("select");
      break;
    }
    // Check for data from the client
    if (FD_ISSET(client_fd, &read_fds))
    {
      ssize_t n = recv(client_fd, sock_buffer, sizeof(sock_buffer), 0);
      if (n <= 0)
      {
        std::cout << "Client disconnected.\n";
        break;
      }
      std::vector<uint8_t> data(sock_buffer, sock_buffer + n);
      std::string msg = ParseWSFrame(data);
      if (!msg.empty()) std::cout << "[Client] " << msg << "\n";
    }
    // Check for user input from the server terminal
    if (FD_ISSET(STDIN_FILENO, &read_fds))
    {
      std::string input;
      std::getline(std::cin, input);
      // If you want to implement a quit feature, you can check for a special
      // command here.
      if (input == "/quit")
      {
        // Send a close frame
        std::vector<uint8_t> closeFrame = BuildWSFrame("", WSOpcode::CLOSE);
        send(client_fd, reinterpret_cast<const char*>(closeFrame.data()),
             closeFrame.size(), 0);
        std::cout << "Closing connection...\n";
        break;
      }
      std::vector<uint8_t> frame = BuildWSFrame(input, WSOpcode::TEXT);
      send(client_fd, reinterpret_cast<const char*>(frame.data()), frame.size(),
           0);
    }
  }
  close(client_fd);
  close(server_fd);
  return 0;
}
