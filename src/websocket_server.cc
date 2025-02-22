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
bool DoHandshake(int client_socket) {
  const int buffer_size = 2048;
  char buffer[buffer_size];
  memset(buffer, 0, buffer_size);

  // Receive the WebSocket handshake request
  int bytes_received = recv(client_socket, buffer, buffer_size - 1, 0);
  if (bytes_received <= 0) {
    std::cerr << "Failed to receive handshake request from client.\n";
    return false;
  }

  std::string request(buffer);

  // Extract the Sec-WebSocket-Key from the request headers
  std::string websocket_key =
      ExtractHTTPHeaderValue(request, "Sec-WebSocket-Key");
  if (websocket_key.empty()) {
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

int main() {
  const int port = 8080;
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
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
  if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("bind");
    close(server_fd);
    return 1;
  }
  if (listen(server_fd, 5) == -1) {
    perror("listen");
    close(server_fd);
    return 1;
  }
  std::cout << "WebSocket server listening on port " << port << "...\n";

  // Container to hold all connected client sockets.
  std::vector<int> client_sockets;

  while (true) {
    fd_set read_fds;
    FD_ZERO(&read_fds);

    // Monitor the server socket for new connections.
    FD_SET(server_fd, &read_fds);
    int max_fd = server_fd;

    // Monitor standard input for server commands.
    FD_SET(STDIN_FILENO, &read_fds);
    if (STDIN_FILENO > max_fd) max_fd = STDIN_FILENO;

    // Monitor each client socket for incoming messages.
    for (int client_socket : client_sockets) {
      FD_SET(client_socket, &read_fds);
      if (client_socket > max_fd) max_fd = client_socket;
    }

    // Wait for activity on any socket.
    int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
    if (activity < 0) {
      perror("select");
      break;
    }

    // Accept new client connections.
    if (FD_ISSET(server_fd, &read_fds)) {
      int new_client = accept(server_fd, nullptr, nullptr);
      if (new_client < 0) {
        perror("accept");
      } else {
        std::cout << "New client connected: " << new_client << "\n";
        if (!DoHandshake(new_client)) {
          std::cerr << "Handshake failed for client: " << new_client << "\n";
          close(new_client);
        } else {
          client_sockets.push_back(new_client);
        }
      }
    }

    // Handle server console input.
    if (FD_ISSET(STDIN_FILENO, &read_fds)) {
      std::string input;
      std::getline(std::cin, input);
      if (input == "/quit") {
        // Send a close frame to all clients.
        for (int client : client_sockets) {
          std::vector<uint8_t> closeFrame = BuildWSFrame("", WSOpcode::CLOSE);
          send(client, reinterpret_cast<const char*>(closeFrame.data()),
               closeFrame.size(), 0);
          close(client);
        }
        std::cout << "Closing all connections...\n";
        break;
      } else {
        // Broadcast the server message to all clients.
        std::string payload;
        payload.append("[Server] ");
        payload.append(input);
        std::vector<uint8_t> frame = BuildWSFrame(payload, WSOpcode::TEXT);
        for (int client : client_sockets) {
          send(client, reinterpret_cast<const char*>(frame.data()),
               frame.size(), 0);
        }
      }
    }

    // Process messages from each connected client.
    for (auto it = client_sockets.begin(); it != client_sockets.end();) {
      int client_socket = *it;
      if (FD_ISSET(client_socket, &read_fds)) {
        char sock_buffer[4096];
        ssize_t n = recv(client_socket, sock_buffer, sizeof(sock_buffer), 0);
        if (n <= 0) {
          std::cout << "Client " << client_socket << " disconnected.\n";
          close(client_socket);
          it = client_sockets.erase(it);
          continue;
        }
        std::vector<uint8_t> data(sock_buffer, sock_buffer + n);
        // Decode the WebSocket frame and obtain the payload string.
        std::string payload = ParseWSFrame(data);
        if (!payload.empty()) {
          // Ensure the payload contains at least 4 bytes for the username
          // length.
          if (payload.size() < 4) {
            std::cerr << "Invalid message from client " << client_socket
                      << "\n";
          } else {
            // Extract the username length.
            uint32_t nameLen;
            memcpy(&nameLen, payload.data(), 4);
            nameLen = ntohl(nameLen);
            if (payload.size() < 4 + nameLen) {
              std::cerr
                  << "Invalid message (username length mismatch) from client "
                  << client_socket << "\n";
            } else {
              // Extract the username and the chat message.
              std::string username = payload.substr(4, nameLen);
              std::string chatMsg = payload.substr(4 + nameLen);
              // Build the final message to display and broadcast.
              std::string fullMsg = "[" + username + "] " + chatMsg;
              std::cout << fullMsg << "\n";

              // Build a WebSocket frame containing the final message.
              std::vector<uint8_t> frame =
                  BuildWSFrame(fullMsg, WSOpcode::TEXT);
              // Broadcast to all clients except the sender.
              for (int dest_socket : client_sockets) {
                if (dest_socket != client_socket)
                  send(dest_socket, reinterpret_cast<const char*>(frame.data()),
                       frame.size(), 0);
              }
            }
          }
        }
      }
      ++it;
    }
  }

  // Cleanup: close any remaining client sockets and the server socket.
  for (int client : client_sockets) close(client);
  close(server_fd);
  return 0;
}
