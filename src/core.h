// WebSocket frame handling functions: constructing frames and parsing frames.
// not handle all edge cases, but working with smaller messages. will be updated soon.

#ifndef WEBSOCKET_SRC_CORE_H_
#define WEBSOCKET_SRC_CORE_H_

#include <cstdint>
#include <string>
#include <vector>

// --- Enum for WebSocket Opcodes ---
enum class WSOpcode : uint8_t
{
  CONTINUATION = 0x0,
  TEXT = 0x1,
  BINARY = 0x2,
  CLOSE = 0x8,
  PING = 0x9,
  PONG = 0xA
};

// --- Build a WebSocket frame (server to client) ---
// For server frames, masking is not applied.
// assuming message sizes don’t exceed 0xFFFF
std::vector<uint8_t> BuildWSFrame(const std::string &message,
                                  WSOpcode opcode = WSOpcode::TEXT)
{
  std::vector<uint8_t> frame;
  frame.push_back(0x80 |
                  static_cast<uint8_t>(opcode));  // FIN flag set plus opcode
  size_t len = message.size();
  if (len < 126)
  {
    frame.push_back(static_cast<uint8_t>(len));
  }
  else if (len <= 0xFFFF)
  {
    frame.push_back(126);
    frame.push_back((len >> 8) & 0xFF);
    frame.push_back(len & 0xFF);
  }
  frame.insert(frame.end(), message.begin(), message.end());
  return frame;
}

// --- Parse a WebSocket frame received from the client ---
// Client-to-server frames must be masked.
// assuming message sizes don’t exceed 0xFFFF
std::string ParseWSFrame(const std::vector<uint8_t> &buffer)
{
  if (buffer.size() < 2) return "";
  // We don't need the first byte here (it contains FIN and opcode)
  uint8_t byte2 = buffer[1];
  bool mask = byte2 & 0x80;
  uint64_t payload_len = byte2 & 0x7F;
  size_t pos = 2;
  if (payload_len == 126)
  {
    if (buffer.size() < 4) return "";
    payload_len = (buffer[2] << 8) | buffer[3];
    pos += 2;
  }
  else if (payload_len == 127)
  {
    // Not implemented for simplicity.
    return "";
  }
  std::string message;
  if (mask)
  {
    if (buffer.size() < pos + 4 + payload_len) return "";
    uint8_t mask_key[4];
    for (int i = 0; i < 4; i++) mask_key[i] = buffer[pos + i];
    pos += 4;
    for (uint64_t i = 0; i < payload_len; i++)
    {
      message.push_back(buffer[pos + i] ^ mask_key[i % 4]);
    }
  }
  else
  {
    if (buffer.size() < pos + payload_len) return "";
    for (uint64_t i = 0; i < payload_len; i++)
      message.push_back(buffer[pos + i]);
  }
  return message;
}

#endif  // WEBSOCKET_SRC_CORE_H_
