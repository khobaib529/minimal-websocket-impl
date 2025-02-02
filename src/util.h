// WebSocket Utility Functions
// Provides helper functions for WebSocket header parsing
// Part of the WebSocket server/client implementation

#ifndef WEBSOCKET_SRC_UTIL_H_
#define WEBSOCKET_SRC_UTIL_H_

#include <sstream>
#include <string>

/*
 * Extracts the value of a specified HTTP header from raw headers.
 *
 * headers should be a raw HTTP header string using `\r\n` (CRLF) separators.
 * Format: `Header-Name: Header-Value\r\n`
 * Example:
 *     Host: example.com\r\n
 *     Upgrade: websocket\r\n
 *
 * header_name is case-sensitive.
 * Returns the extracted value or an empty string if not found.
 */
std::string ExtractHTTPHeaderValue(const std::string &headers,
                                   const std::string &key)
{
  std::istringstream stream(headers);
  std::string line;
  std::string search = key + ":";
  while (std::getline(stream, line))
  {
    if (line.find(search) != std::string::npos)
    {
      size_t pos = line.find(":");
      if (pos != std::string::npos)
      {
        std::string value = line.substr(pos + 1);
        size_t start = value.find_first_not_of(" \t");
        size_t end = value.find_last_not_of(" \r\n");
        if (start != std::string::npos && end != std::string::npos)
          return value.substr(start, end - start + 1);
      }
    }
  }
  return "";
}

/*
 * Computes the SHA-1 hash of a given input string.
 */
std::string ComputeSHA1Hash(const std::string &input)
{
  uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476,
           h4 = 0xC3D2E1F0;
  uint64_t original_bit_len = input.size() * 8;
  std::string padded = input;
  padded.push_back(0x80);
  while ((padded.size() * 8) % 512 != 448) padded.push_back(0x00);
  for (int i = 7; i >= 0; i--)
  {
    padded.push_back(static_cast<char>((original_bit_len >> (i * 8)) & 0xFF));
  }
  size_t chunkCount = padded.size() * 8 / 512;
  for (size_t chunk = 0; chunk < chunkCount; chunk++)
  {
    uint32_t w[80] = {0};
    const unsigned char *chunkData =
        reinterpret_cast<const unsigned char *>(padded.data() + chunk * 64);
    for (int i = 0; i < 16; i++)
    {
      w[i] = (chunkData[i * 4] << 24) | (chunkData[i * 4 + 1] << 16) |
             (chunkData[i * 4 + 2] << 8) | (chunkData[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++)
    {
      uint32_t temp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (temp << 1) | (temp >> 31);
    }
    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; i++)
    {
      uint32_t f, k;
      if (i < 20)
      {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      }
      else if (i < 40)
      {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      }
      else if (i < 60)
      {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      }
      else
      {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
      e = d;
      d = c;
      c = (b << 30) | (b >> 2);
      b = a;
      a = temp;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }
  std::string hash;
  for (int i = 0; i < 5; i++)
  {
    uint32_t h;
    switch (i)
    {
      case 0:
        h = h0;
        break;
      case 1:
        h = h1;
        break;
      case 2:
        h = h2;
        break;
      case 3:
        h = h3;
        break;
      case 4:
        h = h4;
        break;
    }
    for (int j = 3; j >= 0; j--)
    {
      hash.push_back(static_cast<char>((h >> (j * 8)) & 0xFF));
    }
  }
  return hash;
}

/*
 * Encodes a string to Base64 format.
 */
std::string EncodeBase64(const std::string &input)
{
  const char *data = input.data();
  size_t len = input.size();
  static const char base64_chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string encoded;
  int i = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];
  while (len--)
  {
    char_array_3[i++] = *(data++);
    if (i == 3)
    {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] =
          ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] =
          ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;
      for (i = 0; i < 4; i++) encoded += base64_chars[char_array_4[i]];
      i = 0;
    }
  }
  if (i)
  {
    for (int j = i; j < 3; j++) char_array_3[j] = '\0';
    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] =
        ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] =
        ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;
    for (int j = 0; j < i + 1; j++) encoded += base64_chars[char_array_4[j]];
    while ((i++ < 3)) encoded += '=';
  }
  return encoded;
}

#endif  // WEBSOCKET_SRC_UTIL_H_