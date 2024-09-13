#pragma once

#include <stdexcept>      // For exceptions
#include <string>         // For std::string.

#include <openssl/hmac.h> // For the HMAC function
#include <openssl/evp.h>  // For EVP_sha256()

/**
 * @brief This namespace includes the functions needed to generate an HMAC value
 * Using OpenSSL.
 * @remarks To compile, add -lssl -lcrypto to your compiler's arguments!
 */
namespace  hmac {
  // Create our buffer for OpenSSL to dump the value to.
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len = 0;

  /**
   * @brief Generate an HMAC for a message.
   * @param message: The string to compute the HMAC for.
   * @param key: The set of prime numbers to use as the key.
   * @param rounds: The amount of AES rounds (To determine key size)
   * @returns A string containing the HMAC value.
   * @throws std::runtime_error if the HMAC could not be generated.
   * @throws std::runtime_error if the round amount is invalid.
   * @remarks This function uses the OpenSSL implementation of HMAC-SHA256.
   * @remarks https://docs.openssl.org/master/man3/HMAC/#synopsis
   */
  std::string generate(const std::string& message, const std::array<uint64_t, 4>& key, const size_t& rounds) {

    // Get the size of the key we use based on the rounds.
    int key_size = sizeof(uint64_t);
    int keys = 0;
    switch (rounds) {
      case 10: keys = 2; break;
      case 12: keys = 3; break;
      case 14: keys = 4; break;
      default: throw std::runtime_error("Invalid round count!");
    }

    // Translate our 64 bit keys into a character array.
    std::string key_bytes;
    for (size_t x = 0; x < keys; ++x) {
      auto num = key[x];

      // Mask the byte, then shift to the next.
      for (size_t y = 0; y < key_size; ++y, num >>= 1) {
        key_bytes += char(num & 0xf);
      }
    }

    // Generate the HMAC. Since this is more auxiliary to the main program, I won't dwell too long explaining this,
    // but in essence OpenSSL deals with character arrays, specifically unsigned character arrays. For convenience,
    // We deal with std::strings, which are signed characters. Therefore, we need to do some reinterpret casting
    // To convert these signed values to unsigned values.
    if (HMAC(EVP_sha256(), reinterpret_cast<const unsigned char*>(key_bytes.c_str()), key_bytes.length(), reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), &md_value[0], &md_len) == NULL)
      throw std::runtime_error("Failed to generate HMAC!");

    // Same as above. We need to reinterpret the output values as "signed" characters
    return std::string(reinterpret_cast<const char*>(&md_value[0]), md_len);
  }
}
