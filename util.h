#pragma once

#include <iostream>   // For writing to console.
#include <array>      // For std::array

#include "exchange.h" // To exchange the DH keys.
#include "aes.h"      // For AES Encryption.
#include "hmac.h"     // To generate an HMAC for the message.


/**
 * @brief The utility namespace.
 * @remarks A namespace isn't really necessary, since this is only used by main,
 * but it allows Doxygen to document these functions on the HTML.
 */
namespace util {
  // A macro to prompt, then return from a function.
  #define prompt_return(msg) {util::prompt(msg); return;}
  // A macro to prompt, then break from a loop/switch
  #define prompt_break(msg) {util::prompt(msg); break;}
  // A macro to prompty, then continue from a loop
  #define prompt_continue(msg) {util::prompt(msg); continue;}


  /**
  * @brief Clear the screen.
  * @remarks This works on UNIX/Windows. It's a shell escape sequence.
  */
  inline void clear() {std::cout << "\033[2J\033[1;1H";}


  /**
  * @brief std::cin can be a little difficult to use, particularly handling bad input. This sanitized it.
  * @tparam T: The type of input to be returned.
  * @param title: A title to be drawn for the input
  * @param error_ret: If something causes an error, what we should return to let the caller know.
  * @return The user input, or the error return.
  * @remarks This function does not re-prompt upon errors; it is the responsibility of the caller to check for the
  * error return and act accordingly.
  * @warning This function is blocking.
  */
  template <typename T = bool> inline T input(const std::string& title, const T& error_ret = T()) {
    T ret;

    // Print the title, get the input.
    std::cout << title << std::endl;
    std::cin >> ret;

    // If it failed, clear the buffer and set the error return.
    auto f = std::cin.fail();
    if (f) {
      std::cin.clear();
      ret = error_ret;
    }

    // Skip past whatever garbage the user may have added.
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    // Return.
    return ret;
  }


  /**
  * @brief Prompt the user and wait until they have confirmed it
  * @param message: The message to display.
  * @warning This function is blocking.
  */
  inline void prompt(const std::string& message) {
    std::cout << message << std::endl;
    std::cout << "Press Enter to Continue" << std::endl;
    getchar();
  }


  /**
  * @brief Genreate a shared key over a connection.
  * @param sk: The shared key array to populate.
  * @param server: Whether we are the server or not.
  * @remarks AES requires key sizes of 128, 192, or 256 bits, but our uint64_t is just 64.
  * So, we just perform 4 key exchanges to get 256 bits.
  * @warning Selecting different modes of AES merely truncates this key (IE AES-128 uses sk[0,1],
  * AES-192 uses sk[0,1,2], AES-256 uses all of them).
  * @warning This is not the cryptographically secure way of doing things. We should almost certainly
  * Exchange a single, massive 256 bit prime instead of four 64 bit ones, but for the sake of not
  * needing to create our own 256 bit number classes, we just key exchange quadrice.
  */
  void construct_shared_key(std::array<uint64_t, 4>& sk, const bool& server) {
    std::cout << "Exchanging Keys..." << std::endl;
    for (size_t x = 0; x < 4; ++x) {
      sk[x] = exchange::exchange_keys(server);
    }

    prompt("Complete! Ensure that the Shared Key matches!");
  }


  /**
  * @brief Receive an encrypted message from the peer.
  * @param sk: The shared key
  */
  void receive_message(const std::array<uint64_t, 4>& sk) {

    std::cout << "Receiving Key Size..." << std::endl;
    auto Nr = network::recv_value<uint64_t>();

    std::cout << "Receiving Ciphertext..." << std::endl;
    auto message = network::recv_string();

    std::cout << "Receiving Nonce..." << std::endl;
    auto nonce_packet = network::recv_packet();

    // Get the actual Nonce.
    auto str = std::string(&nonce_packet.data[0], PACKET_SIZE);
    uint64_t nonce = 0;
    std::istringstream (str) >> nonce;

    // GCM doesn't include an HMAC.
    if (nonce_packet.m == network::meta::IV) {
      try {
        std::cout << "Message: " << aes::gcm::Dec(message, sk, Nr, nonce) << std::endl;
      }
      catch (std::runtime_error& e) {prompt_return(e.what());}
    }

    else {
      std::cout << "Receiving HMAC..." << std::endl;
      auto hmac = network::recv_string();

      // Check that the HMAC matches what we expect. Refuse to decrypt unless it matches.
      if (hmac != hmac::generate(message, sk, Nr))
        prompt_return("HMAC does not match! Message has been altered!");

      // A NONCE means we're using CTR.
      if (nonce_packet.m == network::meta::NONCE) {
        std::cout << "Message: " << aes::Ctr(message, sk, Nr, nonce) << std::endl;
      }
      // An EMPTY means we're using ECB.
      else if (nonce_packet.m == network::meta::EMPTY) {
        std::cout << "Message: " << aes::InvCipher(message, sk, Nr) << std::endl;
      }

      // Something else means the peer did something wrong.
      else prompt_return("Peer sent invalid packet!");
    }
    std::cout << "Press Enter to Continue" << std::endl;
    getchar();
  }


  /**
  * @brief Send an encrypted message to a peer.
  * @param sk: The shared key.
  */
  void send_message(const std::array<uint64_t, 4>& sk) {
    // Get the message to encrypt.
    std::string message;
    std::cout << "Enter the message:" << std::endl;
    std::getline(std::cin, message);

    // Get the amount of rounds.
    auto size = input<int>("What size key?\n1. 128\n2. 192\n3. 256\n", -1);
    if (size < 1 || size > 3) prompt_return("Invalid selection");
    uint64_t Nr = size == 1 ? 10 : size == 2 ? 12 : 14;

    // Get the mode.
    auto option = input<int>("What mode?\n1. ECB\n2. CTR\n3. GCM", -1);
    if (option < 1 || option > 3) prompt_return("Invalid selection");

    /*
    * The communication between the peers is as follows:
    *
    * INITIATOR               RECIPIENT
    *  MESSAGE       -->
    *                <--      ACK/REFUSE
    *    NR          -->
    * CIPHERTEXT     -->
    * NONCE/EMPTY/IV -->    IV: GCM-DECRYPT
    *   HMAC         -->
    *                        CHECK HMAC
    *                         DECRYPT
    */

    // Let the peer know we want to send a message.
    std::cout << "Reaching out to the Peer..." << std::endl;
    if (network::send_packet({.m = network::meta::MESSAGE}) == -1)
      prompt_return("Failed to communicate with peer!");

    // Get their response. Be generous with the response
    auto response = network::recv_packet(30);
    switch (response.m) {
      case network::meta::ACK: break;
      case network::meta::REFUSED: prompt_return("Peer refused to accept message!");
      case network::meta::ERROR: prompt_return("Could not communicate with peer!");
      case network::meta::MESSAGE: prompt_return("Cannot send two messages at once! One peer must Listen!");
      default: prompt_return("Peer sent invalid response!");
    }

    // Even though ECB doesn't use this, we generate it for the others.
    const uint64_t nonce = std::rand();

    // Get the cipher.
    auto cipher = option == 1 ?
      aes::Cipher(message, sk, Nr) : option == 2 ?
      aes::Ctr(message, sk, Nr, nonce) :
      aes::gcm::Enc(message, sk, Nr, nonce);

    if (network::send_value<uint64_t>(Nr) == -1)
      prompt_return("Failed to send Key Size!");

    // Send that cipher across.
    if (network::send_string(cipher) == -1)
       prompt_return("Failed to send ciphertext!");

    // ECB; we send an empty packet as there is no nonce.
    if (option == 1) {
      if (network::send_packet({.m = network::meta::EMPTY}) == -1)
        prompt_return("Failed to send empty packet!");
    }

    //CTR; we need to create and send the NONCE.
    else if (option == 2) {
      if (network::send_value(nonce, network::meta::NONCE) == -1)
        prompt_return("Failed to send nonce!");
    }

    // GCM does not generate an HMAC, so just return once we've sent the IV.
    if (option == 3) {
      if (network::send_value(nonce, network::meta::IV) == -1)
        prompt_return("Failed to send IV!");
    }
    else {
      // Generate the HMAC and send it across.
      auto hmac = hmac::generate(cipher, sk, Nr);

      if (network::send_string(hmac) == -1)
        prompt_return("Failed to send HMAC!");
    }
  }


  /**
  * @brief Acknowledge a request from a peer.
  * @param what: What is the acknowledgement for?
  * @returns The return code of the send_packet.
  */
  bool acknowledge(const std::string& what) {
    // Do we want to accept this?
    auto response = input<std::string>(what + ": Acknowledge? (y/n)");

    // Send an ACK.
    if (response == "y" || response == "Y") {
      network::send_packet({.m = network::meta::ACK});
      return true;
    }

    // Send a REFUSED.
    network::send_packet({.m = network::meta::REFUSED});
    return false;
  }
}
