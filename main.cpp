#include <iostream>   // For input and output.
#include <cstdlib>    // For the standard library
#include <ctime>      // To seed the RNG.
#include <string>     // For std::string
#include <vector>     // For std::vector
#include <limits>     // For the upper limits to clear the input buffer.
#include <sstream>    // For string streams.
#include <stdexcept>  // For std::runtime_error

#include "util.h"     // For utilities


// The status of the program.
typedef enum status {IDLE = 1, CONNECTED = 2} status;
std::string stat(const status& s) {
  switch (s) {
    case IDLE: return "IDLE";
    case CONNECTED: return "CONNECTED";
    default: return "UNKNOWN";
  }
}


// String constants so we can have descriptive names.
constexpr char
  Initialize[] = "Request New Connection",
  Listen[] = "Listen for New Connection",
  Terminate[] = "Terminate Connection",
  Request[] = "Listen for Request",
  Reexchange[] = "Re-Exchange Keys",
  Send[] = "Send an Encrypted Message",
  Quit[] = "Quit";


int main() {
  // Seed RNG.
  std::srand(std::time(0));

  // The state
  status s = IDLE;

  // The shared key. AES Can be 128, 192, of 256 bits.
  // A single prime key is 64 bits, so we exchange 4 keys
  // To get a max of 256 bits.
  uint64_t nonce = std::rand();
  std::array<uint64_t, 4> sk = {0, 0, 0, 0};

  // ECB Test
  size_t Nr = 10;
  for (const auto& welcome : {"Welcome ", "to the ", "AES-DH application!"}) {
    std::cout << aes::InvCipher(aes::Cipher(welcome, sk, Nr), sk, Nr);
    Nr += 2;
  }
  std::cout << "\t(ECB)\n";

  // CTR Test
  Nr = 10;
  for (const auto& welcome : {"If any of ", "these messages ", "look corrupted"}) {
    std::cout << aes::Ctr(aes::Ctr(welcome, sk, Nr, nonce), sk, Nr, nonce);
    Nr += 2;
  }
  std::cout << "\t(CTR)\n";

  // GCM Test
  Nr = 10;
  for (const auto& welcome : {"Then you need ", "to recompile ", "the app!"}) {
    std::cout << aes::gcm::Dec(aes::gcm::Enc(welcome, sk, Nr, nonce), sk, Nr, nonce);
    Nr += 2;
  }
  std::cout << "\t(GCM)\n";

  std::cout << "Press Enter to Continue" << std::endl;
  getchar();

  while (true) {

    util::clear();
    std::cout << "Status: " << stat(s) << std::endl;

    // Populate valid choices given the state.
    std::stringstream in;
    in << "What would you like to do?\n";

    std::vector<std::string> choices = {};
    if (s == IDLE) {
      choices.emplace_back(Initialize);
      choices.emplace_back(Listen);
    }
    else if (s == CONNECTED) {
      in << "Shared Key (Mod 100): " << sk[0] % 100 <<  sk[1] % 100 << sk[2] % 100 << sk[3] % 100 << '\n';
      choices.emplace_back(Request);
      choices.emplace_back(Send);
      choices.emplace_back(Reexchange);
      choices.emplace_back(Terminate);
    }
    choices.emplace_back(Quit);

    // Generate the choices, and prompt the user.
    for (size_t x = 0; x < choices.size(); ++x)
      in << x << ": " << choices[x] << '\n';
    auto selection = util::input<uint>(in.str(), choices.size());
    if (selection >= choices.size()) prompt_continue("Invalid selection");

    auto command = choices[selection];

    /*
     * Setup a connection between two peers. One peer takes the part of the server, the other
     * the client. Once the connection has been made, these roles do not impact further
     * communication.
     */
    if (command == Listen || command == Initialize) {

      // Both need to give a port, unless the server has already setup a socket.
      int port = 0;
      if (command == Initialize || network::sock == -1) {
        port = util::input<int>("Enter a port", 0);
        if (port == 0) prompt_continue("Invalid port");
      }

      // The client will contact the server
      if (command == Initialize) {
        auto server = util::input<std::string>("Enter server address (Or \"local\" for localhost)", "0");
        if (server == "0") prompt_continue("Invalid server address");
        if (server == "local") server = "127.0.0.1";
        network::get_server(port, server.c_str());
      }

      // The server will simply wait until a client connects.
      else {
        std::cout << "Listening..." << std::endl;
        network::get_client(port);
      }

      // If the initial connection failed, do nothing.
      if (network::connection == -1) util::prompt("Failed to connect!");

      // Otherwise, exchange keys and change the status.
      else {
        try {
          util::construct_shared_key(sk, command == Initialize);
          s = CONNECTED;
        }
        catch (std::runtime_error&) {
          util::prompt("Failed to exchange keys");
          close(network::connection);
        }
      }
    }


    /*
     * Wait for the other peer to initiate an action.
     */
    else if (command == Request) {
      std::cout << "Waiting for Request..." << std::endl;

      // Give some wait time :)
      auto p = network::recv_packet(30);
      switch (p.m) {

        // If the peer sent an error message.
        case network::meta::ERROR: prompt_break("Failed to receive packet");

        // A reexchange. Sometimes sending values across the network
        // will lead to silent corruption, leading to different shared keys.
        case network::meta::REEXCHANGE:
          if (util::acknowledge("Peer is requesting to re-exchange keys"))
            util::construct_shared_key(sk, true);
          break;

        // Receive a message
        case network::meta::MESSAGE:
          if (util::acknowledge("Peer is sending a message")) {
            try {util::receive_message(sk);}
            catch (std::runtime_error&) {util::prompt("Failed to receive message!");}
          }
          break;

        // If the peer sent something weird.
        default: prompt_break("Unknown request");
      }
    }


    /*
     * Send encrypted data.
     */
    else if (command == Send) {
      try {util::send_message(sk);}
      catch (std::runtime_error&) {util::prompt("Failed to send message!");}
    }


    /*
     * Either party can request to generate new keys; however, the second peer must confirm such an
     * exchange, and should they confirm, they are the ones that generate the new p and g values.
     */
    else if (command == Reexchange) {

      // Reexchange must be approved by both parties.
      std::cout << "Asking peer to re-exchange keys..." << std::endl;
      if (network::send_packet({.m = network::meta::REEXCHANGE}) == -1)
        prompt_continue("Failed to send packet");


      // Get the response; Be generous with the wait time.
      std::cout << "Awaiting response..." << std::endl;
      auto p = network::recv_packet(30);
      switch (p.m) {

        case network::meta::ERROR: prompt_break("Error receiving packet");

        // If yes, then re-exchange new keys.
        case network::meta::ACK:
          try {util::construct_shared_key(sk, false);}
          catch (std::runtime_error&) {util::prompt("Failed to exchange keys");}
          break;

        // Otherwise, just back out.
        case network::meta::REFUSED: prompt_break("Peer refused exchange!");

        // If both peers tried to key-exchange
        case network::meta::REEXCHANGE: prompt_break("To perform a re-exchange, one peer must Listen for Request!");

        // In case the other peer sent something incorrect.
        default: prompt_break("Peer gave invalid response!");
      }
    }

    /*
     * Either peer can disconnect from the other at any time, without needing to inform them.
     * The peer will simply get errors trying to do anything, and will need to hangup the connection
     * on their side.
     */
    else if (command == Terminate) {

      // Close any open connection.
      if (network::connection != -1) {
        close(network::connection);
        network::connection = -1;
      }

      // Clear the private key and reset the state.
      sk[0] = 0; sk[1] = 0; sk[2] = 0; sk[3] = 0;
      s = IDLE;
    }

    // Exit.
    else if (command == Quit) break;
  }


  // Close any sockets that are open, then return.
  if (network::connection != -1) close(network::connection);
  if (network::sock != -1) close(network::sock);
  return 0;
}
