#pragma once

#include <arpa/inet.h>    // For Converting IP/Port into the right format.
#include <sys/socket.h>   // For sockets.
#include <unistd.h>       // For various functions.
#include <string.h>       // For strings.
#include <poll.h>         // For the poll function for timeouts.
#include <stdexcept>      // For exceptions.

/**
 * @brief The namespace for communication along a socket.
 */
namespace network {

  /**
   * @brief The FD sock for when the program is in Listen mode.
   * @remarks This is not the FD that peers communicate over.
   * @remarks This is only used for the initial connection.
   */
  int sock = -1;

  /**
   * @brief the FD sock that peers communicate over.
   */
  int connection = -1;

  /**
   * @brief Metadata tags for packets.
   * @var ERROR: If something bad happened.
   * @var EMPTY: An empty packet.
   * @var DATA: A packet of data.
   * @var HMAC: A packet containing an HMAC string.
   * @var NONCE: A packet containing a NONCE value.
   * @var IV: A packet containing the GCM IV/Nonce
   * @var FINAL: The final packet in a string transfer.
   * @var MESSAGE: A packet to initiate a message exchange.
   * @var ACK: An acknowledgement.
   * @var REFUSED: A refusal to a request.
   * @var REEXCHANGE: A request to regenerate shared keys.
   */
  typedef enum {
    ERROR, EMPTY, DATA, HMAC, NONCE, IV,
    FINAL, MESSAGE, ACK, REFUSED, REEXCHANGE,
  } meta;

  // The size of the buffer
  #define PACKET_SIZE 1024

  /**
   * @brief The basic object sent between peers.
   * @var m: A metadata tag for what the packet contains.
   * @var data: Arbitrary data.
   * @remarks data's size is defined by PACKET_SIZE. Setting this value
   * to large numbers can cause problems when sending numbers.
   */
  typedef struct {
    meta m = EMPTY;                   // Describe what the packet is.
    char data[PACKET_SIZE] = {0};     // The actual data.
  } packet;


  /**
   * @brief Send a packet.
   * @param p: The packet to send.
   * @param timeout: How long to wait (seconds) before throwing an error.
   * @returns The return code of send.
   */
  int send_packet(const packet& p, const size_t& timeout=5) {
    struct pollfd fd;
    fd.fd = connection;
    fd.events = POLLOUT;

    switch (poll(&fd, 1, timeout * 1000)) {
      case -1: case 0: return -1;
      default: return send(connection, reinterpret_cast<const void*>(&p), sizeof(p), 0);
    }
  }


  /**
   * @brief Receive a packet.
   * @param timeout: How long to wait (seconds) before throwing an error.
   * @returns The packet.
   * @remarks If an error occured, the packet will have type network::meta::ERROR.
   * Causes of this include the peer hanging up the connection or a timeout.
   */
  packet recv_packet(const size_t& timeout=5) {
    packet p;
    struct pollfd fd;
    fd.fd = connection;
    fd.events = POLLIN;

    switch (poll(&fd, 1, timeout * 1000)) {
      case -1: case 0: p.m = network::meta::ERROR; break;
      default: recv(connection, reinterpret_cast<void*>(&p), sizeof(p), 0); break;
    }
    return p;
  }


  /**
   * @brief Send a value.
   * @tparam T: The datatype of the value.
   * @param value: The value to send.
   * @param type: Whether to tag the data with something.
   * @param timeout: A listening timeout before aborting.
   * @returns 0 if success, -1 if error.
   */
  template <typename T> inline int send_value(const T& value, const network::meta& type = DATA, const size_t& timeout=5) {
    packet p = {.m = type};

    // Pack the value into a string.
    std::stringstream in; in << value;
    auto str = in.str();
    if (str.length() > PACKET_SIZE) {
      throw std::runtime_error("Value exceeds packet size!");
    }
    strncpy(&p.data[0], str.c_str(), PACKET_SIZE);

    return send_packet(p, timeout);
  }


  /**
   * @brief Receive a value.
   * @tparam T: The datatype of the value.
   * @param timeout: A listening timeout before aborting.
   * @returns The send value.
   * @throws std::runtime_error if an ERROR packet is sent.
   */
  template <typename T> inline const T recv_value(const size_t& timeout=5) {
    auto p = recv_packet(timeout);
    if (p.m = network::meta::ERROR) throw std::runtime_error("Failed to read from socket!");

    // Get the value from the string.
    auto str = std::string(&p.data[0], PACKET_SIZE);
    T ret = {};
    std::istringstream (str) >> ret;
    return ret;
  }


  /**
   * @brief Send a string of any size.
   * @param message The string to send.
   * @param type: Whether you want to tag this data with something other than DATA.
   * @param timeout: A listening timeout before aborting.
   * @returns 0 if the string was sent succesfully. -1 Otherwise.
   * @remarks This function simply breaks the string into packet sized blocks, and sends them
   * across one at a time. The last package will be sent with a FINAL type, which will terminate the exchange.
   * @remarks A length package will be sent to trim excessive 0's.
   */
  inline int send_string(const std::string& message, const network::meta& type = DATA, const size_t& timeout=5) {

    // Send the length of the message, so that we can trim the string accordingly.
    send_value<uint64_t>(message.length(), DATA, timeout);

    // We'll reuse this packet with the correct type
    packet p = {.m = type};
    size_t x = 0;
    p.data[0] = message[0];

    // Simply increment through the message, and once we hit PACKET_SIZE,
    // send the package before overwriting the old data.
    for (x = 1; x < message.length(); ++x) {
      if (x % PACKET_SIZE == 0) {
        if (send_packet(p, timeout) == -1)
          return -1;
      }
      p.data[x % PACKET_SIZE] = message[x];
    }

    // Fill the remainder of the packet with 0's (Since previous data will be there)
    // And then send a FINAL packet.
    p.m = FINAL;
    while (x % PACKET_SIZE != 0) p.data[x++ % PACKET_SIZE] = 0;
    if (send_packet(p, timeout) == -1)
      return -1;
    return 0;
  }


  /**
   * @brief Receive a string
   * @param timeout: A listening timeout before aborting.
   * @returns: The string.
   */
  inline std::string recv_string(const size_t& timeout=5) {

    // Get the string ready, and receive the size.
    std::string ret;
    packet p;

    auto length = recv_value<uint64_t>();

    // Simply receive packets until the sender provides a FINAL packet.
    while (true) {
      p = recv_packet();
      if (p.m == ERROR) throw std::runtime_error("Failure recieving packet!");

      // Just append it.
      ret.append(p.data, PACKET_SIZE);
      if (p.m == FINAL) break;
    }

    // Trim to length and return.
    return std::string(ret.c_str(), length);
  }


  /**
   * @brief Listen on the socket for a client to initiate a connection.
   * @param port The port to listen on.
   * @warning This function will initialize network::out; be sure to close it before
   * closing the application.
   * @warning This function will initialize network::connection; be sure to close it
   * before closing the application.
   * @warning You are responsible for closing sockets.
   */
  void get_client(const int& port) {

    // Make our socket.
    if (sock == -1) {
      sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock == -1) return;

      // Bind the socket
      sockaddr_in serverAddress = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {.s_addr = INADDR_ANY}
      };

      // The main socket has a 30 timeout.
      // The connection socket
      struct timeval timeout;
      timeout.tv_sec = 30;
      timeout.tv_usec = 0;
      setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

      if (bind(sock, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        close(sock);
        sock = -1;
        return;
      }
    }

    // We only have a single connection
    if (listen(sock, 1) == -1) {
      close(sock);
      sock = -1;
      return;
    }

    // Accept connections
    sockaddr_in clientAddress;
    socklen_t clientSize = sizeof(clientAddress);
    connection = accept(sock, (struct sockaddr *)&clientAddress, &clientSize);
  }


  /**
   * @brief Try and connect to the server.
   * @param port: The port to connect to
   * @param address: The address of the server
   * @warning This function will initialize network::out; be sure to close it before
   * closing the application.
   * @warning This function will initialize network::connection; be sure to close it
   * before closing the application.
   * @warning You are responsible for closing sockets.
   */
  void get_server(const size_t& port, const char address[] = "127.0.0.1") {

    // There is only one communication socket.
    if (connection != -1)
      close(connection);

    connection = socket(AF_INET, SOCK_STREAM, 0);
    if (connection == -1) return;

    // Connect to the server
    sockaddr_in serverAddress = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr = {.s_addr = inet_addr(address)}
    };

    if (connect(connection, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
      close(connection);
      connection = -1;
    }
  }
}
