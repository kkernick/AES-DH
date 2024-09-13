#pragma once

#include <numeric>
#include <stdexcept>
#include <iostream>

#include "network.h"
#include "prime.h"

/**
 * @brief The namespace for Key-Exchange functions.
 * @remarks This code has been created with reference to:
 * https://datatracker.ietf.org/doc/html/rfc2631#section-2.1
 * Herein referred to as "The Reference"
 * @remarks The Diffie-Hellman Key Exchange Algorithm is a means for
 * two peers to negotiate a secure, shared key in an untrusted network.
 * Each peer will generate a private key a, and b. They will then used
 * A shared, public key containing a large prime number p, and a
 * primitive root of p: g. Each party will take g, and raise it to their
 * private key, sending it to the other party. Then, they will take their
 * other peer's intermediary key, and raise it by their own private key.
 * This leads to the following values (g^a)^b, (g^b)^b, which when
 * Simplied leads to g^(ab), g^(ba), which due to the associative property
 * of multiplication will lead to the same, shared key. Every operation in
 * this exchange is done with mod p. Due to the difficulty in computing
 * discrete logarithms, while computing the intermediary and shared key
 * is easy if a private key is known (Simply raising a value), it is infesible
 * For an attacker to try and determine the private key used to create an intermediary
 * given only the intermediary value and the public p,g. This makes Diffie-Hellman a
 * one-way function.
 * @remarks In this implementation, The server will generate the public p and g, and will
 * send them alongside the intermediary to the other party.
 */
namespace exchange {


  /**
   * @brief Compute the intermeidary value to send across the wire.
   * @param p: The prime.
   * @param g: The g.
   * @param k: The private key.
   * @return The g**k % p via a reduced g**r % p
   * @remarks This function uses the reduced calculation by generating q,r. prime::raise is leagues
   * fast enough to just do the computation directly, but if working with very large numbers, this
   * would make a substantial difference on performance.
   */
  uint64_t compute_intermediary(const uint64_t& p, const uint64_t& g, const uint64_t& k) {
    // We can write the key as: k = (p-1)q + r
    // Which turns g**k % p into g**((p-1)q + r) % p
    // By simplifying the exponent, we get ((g**(p-1))**q)g**r
    // According to Fermat's Little Theorem, g**(p-1) = 1, so
    // we can reduce all that down to g**r % p.
    // This only applies if p is co-prime to g.
    uint64_t r = k % (p - 1), q = (k - r) / (p - 1);
    return prime::raise(g, r, p);
  }


  /**
   * @brief Exchange keys on an established connection.
   * @param server: Whether this is the server.
   * @returns The shared key to be used for communication
   * @remarks See 2.1.1 of the Reference.
   */
  uint64_t exchange_keys(const bool& server) {
    // Generate our private key, and the other user's intermediary.
    uint64_t a = 0, k = std::rand(), p = 0, g = 0;

    if (server) {

      // Firstly, we generate our p, which will be our mod value
      // (And public), and then generate a q value, which we'll
      // use for g. These follows the relationship p = jq + 1,
      // Where j = 2. See 2.2 of the Reference.
      // This ensures that p is a "safe prime," which has the following
      // helpful properties:
      //  1. Every quadratic nonresidue is a primitive root (Which we need for g)
      //  2. The least positive primitive root is a prime number.
      // What does this mean? It basically lets us quickly find an associated g
      // value, rather than going through an expensive algorithm to compute
      // primitive roots for a number.
      auto pair = prime::generate();
      p = std::get<0>(pair);
      auto q = std::get<1>(pair);

      // Next, we calculate h, which we'll use to generate g.
      // We simply need to find a number such that h^((p-1)/q) % p
      // Is greater than one. (I think the Reference has a typo in
      // this section were they are missing the raise ^).
      //
      // Any interesting tibit of knowledge for you:
      // I've also found suggestions of generating g by omitting
      // h, and simply taking the smallest primitive root of p.
      // We take the smallest because g should usually be small.
      // According to Wikipedia, this is:
      // "Because of the random self-reducibility of the discrete
      // logarithm problem a small g is equally secure as any other
      // generator of the same group."
      // - https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
      // That being said, I had an implementation to find a primitive
      // root for a value p, which would ensure that g would be as small
      // as possible, but it was so SLOW. This method is lightning quick
      // Which is probably why the Reference suggests it. In fact,
      // there are probably far more efficient ways of generating h,
      // Since we're just brute forcing it here.
      uint64_t h = 1;
      while (prime::raise(h++, (p-1)/q, p) <= 1) {}

      // With an h, we can generate g.
      g = prime::raise(h, (p-1)/q, p);

      // Send them across.
      if (network::send_value(p) == -1)
        throw std::runtime_error("Failed to send key!");
      if (network::send_value(g) == -1)
        throw std::runtime_error("Failed to send key!");

      // Then, we send our intermediary, and receive the client.
      if (network::send_value(exchange::compute_intermediary(p, g, k)) == -1)
        throw std::runtime_error("Failed to send key!");
      a = network::recv_value<uint64_t>();
    }

    else {
      // Collect the server's p,g, and intermediary.
      p = network::recv_value<uint64_t>();
      g = network::recv_value<uint64_t>();
      a = network::recv_value<uint64_t>();

      // Calculate our intermediary, and send it back.
      if (network::send_value(exchange::compute_intermediary(p, g, k)) == -1)
        throw std::runtime_error("Failed to send key!");
    }

    // Both server and client can now calculate their shared key.
    auto sk = prime::raise(a, k, p);
    return sk;
  }
}
