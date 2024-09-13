#pragma once

#include <cmath>    // For std::sqrt()
#include <cstdlib>  // For randomness.
#include <cstdint>  // For fixed width integers.

/**
 * @brief The namespace for prime number related operations.
 * @remarks Everything is inlined; this will increase binary size, but hopefully (If the compiler
 * wants to cooperate) increase speed.
 * @warning values are stored in regular C++ datatypes; best practice would be to use secure classes, such
 * as a container that allocates on the heap, and then overwrites the values randomly upon its destruction.
 */
namespace prime {

  /**
  * @brief Checks if any given number is prime.
  * @param  num: The number.
  * @returns True if the number is prime, False if it isn't.
  */
  inline bool is(const uint64_t& num) {
    if (num == 1) return false;

    // We only need to check up to the square root of the number in order to know if it's prime.
    auto root = static_cast<uint64_t>(std::sqrt(num)) + 1;

    // Start at 2, so we don't get a 0/1 false positive.
    for (size_t x = 2; x <= root; ++x) {
      if (num % x == 0)
        return false;
    }
    return true;
  }


  /**
   * @brief Find the next prime greater than the provided number.
   * @tparam T: The type of number. Generating a prime uses half-width.
   * @param num: The number (Does not need to be prime itself)
   * @remarks This function is intended to overflow, since the datatype is unsigned. Since we are always dealing with
   * odd numbers, an overflow will bring us to 1.
   * @warning This function is done in-place. It modifies the number you pass to it.
   */
  template <typename T = uint64_t> inline void next(T& num) {
    // Get to an odd number.
    if (num % 2 == 0) num++;

    // Loop until we find one.
    for (; !prime::is(num); num += 2) {}
  }


  /**
   * @brief A O(logn) raise operation that works within modulus to prevent overflow.
   * @param value: The value to raise.
   * @param exp: The exponent to raise the value by.
   * @param mod: The mod space
   * @returns the result.
   * @note From https://www.geeksforgeeks.org/primitive-root-of-a-prime-number-n-modulo-n/
   * @remarks Because raising values is almost assured to overflow when using such large numbers.
   * We need to compute it piecemeal, applying the modulus on each self multiplication such
   * that it remains bounded with our datatype.
   */
  inline uint64_t raise(uint64_t value, uint64_t exp, const uint64_t& mod) {
    uint64_t ret = 1;

    // Ensure it's bounded by the mod.
    value = value % mod;

    // March down the exponent until it's been 0d.
    while (exp > 0) {

      // If the current bit is 1, multiply ret by our value, and mod it.
      if (exp & 1) ret = (ret*value) % mod;

      // Shift exp down.
      exp = exp >> 1;
      value = (value*value) % mod;
    }
    return ret;
  }


  /**
  * @brief Generates a prime number
  * @returns A prime number p, and the smaller prime q.
  * @remarks This function will use std::rand() to find a starting value, and then find the nearest prime larger than it.
  * There are some cavets to this approach for the sake of simplicity and readibility. Firstly, primes are confined from 3 - 2**64
  * Secondly, std::rand() is not considered a cryptographically secure PRNG. However, this implemention makes it easier to
  * understand, and allows us to work within the confines of standard integer types.
  * @remarks See 2.2 of the Diffie-Hellman Reference.
  */
  inline std::pair<uint64_t, uint64_t> generate() {
    auto q = static_cast<uint32_t>(std::rand());
    prime::next<uint32_t>(q);

    // Sometime's q will not be prime, due to casting.
    // We can just re-roll the number if that's the case.
    auto p = (static_cast<uint64_t>(q) * 2) + 1;
    if (!prime::is(p)) {
      return prime::generate();
    }
    return {p, q};
  }
}
