#pragma once

#include <vector>   // For a collection of states
#include <cstdint>  // For fixed width integers
#include <sstream>  // For stringstream construction.
#include <bitset>   // For raw bit access.
#include <bit>      // For rotl
#include <array>    // For the shared key array.

/**
 * @brief The namespace containing AES encryption/decryption functions.
 * @remarks This code has been created with reference to:
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
 * Herein referred to as "The Reference"
 * @remarks Another wonderful source is available here:
 * https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_2002.pdf
 * Which we will refer to as the "2002 Paper"
 * @remarks AES is block cipher which takes a message of arbitrary size, alongside a
 * key, and returns a ciphertext that can be safely shared across an untrusted network.
 * AES breaks down a message into a set of 16 byte blocks, and extends the key into a
 * Key Schedule. It then repeatedly applies four operations to each block: SubBytes,
 * ShiftRows, MixColumns, and AddRoundKey. The amount of repetitions (Or rounds) depends
 * on the size of the key, with 10 rounds for a 128 bit key, 12 for 192, and 14 for 256.
 * The Key Schedule creates a unique key for each column of the block, for each round
 * Of the algorithm. Operations are typically performed in the Finite Field GF(256),
 * Which is a field of 256 elements. The reason for this is performance.
 * @remarks This implemention supports three modes of AES: ECB, CTR, and GCM. ECB takes
 * a message, and directly feeds it through AES to receive a ciphertext. CTR uses a nonce
 * value and runs this through AES to generate a block--or pad--that is then XOR'd against
 * The message in a similar fashion to the One-Time Pad. With an incrementing nonce, each
 * Pad will be unique, eliminating a key issue of ECB. Finally, GCM is essentially a version
 * of CTR that incorporates a MAC algorithm to provide integrity.
 */
namespace aes {

  /**
   * @brief Helper utilities for working within a Galois Field 2**8
   */
  namespace gf {

    /**
     * @brief Multiply two bytes in GA(256)
     * @param a: The first byte.
     * @param b: The second byte.
     * @note From https://gist.github.com/meagtan/dc1adff8d84bb895891d8fd027ec9d8c
     * @remarks Most implementations would avoid this, and simply compute a 256x256 lookup
     * table containing all values, like how SubBytes works.
     */
    uint8_t mult(uint8_t a, uint8_t b) {
      // This function looks confusing, and that's because it is, but here's the rundown:
      // Addition in a finite field of characteristic 2 (GF(2**X)) is simply XOR.
      // This is nice, because we avoid carries and XOR is fast.
      // Multiplication operates identically to normal mutiplication (Meaning repeated addition,
      // which in our case means XOR), except we mod each stage with a "Reducing Polynomial"
      // See all of Section 4 of the Reference for more details, but in essence we treat each byte as a
      // polynomial (IE 0b11000001 = x**8 + x**7 + x**0).
      // The reducing polynomial for GF(256) is 100011011:
      // https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
      // And this whole function is in essence just long multiplication, how you would do it
      // by hand, where we slowly move through the b value by shifting it to 0, check that shifted
      // first bit and "add" it to the result via an xor of A, and then preemptively check
      // for an overflow condition on the final bit of a (0x80 = 128), which then applies our
      // modulus to keep it bounded.
      //
      // However, the main question that arises is why do we need to use this at all. The Reference makes
      // no attempt to explain WHY our operations must be performed in a Galois Field, and why that's useful.
      // From what I've gathered: it's perfomance. Both addition and multiplication do not have
      // to deal with carries, and the former is reduced to the blazing fast XOR, rather than the
      // (relatively) complicated ADD.
      //
      // Finite Field Arithmetic is complicated, and I can't begin to scratch the surface of it
      // in this comment block (Which is already monsterous), so here's some resources if you're interested:
      // https://www.samiam.org/galois.html
      // https://web.eecs.utk.edu/~jplank/plank/papers/CS-07-593/
      // https://archive.org/details/finitefields0000lidl_a8r3
      //

      // The running result.
      uint8_t res = 0;

      // Iterate through every bit of b until it's been zeroed.
      for (; b; b >>= 1) {

        // If our current bit in b is a 1, then "add" a copy of a to the result.
        if (b & 1) res ^= a;

        // If a is about to overflow (IE there's a bit in 128), then "mod" it by the reducing
        // polynomial pre-shift.
        if (a & 0x80) a = (a << 1) ^ 0b100011011;

        // Otherwise, just shift a.
        else a <<= 1;
      }
      return res;
    }


    /**
    * @brief Find the Multiplicative Inverse of a byte in GF(2**8)
    * @param a: The value to find the inverse of.
    * @remarks There are much more efficient ways to do this (Primarily just forgoing
    * any explicit algorithm and just using a precomputed table),
    * But for the sake of simplicity (And since there's only 256 values to check),
    * We can just brute force it by checking against every value.
    */
    uint8_t inverse(uint8_t a) {
      for (size_t x = 0; x < 256; ++x) {
        if (mult(a, x) == 1) return x;
      }
      return 0;
    }
  }


  /**
   * @brief Manage the key.
   */
  namespace key {

    /**
     * @brief The round constants.
     * @remarks This is copied from Table 5 of the Reference.
     * @remarks The Reference likes to split up words into
     * the individual bytes, but we just treat the whole word
     * as one number.
     * @remarks These values can be computed via r(i)= x(i−4)/4 mod(x8+x4+x3+x+1)
     * @remarks Why do we use these round constants? It eliminates symmetries. See:
     * The 2002 Paper for more details.
     */
    uint32_t Rcon[10] = {
      0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
      0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
    };


    /**
     * @brief Rotate a word by one byte left.
     * @param word: The word.
     * @returns The rotated word.
     * @remarks See Figure 5.10 of the Reference
     */
    uint32_t RotWord(const uint32_t& word) {return std::rotl(word, 8);}

    /**
     * @brief Substitue the bytes in a key-schedule word.
     * @param word: The word
     * @returns The modified word.
     * @remarks This uses the exact same algorithm as SubBytes, and as with that
     * step, the Reference just uses a lookup table rather than manually computig it.
     * @remarks See Figure 5.11 of the Reference.
     */
    uint32_t SubWord(const uint32_t& word) {
      uint8_t dest[4] = {0};

      // Get the bytes
      auto* bytes = reinterpret_cast<const uint8_t*>(&word);

      for (size_t x = 0; x < 4; ++x) {
        // See state_array::SubBytes for an explanation of what this does.
        const uint8_t byte = bytes[x];
        std::bitset<8> i = gf::inverse(byte), c = 0b01100011, result = 0;
        for (int x = 0; x < 8; ++x) {
          result[x] = i[x] ^ i[(x + 4) % 8] ^ i[(x + 5) % 8] ^ i[(x + 6) % 8] ^ i[(x + 7) % 8] ^ c[x];
        }
        dest[x] = uint8_t(result.to_ulong());
      }

      // Bundle our bytes back into a word.
      return *reinterpret_cast<uint32_t*>(&dest[0]);
    }

    /**
     * @brief Expand a set of keys.
     * @param key: The shared key array.
     * @param Nk: The size of the key in words.
     * @returns A vector of the keys to use.
     * @remarks This function is a verbatim translation of Algorithm 2 of the Reference.
     * @remarks key is always exchanged as 4 64bit numbers, or 256 bits total.
     * Nk simply determines where the cutoff is made, thus removing the last
     * 64 bits for AES-192, or the last 128 for AES-128.
     * @remarks When implementing this algorithm, there are two real options:
     * Either do it like the Reference, where we treat the key schedule as a collection of words
     * Or treat it like a collection of individual bytes. The former will be faster, but will also
     * require bitwise operation to index positions in each word. The latter, on the other hand
     * Makes more sense when working on a per key level, but can be confusing when looking at the whole
     * schedule. We followed the Reference.
     * @remarks In essence this function takes a "small" key, and expands
     * it to be large enough for all of AES' rounds, such that it
     * looks random. See Section 5.8 of the 2002 Paper for more details.
     * @remarks For a more visual explanation, see Figure 6, 7, and 8
     * of the Reference.
     */
    std::vector<uint32_t> Expansion(const std::array<uint64_t, 4>& key, const uint64_t& Nk) {
      size_t i = 0;

      // Break each 64 bit key into two 32 bit words.
      std::vector<uint32_t> words;
      for (size_t x = 0; x < 4; ++x) {
        words.emplace_back(key[x] & 0xffffffff);
        words.emplace_back(key[x] >> 32);
      }

      // The number of rounds depends on the size of the key.
      // Nk = 4,6,8 if AES 128,192,256.
      uint64_t Nr = Nk == 4 ? 10 : Nk == 6 ? 12 : 14;
      auto w = std::vector<uint32_t>(4*Nr + 4, 0);

      // The first Nk words of the expanded key are the key itself.
      for (; i < Nk; ++i)
        w[i] = words[i];

      // This part of the algorithm is where things get confusing.
      // In essence, AES mutates the key by taking the last wprd,
      // And then performing a Subtitution step (SubWord like SubBytes),
      // and then a transposition step (RotWord, like ShiftRows). By using the
      // previous word, (Alongside An XOR with i - Nk), we're generating enough
      // words to perform all the rounds AES from the original 4/6/8 that all
      // depend on the original key.
      //
      for(; i < 4*Nr + 3; ++i) {

        // Store the last word into temp.
        uint32_t temp = w[i - 1];

        // If our current iteration falls within the round constants, XOR it.
        if (i % Nk == 0)
          temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];

        // This only applies for AES-256.
        else if (Nk > 6 && i % Nk == 4) {
          temp = SubWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
      }
      return w;
    }
  }


  /**
   * @brief The state array is a 4x4 byte matrix to which
   * AES operations are performed; also called a block.
   * @details For every 16 bytes of input, the state_array organizes
   * these bytes column first, Such that state_array[0] = [0,1,2,3],
   * state_array[1] = [4,5,6,7]
   * @remarks See Figure 1 of the Reference.
   */
  class state_array {
  private:

    // The state array is fixed in size; usually, we can assume
    // that char is a byte, but we'll use the explicit, fixed width
    // uint8 to ensure that each entry in the array is 8 bits.
    std::array<std::array<uint8_t, 4>, 4> array;

  public:

    /**
     * @brief Initialize a state_array from a string.
     * @param in: The input string.
     * @param x: A mutable index of the string, so that multiple arrays can be initialized from the state class.
     */
    state_array(const std::string& in, size_t& x) {
      auto length = in.length();

      uint8_t i = 0;

      // The syntax here might look a little weird, but this maps the 16 bytes to the row/col scheme:
      // 0: array[0 / 4][0 % 4] = array[0][0]
      // 1: array[1 / 4][1 % 4] = array[0][1]
      // 2: array[2 / 4][2 % 4] = array[0][2]
      // 3: array[3 / 4][3 % 4] = array[0][3]
      // 4: array[4 / 4][4 % 4] = array[1][0]
      // ...
      // 12: array[12 / 4][12 % 4] = array[3][0]
      // 13: array[13 / 4][13 % 4] = array[3][1]
      // 14: array[14 / 4][14 % 4] = array[3][2]
      // 15: array[15 / 4][15 % 4] = array[3][3]

      // Populate the array with bytes from the string.
      for (; x < length && i < 16; ++i, ++x) array[i / 4][i % 4] = in[x];

      // Initialize the remainder of the array should the string be exhausted.
      for (; i < 16; ++i) array[i / 4][i % 4] = 0;
    }


    // Initialize from a string, taking 16 bytes or the length.
    state_array(const std::string& in) {
      auto length = in.length();
      for (uint8_t i = 0; i < 16; ++i)
        array[i / 4][i % 4] = i < length ? in[i] : 0;
    }


    // Copy constructor.
    state_array(const state_array& arr) {
      for (uint8_t row = 0; row < 4; ++row) {
        for (uint8_t col = 0; col < 4; ++col) {
          array[row][col] = arr.array[row][col];
        }
      }
    }


    // Default constructor, populated with 0s.
    state_array() {
      for (uint8_t row = 0; row < 4; ++row) {
        for (uint8_t col = 0; col < 4; ++col) {
          array[row][col] = 0;
        }
      }
    }


    // Getter.
    auto& get() {return array;}
    const auto& get() const {return array;}


    // Helper function for GCM to XOR two blocks together.
    void xor_arr(const state_array& arr) {
      for (uint8_t row = 0; row < 4; ++row) {
        for (uint8_t col = 0; col < 4; ++col) {
          array[col][row] ^= arr.array[col][row];
        }
      }
    }


    // Helper function for GCM to Shift a block
    void shift_r(const size_t& bits) {
      if (bits == 0) return;

      // Basically, we iterate through each block,
      // We then shift it by one, and append the
      // carry to the end (As the shift put a 0 at the
      // last bit position).
      //
      // Before we do the shift, we see what value we're shifting
      // out (The bit in position 1). And if it's a 1, we set
      // Carry to 0b10000000, so that when we shift the next byte,
      // we are adding that bit onto the end.
      //
      uint8_t carry = 0;
      for (uint8_t row = 0; row < 4; ++row) {
        for (uint8_t col = 0; col < 4; ++col) {

          // Get our new value.
          uint8_t value = (array[col][row] >> 1) | carry;

          // Update the carry flag depending on what we shift off.
          if (array[col][row] & 1)
            carry = 0b10000000;
          else carry = 0;

          // Replace.
          array[col][row] = value;
        }
      }

      // Is this inefficient? Yes. Very. Because the goal was making
      // AES easier to understand, the 2D array makes it easy to
      // follow what AES is doing (IF we just had a 16 byte array,
      // ShiftRows and MixColumns would look a little strange).
      // However, since we aren't dealing with a string of bytes, and
      // can't necessarily trust that std::array is contigious,
      // dealing with the block as a single value, which is what GCM
      // likes to do, is tedious. Fortunately, we only ever shift
      // By 1 bit, this is just for completeness.
      shift_r(bits - 1);
    }


    /**
     * @brief Unravel the state_array back into a string.
     * @returns The string.
     */
    std::string unravel() const {
      std::stringstream out;
      for (uint8_t row = 0; row < 4; ++row) {
        for (uint8_t col = 0; col < 4; ++col) {
          out << array[row][col];
        }
      }
      return out.str();
    }


    /**
     * @brief Add the round key
     * @param round: The current round.
     * @param keys: The vector of keys.
     * @remarks Each round has 4 keys, one for each column.
     */
    void AddRoundKey(const uint64_t& round, const std::vector<uint32_t>& keys) {
      for (size_t col = 0; col < 4; ++col) {
        const auto key = keys[(4 * round) + col];

        // We can just cast the number into a byte array.
        auto* bytes = reinterpret_cast<const uint8_t*>(&key);

        for (size_t row = 0; row < 4; ++row) {
          array[row][col] ^= bytes[row];
        }
      }
    }


    /**
     * @brief A invertible, non-linear transformation of the state.
     * @remarks This function takes the multiplicative inverse of each byte in the state (Or 0 if byte is 0), and
     * then performs an affine transformation against a constant value 99.
     * @remarks This function is entirely deterministic, and as such we could (and should) use a lookup table to determine values.
     * Table 4 of the Reference provides said table, which we can use for O(1) efficiency.
     * To better understand the process, here we manually calculate each byte, at the expense of speed.
     * @remarks This step of AES provides non-linearity, and ensures that The resultant byte is not the same as the input.
     */
    void SubBytes() {
      for (uint8_t row = 0; row < 4; ++row) {
        for (uint8_t col = 0; col < 4; ++col) {

          const uint8_t byte = array[col][row];

          // Here, we find the multiplicative inverse of the byte in
          // In a Galois Field of GF(2**8). We can use the extended Euclidean
          // Algorithm: b(x)a(x) + m(x)c(x) = 1.
          // See Section 4.4 of the Reference for details.
          // The multiplicative inverse over this field has good non-linearity properties.
          // The constant value is chosen in a similar fashion to the Round Constants in
          // Expansion: It eliminates symmetries.
          std::bitset<8> i = gf::inverse(byte), c = 0b01100011, result = 0;

          // Now, we perform the affine transformation. This
          // is done on a bit-by-bit level, performing 5 XOR
          // operations per bit, or 40 XOR operations per byte.
          // Again, this shows the value of the lookup table.
          for (int x = 0; x < 8; ++x) {

            // The entire expression is:
            // b_i = b_i ^ b_i+4%8 ^ b_i+5%8 ^ b_i+6%8 ^ b_i+7%8 ^ c_i
            // This gets applied for each bit, so eight times for a single value.
            result[x] = i[x] ^ i[(x + 4) % 8] ^ i[(x + 5) % 8] ^ i[(x + 6) % 8] ^ i[(x + 7) % 8] ^ c[x];
          }

          // Finally, collapse the bitset back into an actual number we can store.
          array[col][row] = result.to_ulong();
        }
      }
    }


    /**
     * @brief: Invert the SubBytes step of AES.
     * @remarks As a testament to the ubiquity and performance of using a lookup table over manual calculation:
     * The Reference does not provide formulas for this stage, and I couldn't find any implementation that doesn't just use
     * InvSBox.
     */
    void InvSubBytes() {
      for (uint8_t row = 0; row < 4; ++row) {
        for (uint8_t col = 0; col < 4; ++col) {
          const uint8_t byte = array[col][row];

          // This may be confusing, but this is the inverse of the affine transformation we did in SubBytes.
          // https://en.wikipedia.org/wiki/Rijndael_S-box#Inverse_S-box
          // The math isn't particularly important, all that you need to understand is this reverses what we
          // did prior.
          // std::rotl is a rotate shift (IE bits shifted out are added to the front)
          uint8_t i = byte, c = 0b00000101, result = 0;
          result = std::rotl(i, 1) ^ std::rotl(i, 3) ^ std::rotl(i, 6)  ^ c;

          // Once we've undone the transformation, get the multiplicative inverse, which is our original.
          array[col][row] = gf::inverse(result);
        }
      }
    }


    /**
     * @brief Cyclically shift the bytes in each row.
     * @remarks This step in AES transposes values in (r,c) to (r, c+r % 4)
     * @remarks See 5.1.2 of the Reference.
     * @remarks This step acts as the transposition stage, and is important
     * to avoid columns being encrypted independently; if this stage
     * was absent, AES would effectively be four separate ciphers acting
     * on each row independently.
     */
    void ShiftRows() {

      // Create a buffer to place the values at new positions.
      std::array<std::array<uint8_t, 4>, 4> buffer;

      // Shift each of the based on the scheme described
      // in 5.5 of the Reference.
      // Note that while there is no explicit statement
      // Excluding the first row as mentioned in the Reference.
      // The math here works out such that the first row
      // Is copied in place:
      // 0,0 = 0+0 % 4 = 0
      // 0,1 = 0+1 % 4 = 1 ...
      // And since the row itself remains constant,
      // The top row remains unchanged.
      // I could not find a reason for WHY the first row is excluded,
      // Which makes me think it was just a quirk of how this algorithm
      // Works. Because this step is to prevent each COLUMN from being
      // Independent, the top row being unchanged doesn't actually
      // present any weakness, since the columns are still being shuffled
      for (size_t row = 0; row < 4; ++row) {
        for (size_t col = 0; col < 4; ++col) {
          buffer[col][row] = array[(col + row) % 4][row];
        }
      }

      // Replace with the new values. There is probably a more efficient
      // Way of doing this, perhaps mutating the array in place, rather
      // Than creating a copy, but this allows us to better shows what
      // shift is being performed.
      for (size_t row = 0; row < 4; ++row) {
        for (size_t col = 0; col < 4; ++col) {
          array[col][row] = buffer[col][row];
        }
      }
    }


    /**
     * @brief Invert the cyclical shift in ShiftRows()
     * @remarks This step in AES transposes values in (r,c) to (r, c-r % 4)
     * @remarks See 5.3.1 of the Reference.
     * @remarks InvShiftRows is pretty much identical to ShiftRows(),
     * and the inversion is simply changing c+r to c-r.
     */
    void InvShiftRows() {

      // Create a buffer to place the values at new positions.
      std::array<std::array<uint8_t, 4>, 4> buffer;

      // Exact same loop as ShiftRows, but invert the index.
      for (size_t row = 0; row < 4; ++row) {
        for (size_t col = 0; col < 4; ++col) {
          buffer[col][row] = array[(col - row) % 4][row];
        }
      }

      // Update the state.
      for (size_t row = 0; row < 4; ++row) {
        for (size_t col = 0; col < 4; ++col) {
          array[col][row] = buffer[col][row];
        }
      }
    }


    /**
     * @brief Transform each column by a single, fixed matrix.
     * @remarks See 5.1.3 of the Reference.
     * @remarks Each byte in the column are combined, which provides
     * diffusion.
     */
    void MixColumns() {
      // These operations are equivalent to multiplying the columns
      // Against a matrix, specifically:
      // [ 02 03 01 01 ][s0c]
      // [ 01 02 03 01 ][s1c]
      // [ 01 01 02 03 ][s2c]
      // [ 03 01 01 02 ][s3c]
      // For each column c.
      // Our multiplications are done in GF(256)

      uint8_t buffer[4];
      const uint8_t set[4] = {0x02, 0x01, 0x01, 0x03};
      for (size_t col = 0; col < 4; ++col) {
        buffer[0] = gf::mult(0x2, array[col][0]) ^ gf::mult(0x3, array[col][1]) ^ array[col][2] ^ array[col][3];
        buffer[1] = array[col][0] ^ gf::mult(0x2, array[col][1]) ^ gf::mult(0x3, array[col][2]) ^ array[col][3];
        buffer[2] = array[col][0] ^ array[col][1] ^ gf::mult(0x2, array[col][2]) ^ gf::mult(0x3, array[col][3]);
        buffer[3] = gf::mult(0x3, array[col][0]) ^ array[col][1] ^ array[col][2] ^ gf::mult(0x2, array[col][3]);

        for (size_t row = 0; row < 4; ++row) array[col][row] = buffer[row];
      }
    }


    /**
     * @brief Inverts the column transformation
     * @remarks See 5.3.3 of the Reference.
     */
    void InvMixColumns() {
      // These operations are equivalent to multiplying the columns
      // Against a matrix, specifically:
      // [ 0e 0b 0d 09 ][s0c]
      // [ 09 0e 0b 0d ][s1c]
      // [ 0d 09 0e 0b ][s2c]
      // [ 0b 0d 09 0e ][s3c]
      // For each column c.
      // Our multiplications are done in GF(256)
      // This matrix reverses the matrix we multiplied with in MixColumns()

      uint8_t buffer[4];
      const uint8_t set[4] = {0x0e, 0x09, 0x0d, 0x0b};
      for (size_t col = 0; col < 4; ++col) {
        buffer[0] = gf::mult(0xe, array[col][0]) ^ gf::mult(0xb, array[col][1]) ^ gf::mult(0xd, array[col][2]) ^ gf::mult(0x9, array[col][3]);
        buffer[1] = gf::mult(0x9, array[col][0]) ^ gf::mult(0xe, array[col][1]) ^ gf::mult(0xb, array[col][2]) ^ gf::mult(0xd, array[col][3]);
        buffer[2] = gf::mult(0xd, array[col][0]) ^ gf::mult(0x9, array[col][1]) ^ gf::mult(0xe, array[col][2]) ^ gf::mult(0xb, array[col][3]);
        buffer[3] = gf::mult(0xb, array[col][0]) ^ gf::mult(0xd, array[col][1]) ^ gf::mult(0x9, array[col][2]) ^ gf::mult(0xe, array[col][3]);

        for (size_t row = 0; row < 4; ++row) array[col][row] = buffer[row];
      }
    }
  };


  /**
   * @brief An arbitrary collection of state arrays.
   */
  class state {
  private:
    std::vector<state_array> arrays;
    std::vector<uint32_t> expanded;
    std::array<uint64_t, 4> key = {0};
    uint64_t rounds = 0;


    /**
     * @brief Generate the key schedule.
     * @param k: The key.
     * @param Nr: The number of rounds.
     * @throws std::runtime_error If the Nr rounds is not 10,12,14.
     */
    void Schedule(const std::array<uint64_t, 4>& k, const uint64_t& Nr) {
      switch (Nr) {
        case 10: expanded = key::Expansion(k, 4); break;
        case 12: expanded = key::Expansion(k, 6); break;
        case 14: expanded = key::Expansion(k, 8); break;
        default: throw std::runtime_error("Invalid key size:" + std::to_string(Nr));
      }
    }


  public:

    // Construct a state from a input string.
    state(const std::string& in, const std::array<uint64_t, 4>& k, const uint64_t& Nr) {

      // Get our key schedule.
      Schedule(k, Nr);
      size_t x = 0;

      // The state_array constructor takes a mutable reference to x,
      // and will increment it automatically. Therefore, we just need
      // to repeatedly construct state_arrays until the string has been exhausted.
      while (x < in.length()) {arrays.emplace_back(state_array(in, x));}

      key = k;
      rounds = Nr;
    }


    // Construct a state from a collection of state_arrays.
    state(const std::vector<state_array>& arrs, const std::array<uint64_t, 4>& k, const uint64_t& Nr) {
      Schedule(k, Nr);
      arrays = arrs;
      key = k;
      rounds = Nr;
    }


    // Getters
    auto& get_arrays() {return arrays;}
    const auto& get_arrays() const {return arrays;}
    const auto& get_key() {return key;}
    const auto& get_rounds() {return rounds;}


    /**
     * @brief Unravel a state into a character string.
     * @returns A string.
     */
    std::string unravel() const {
      std::stringstream out;
      for (const auto& array : arrays)
        out << array.unravel();
      return out.str();
    }


    /**
     * All of the steps here simply act on each state_array in the state.
     */

    // AddRoundKey
    void AddRoundKey(const uint64_t& round) {for (auto& array: arrays) array.AddRoundKey(round, expanded);}

    // SubBytes.
    void SubBytes() {for (auto& array: arrays) array.SubBytes();}
    void InvSubBytes() {for (auto& array: arrays) array.InvSubBytes();}

    // ShiftRows
    void ShiftRows() {for (auto& array: arrays) array.ShiftRows();}
    void InvShiftRows() {for (auto& array: arrays) array.InvShiftRows();}

    // MixColumns
    void MixColumns() {for (auto& array: arrays) array.MixColumns();}
    void InvMixColumns() {for (auto& array: arrays) array.InvMixColumns();}
  };


  /**
   * @brief Encrypt a message with AES
   * @param in: The input string.
   * @param k: The key
   * @param Nr: The number of rounds we should run (Determine how much of the key is used).
   * @remarks This function is intentionally a verbatim translation of the
   * pseudo-code outlined in Algorithm 1 of the Reference.
   * @warning This function, on its own is no different from ECB!
   */
  std::string Cipher(const std::string& in, const std::array<uint64_t, 4>& k, const uint64_t& Nr) {
    auto s = state(in, k, Nr);
    s.AddRoundKey(0);

    for (size_t x = 0; x < Nr - 1; ++x) {
      s.SubBytes();
      s.ShiftRows();
      s.MixColumns();
      s.AddRoundKey(x + 1);
    }

    s.SubBytes();
    s.ShiftRows();
    s.AddRoundKey(Nr - 1);

    return s.unravel();
  }


  /**
   * @brief Decrypt a message with AES
   * @param in: The input string.
   * @param k: The key
   * @param Nr: The number of rounds to run.
   * @remarks This function is intentionally a verbatim translation of the
   * pseudo-code outlined in Algorithm 3 of the Reference.
   * @warning This function, on its own is no different from ECB!
   */
  std::string InvCipher(const std::string& in, const std::array<uint64_t, 4>& k, const uint64_t& Nr) {
    auto s = state(in, k, Nr);

    // Because the AddRoundKey is literally just XOR, running it again, but in reverse (Nr-1 -> 0),
    // undoes the operation, so we don't need a dedicated InvAddRoundKey like the other
    // steps.
    s.AddRoundKey(Nr - 1);

    for (size_t x = Nr - 1; x >= 1; --x) {
      s.InvShiftRows();
      s.InvSubBytes();
      s.AddRoundKey(x);
      s.InvMixColumns();
    }

    s.InvShiftRows();
    s.InvSubBytes();
    s.AddRoundKey(0);

    return s.unravel();
  }


  /**
   * @brief An implementation of AES in CTR mode.
   * @param in: The input string.
   * @param k: The key.
   * @param Nr: The number of rounds to perform.
   * @param nonce: The nonce value to use.
   * @remark CTR mode generates a OTP that is then XOR'ed to the message. Therefore, Encryption/Decryption
   * Uses the same function.
   */
  std::string Ctr(const std::string& in, const std::array<uint64_t, 4>& k, const uint64_t Nr, uint64_t nonce) {
    // We just use this to partition the input into individual state_arrays.
    auto s = state(in, k, Nr);

    // Go through each array.
    for (auto& array: s.get_arrays()) {

      // Generate a Pad for it.
      auto pad = state_array(Cipher(std::string(reinterpret_cast<char*>(&nonce), sizeof(uint64_t)), k, Nr));

      // XOR
      array.xor_arr(pad);

      // Increment the nonce for the next array.
      nonce++;
    }

    // Unravel the state.
    return s.unravel();
  }


  /**
   * @brief Functions related to AES-GCM.
   * @remarks These functions have been created in reference to:
   * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
   * Herein referred to as "The Reference" (The AES reference is not
   * Used here).
   */
  namespace gcm {

    /**
     * @brief The Nonce Increment Function.
     * @param the state array used as the counter.
     * @remarks GCM uses a "more sophisticated" means of stepping the
     * Counter that is passed to AES with the Key to generate the Pad.
     * @remarks See 6.2 of the Reference.
     * @remarks I couldn't find a reason for why the increment is performed
     * This way. By only incrementing the first four bytes, it technically
     * limits the size of the message to 4294967296 blocks, and we then repeat
     * A nonce, which would be disaterous. That value is equal to 64GB. My best
     * Guess is that a more performant implementation (One that wouldn't need to
     * deconstruct the last four bytes into a new number), would be able to just cast
     * The last bits, treat it like the very fast uint32_t directly, and increment
     * it with instructions that are blazingly fast with this datatype (int defaults
     * to 32bit specifically because it's fast, even faster than the native register
     * size of 64bit. You can see this by using uint_fast32_t, which C++ mandates as
     * an integer at least 32 bits, but can be faster if performance will improve
     * (See https://en.cppreference.com/w/cpp/types/integer). Yet, on every computer
     * I've personally used, it will always be a 32 bit value, not a 64 bit, which
     * is neat).
     */
     void increment(state_array& X) {
       // Get the underlying array.
       auto& array = X.get();

       // The state array is always 128 bits, so len(X) = 128/8 = 16.
       // While the Reference makes the increment function generic in
       // Terms of the s value, it is always used with s=32 within GCM,
       // which is 4 bytes.
       //
       // The incrementing function takes the len(X) - s Most
       // Significant Bits (The first 12 bytes), and does nothing.
       //
       // Then, it takes the s least significant bits (the last 4)
       // Bytes, casts it into a integer, adds one, and then applies
       // A modulus 2**s, and then brings it all back together.
       //
       // So, for the purpose of implementation, we just need to
       // extract the last four bytes of the state_array used for
       // the counter (Which just means the last column for our
       // implementation, treat the entire thing as a single value,
       // increment it, mod it, and then replace the existing values
       // with these new values.
       //

       // Basically we just take each 8bit value, and shift it:
       // uint32_t = 00000000 00000000 00000000 00000000 |
       //            11111111 00000000 00000000 00000000 | (array[3][0])
       //            00000000 11111111 00000000 00000000 | (array[3][1])
       //            00000000 00000000 11111111 00000000 | (array[3][2])
       //            00000000 00000000 00000000 11111111 | (array[3][3])
       //            -----------------------------------
       //            11111111 11111111 11111111 11111111
       //
       // Don't think about this too hard, it just takes our bytes in the state_array
       // and puts them into a form so that we can increment the entire thing.
       uint32_t lsb = (array[3][0] << 24) | (array[3][1] << 16) | (array[3][2] << 8) | array[3][3];

       // Fun fact, since we're working with uint32_t, modding by 2**32 is not required, since if the
       // value is exceeded, it will automatically overflow for us. Therefore, we can just increment it
       // And let C++ handle the "mod".
       lsb += 1;

       // This just returns the value into individual 8 bit values in the array.
       // We go in reverse because the first 8 bits are array[3][3].
       for (int x = 3; x >= 0; --x) {

         // Mask to get the first 8 bits. Then shift those values out to get the next eight.
         array[3][x] = lsb & 0xFF;
         lsb >>= 8;
       }
     }


     /**
      * @brief Perform a multiplication on two blocks of data.
      * @param X: The first block.
      * @param Y: The second block.
      * @returns: The resultant block.
      * @remarks See 6.3 of the Reference.
      */
     state_array mult(const state_array& X, const state_array& Y) {
      // This is just a constant. Which is just a state version
      // of the reducing polynomial.
      state_array R;
      R.get()[0][0] = 0b11100001;

      // Basically to multiply we start with generation 0
      // Of Z, V, and then iterating through each BIT of
      // X, we mutate Z and V. Once we've gone through
      // All the bits, we'll have 128 generations, and
      // we return the last Z.
      //
      // You may notice this scheme is very similar to our Galois
      // Field 128 mult, which takes one of the numbers, continually
      // bit shifts it down to zero, and then performs XOR depending
      // on that bit. This is little more than a state_array version
      // of that function! Go back up to gf::mult and compare!
      //
      state_array Z, V = Y;

      // To iterate through X, we just do our normal row, col
      // Iteration, and then for each value, we iterate 8 times
      // For each bit.
      for (size_t row = 0; row < 4; ++row) {
        for (size_t col = 0; col < 4; ++col) {
          uint8_t byte = X.get()[col][row];
          for (size_t bit = 0; bit < 8; ++bit) {
          // We can treat this as a boolean, as every non-zero
          // value is "true".
          bool x = byte & 0b10000000;

          // If x_i = 1, Z+1 = Z ^ V. Otherwise, it is unchanged.
          if (x) Z.xor_arr(V);

          // If the least significant bit of V is 1, we
          // Shift V, and then XOR it with R.
          // Otherwise, we just Shift it.
          V.shift_r(1);
          if (V.get()[3][3] & 1 == 1)
            V.xor_arr(R);

          // Shift to the next bit.
          byte << 1;
          }
        }
      }
      return Z;
    }


    /**
     * @brief Calculate the GHASH for a state.
     * @param X: The state
     * @param H: The hash subkey.
     * @returns The hash block.
     * @remarks See 6.4 of the Reference.
     * @remarks This function operates almost identically to a MAC, like HMAC-SHA256
     * (Hence the name). Basically we set an initial generation of Y, and then
     * Update that value for every block in the state. We do this with a fast XOR,
     * And then apply our multiplication on the hash subkey. Since the hash subkey
     * Is derived from the key and nonce, this is essentially the key in an HMAC,
     * And the state is the data that runs through the hashing algorithm. By
     * The end of the iteration, we have a block that has been influenced by not only
     * the key, but every block in the state, hence arriving at a hash that, if the key
     * or any block has been modified, will not match. Since it's also a state_array itself,
     * We can trivially append it to the end of the state, and unravel the entire thing
     * Without needing to send an explicit HMAC value across.
     */
    state_array GHASH(const state& X, const state_array& H) {
      state_array Y;

      // Set the new generation of Y to (Y XOR X_i) * H;
      for (const auto& array: X.get_arrays()) {
        Y.xor_arr(array);
        Y = mult(Y, H);
      }
      return Y;
    }


    /**
     * @brief Apply AES-CTR to a message.
     * @param s: The state to operate on.
     * @param ICB: The initial vector, or nonce.
     * @returns The encrypted/decrypted state.
     * @remarks See 6.5 of the Reference, and Figure 2.
     * @remarks As the name suggests, this is pretty much identical to AES-CTR, Specifically the Ctr function in
     * This file. The only difference is that our nonce is a state_array, instead of a number (Which isn't specific
     * To GCM or CTR, but is just how we implemented it in this case), we increment by a special function, rather than
     * just adding one, and we return the state, rather than the unravelled string, so that we can compute the GHASH.
     */
    state GCTR(state s, state_array ICB) {
      // Go through each array.
      for (auto& array: s.get_arrays()) {

        // Generate a Pad for it.
        // I KNOW. Unravelling the ICB, and then generating a state is not the pinnacle of efficiency,
        // but creating a separate Cipher for handling a state_array/state would length an already massive
        // source file.
        auto pad = state_array(Cipher(ICB.unravel(), s.get_key(), s.get_rounds()));

        // XOR
        array.xor_arr(pad);

        // Increment the nonce for the next array.
        increment(ICB);
      }
      return s;
    }


    /*
     * @brief Encrypt a message with AES-GCM
     * @param in: The input string.
     * @param k: The key.
     * @param Nr: The number of rounds to perform.
     * @param nonce: The nonce IV.
     * @returns An encrypted string, with the hash block attached to the end
     */
    std::string Enc(const std::string& in, const std::array<uint64_t, 4>& k, const uint64_t Nr, uint64_t nonce) {

      // Generate our H hash subkey by encrypting a 0 block.
      state_array H = Cipher("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", k, Nr);

      // Generate the J0 that we'll use as a counter, based on our IV/Nonce.
      auto J = GHASH(state(std::string(reinterpret_cast<char*>(&nonce), sizeof(nonce)), k, Nr), H);

      // This J is incremented for encrypting the message (We use J0 for the hash). This is so that
      // We can immediately check the hash on the decryption step, avoiding having to decrypt the message
      // before we can verify if it's been modified
      auto Jc = J;
      increment(Jc);

      // Encrypt our message.
      auto cipher_state = state(in, k, Nr);
      cipher_state = GCTR(cipher_state, Jc);

      // Generate our Hash. Basically, we run GHASH to get a single block or state_array, and then turn that into
      // A "state" of 1 so that GCTR can encrypt it, and then pull out the singular block to get a state_array again.
      // One thing to note here, is that this block, called S in the Reference,
      // Can optionally take AAD, or Additional Authenticated Data, which can be
      // anything from destination IP, to Names (This data will be Authenticated, but must be sent in the clear)
      // . For this implementation the only AAD that we would consider is the Nonce, but since it's already
      // Included in the Hash via J, we just hash the cipher.
      auto hash = GCTR(state({GHASH(cipher_state, H)}, k, Nr), J).get_arrays()[0];

      // Add the hash to the end of the cipher_state, and return it as one object.
      cipher_state.get_arrays().emplace_back(hash);
      return cipher_state.unravel();
    }


    /**
     * @brief Decrypt a message with AES-GCM
     * @param in: The ciphertext.
     * @param k: The key.
     * @param Nr: The number of rounds to perform.
     * @param nonce: The nonce value/IV.
     * @returns The plaintext message.
     * @throws std::runtime_error if the message has been modified or an incorrect key was supplied.
     */
    std::string Dec(const std::string& in, const std::array<uint64_t, 4>& k, const uint64_t Nr, uint64_t nonce) {

      // Generate our H hash subkey by encrypting a 0 block.
      state_array H = Cipher("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", k, Nr);

      // Generate the J0 that we'll use as a counter, based on our IV/Nonce.
      auto J = GHASH(state(std::string(reinterpret_cast<char*>(&nonce), sizeof(nonce)), k, Nr), H);

      // Get the cipher, and then pop the hash off the back.
      auto cipher_state = state(in, k, Nr);
      auto hash = cipher_state.get_arrays().back();
      cipher_state.get_arrays().pop_back();

      // Then, compute the hash using J.
      hash = GCTR(state({hash}, k, Nr), J).get_arrays()[0];

      // If they don't match then either the key was wrong, or one of the blocks has been modified.
      // Either way, throw a runtime error.
      if (hash.unravel() != GHASH(cipher_state, H).unravel()) {
        throw std::runtime_error("Message does not match! Refusing to decrypt!");
      }

      // If they do match, then increment J and proceed with decryption.
      increment(J);
      return GCTR(cipher_state, J).unravel();
    }
  }
}
