#include <fstream>    // Manage files
#include <iostream>   // Manage consoles
#include <map>        // To store arguments.
#include <string>     // For strings.
#include <sstream>    // For streams
#include <random>     // For nonce generation
#include <ctime>      // To seed the RNG.

#include "aes.h"      // For our AES Implementation

// Main must be explicitly written like this to receive command line arguments.
// argc is the number of arguments (The program name itself is considered an argument)
// argv is the list of arguments themselves.
int main(int argc, char* argv[]) {

  // Seed for the Nonce.
  std::srand(std::time(0));

  // Collect command line arguments.
  std::map<std::string, std::string> arguments;
  for (size_t x = 0; x < argc; ++x) {

    // Split it on the =
    // If it doesn't exist, we'll just have --title: --title
    auto arg = std::string(argv[x]);
    size_t delim = arg.find("=");
    arguments[arg.substr(0, delim)] = arg.substr(delim + 1);
  }

  // Print the help screen if the user requests it.
  if (arguments.count("--help")) {
    std::stringstream help;
    help << "Usage: aes (--infile=/path/to/file) (--outfile=/path/to/file) (--keyfile=/path/to/file) [--mode=MODE] (--verbose)\n"
        << "--infile: The path to the file. If not provided, read from standard input\n"
        << "--outfile: The path to write to. If not provided, write to standard output\n"
        << "--keyfile: The path to load the key. If not provided, user will be prompted\n"
        << "--mode: The mode. Must follow the pattern ENC-256-CTR. For example:\n"
        << "  DEC-192-ECB: Decrypt the infile with AES-ECB with a 192 bit key\n"
        << "  ENC-128-CTR: Encrypt the infile with AES-CTR with a 128 bit key\n"
        << "  Valid options for each field are: ENC/DEC, 128/192/256, ECB/CTR/GCM\n"
        << "--verbose: Print verbose information to console\n";
    std::cout << help.str() << std::endl;
    return 0;
  }

  // Ensure mode has been provided.
  if (!arguments.count("--mode") || arguments["--mode"].length() != 11) {
    std::cerr << "A valid mode string must be provided. See --help for details" << std::endl;
    return -1;
  }

  // Ensure that the operation is correct.
  auto operation = arguments["--mode"].substr(0, 3);
  if (operation != "ENC" && operation != "DEC") {
    std::cerr << "Unrecognized operation: " << operation << ". Valid options are ENC/DEC" << std::endl;
    return -1;
  }

  // Ensure that the key size is correct.
  auto key_size = arguments["--mode"].substr(4, 3);
  uint64_t size = 0, rounds = 0, keys = 0;
  if (key_size == "128") {size = 128; rounds = 10; keys = 2;}
  else if (key_size == "192") {size = 192; rounds = 12; keys = 3;}
  else if (key_size == "256") {size = 256; rounds = 14; keys = 4;}
  else {
    std::cerr << "Unrecognized key size: " << key_size << ". Valid options are 128/192/256" << std::endl;
    return -1;
  }

  // Ensure that the mode is correct.
  auto mode = arguments["--mode"].substr(8, 3);
  if (mode != "ECB" && mode != "CTR" && mode != "GCM") {
    std::cerr << "Unrecognized mode: " << mode << ". Valid operations are ECB/CTR/GCM" << std::endl;
    return -1;
  }

  std::string input;

  // Get the key.
  std::array<uint64_t, 4> key = {0, 0, 0, 0};
  if (arguments.count("--keyfile")) {
    auto keyfile = std::ifstream(arguments["--keyfile"], std::ios::in|std::ios::binary);
    std::getline(keyfile, input);
    keyfile.close();
  }
  else {
    std::cout << "Enter the key:" << std::endl;
    std::getline(std::cin, input);
  }

  // Add padding if they don't provide a good key.
  if (input.length() < size / 8) {
    std::cout << "WARNING: Key only contain " << input.length() * 8 << " Bits of information! Remainder of key has been zeroed!" << std::endl;
    // Pad with 0s.
    while (input.length() < size / 8) {input += '\0';}
  }

  // Cast into a format our AES can handle.
  for (size_t x = 0; x < keys; ++x)
    key[x] = *reinterpret_cast<uint64_t*>(&input[x * sizeof(uint64_t)]);

  // Get the input. We initialize the Nonce here, even though ECB doesn't use it, and DEC overwrites it.
  uint64_t nonce = std::rand();

  // Get our infile
  if (arguments.count("--infile")) {
    auto infile = std::ifstream(arguments["--infile"], std::ios::in|std::ios::binary);

    std::ostringstream stream;
    stream << infile.rdbuf();
    input = stream.str();
    infile.close();

    // If we are in Decryption mode, the Nonce is at the start of the file.
    if (operation == "DEC") {
      nonce = *reinterpret_cast<const uint64_t*>(input.c_str());

      // Skip past the nonce.
      input = input.substr(sizeof(uint64_t));
    }
  }

  // If no infile, ask for input directly.
  else {
    std::cout << "Enter the input text:" << std::endl;
    std::getline(std::cin, input);

    // In the only situation where the Nonce is used, ask for it.
    if (mode == "ECB" && operation == "DEC") {
      std::cout << "Enter the Nonce: " << std::endl;
      std::cin >> nonce;
    }
  }

  // If encrypting
  if (operation == "ENC") {

    // Generate the ciphertext.
    std::string cipher;
    if (mode == "ECB") cipher = aes::Cipher(input, key, rounds);
    else if (mode == "CTR") cipher = aes::Ctr(input, key, rounds, nonce);
    else if (mode == "GCM") cipher = aes::gcm::Enc(input, key, rounds, nonce);

    // If there is no outfile, or there is one but we want verbose output, print the values.
    if (!arguments.count("--outfile") || arguments.count("--verbose")) {
      std::cout << "Nonce: " << nonce << std::endl;
      std::cout << "Ciphertext: ";
      for (const auto& x : cipher) {std::cout << int(x) << ' ';}
      std::cout << std::endl;
    }

    // If there is an outfile, write the ciphertext to it.
    if (arguments.count("--outfile")) {
      auto outfile = std::ofstream(arguments["--outfile"], std::ios::out|std::ios::binary);
      // Write the nonce, then the cipher.
      outfile.write(reinterpret_cast<char*>(&nonce), sizeof(uint64_t));
      outfile.write(cipher.c_str(), cipher.length());
      outfile.close();
    }
  }

  // If we're decrypting.
  else if (operation == "DEC") {

    // Generate the plaintext.
    std::string plain;
    if (mode == "ECB") plain = aes::InvCipher(input, key, rounds);
    else if (mode == "CTR") plain = aes::Ctr(input, key, rounds, nonce);
    else if (mode == "GCM") plain = aes::gcm::Dec(input, key, rounds, nonce);

    // If there isn't an outfile, or there is one but we are verbose, print values to console.
    if (!arguments.count("--outfile") || arguments.count("--verbose")) {
      std::cout << "Nonce: " << nonce << std::endl;
      std::cout << "Ciphertext: ";
      for (const auto& x : input) {std::cout << int(x) << ' ';}
      std::cout << std::endl;
      std::cout << "Plaintext: " << plain << std::endl;
    }

    // If there is an outfile, write it.
    if (arguments.count("--outfile")) {
      auto outfile = std::ofstream(arguments["--outfile"], std::ios::out|std::ios::binary);
      outfile.write(plain.c_str(), plain.length());
      outfile.close();
    }
  }

  return 0;
}
