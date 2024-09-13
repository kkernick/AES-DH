
If you’d like to build the applications from source, you can simply run `make` within the directory, and both the `main` and `aes` application will be built. If you’d prefer to only build one, simply specify that application after the make command, such as `make main` or `make aes`.

You’ll need the C++ compiler from the GNU Compiler Collection (GCC): `g++`. If you run into an error like:
```bash
make: g++: No such file or directory
```

You’ll need to install it from your package manager of choice. Some common options include:
* Debian-Based Distributions: `sudo apt-get install g++`
* Fedora/RHEL: `sudo dnf install gcc-c++`
* Arch-Based Distributions: `sudo pacman -Syu gcc

`main` uses OpenSSL in order to generate HMAC values, and you may run into an error complaining that an OpenSSL header could not be found:

```bash
hmac.h: fatal error: openssl/hmac.h: No such file or directory
```

To fix this, you’ll need to install the OpenSSL development headers. Again, some common examples:
* Debian-Based Distributions: `sudo apt-get install libssl-dev
* Fedora/RHEL: `sudo dnf install openssl-devel`
* Arch-Based Distributions: `sudo pacman -Syu openssl`