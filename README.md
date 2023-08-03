# Besu Native

This repository contains scripts and tooling that is used to build and package the native libraries
used by Hyperledger Besu.

Besu Native libraries are licensed unde the [Apache 2.0 License](LICENSE).

## Prerequisites

### Linux

You'll need to be sure that gcc, make, autoconf, automake, and libtool are installed. If you are
building on Ubuntu or Debian, the following command will install these dependencies for you:

```
sudo apt-get install build-essential automake autoconf libtool patchelf
```

### OS X

You'll need to be sure that XCode Command Line Tools, make, autoconf, automake, and libtool are
installed. The easiest way to do this is to install [Homebrew](https://brew.sh/), and then run the
following command. Note that installing Homebrew will automatically install the XCode command line
tools.

```
brew install autoconf automake libtool
```

### Windows

TBD

### Rust

Rust needs to be installed to compile the arithmetic and bls12-381 libraries. The default way to install it on Linux or OS X is:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

If you prefer another installation method please refer to the [Rust installation instructions](https://www.rust-lang.org/tools/install).

## Building

1. This repository builds native libraries from source that is included as git submodules. To be
   sure that you have cloned those submodules into the appropriate locations,
   run `git submodule init && git submodule update`
2. The build steps are entirely contained within the `build.sh` script at the repository root.
   Simply run this script, and all the native modules contained herein will be configured with the
   correct build options for Hyperledger Besu, and built.

