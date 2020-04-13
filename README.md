# Besu Native

This repository contains scripts and tooling that is used to build and package the native libraries used by Hyperledger Besu.

## Prerequisites

### Linux

You'll need to be sure that gcc, make, autoconf, automake, and libtool are installed. If you are building on Ubuntu or Debian, the following command will install these dependencies for you:

```
sudo apt-get install build-essential automake autoconf libtool
```

### OS X

You'll need to be sure that XCode Command Line Tools, make, autoconf, automake, and libtool are installed. The easiest way to do this is to install [Homebrew](https://brew.sh/), and then run the following command. Note that installing Homebrew will automatically install the XCode command line tools.

```
brew install autoconf automake libtool
```

### Windows

TBD

## Building

1. This repository builds native libraries from source that is included as git submodules. To be sure that you have cloned those submodules into the appropriate locations, run `git submodule update`
2. The build steps are entirely contained within the `build.sh` script at the repository root. Simply run this script, and all of the native modules contained herin will be configured with the correct build options for Hyperledger Besu, and built.

