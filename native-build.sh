#!/bin/bash
apt-get update
DEBIAN_FRONTEND=non-interactive apt-get install -y autoconf build-essential libtool automake patchelf curl openjdk-11-jre-headless git
export CARGO_HOME="$HOME/.cargo"
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.62.1
export PATH=$PATH:$CARGO_HOME/bin
git config --global --add safe.directory /home/ubuntu/secp256r1/besu-native-ec
/home/ubuntu/build.sh
