#!/bin/bash
apt-get update
DEBIAN_FRONTEND=non-interactive apt-get install -y autoconf build-essential libtool automake patchelf curl openjdk-11-jre-headless git wget
wget https://go.dev/dl/go1.20.2.linux-arm64.tar.gz
echo "78d632915bb75e9a6356a47a42625fd1a785c83a64a643fedd8f61e31b1b3bef  go1.20.2.linux-arm64.tar.gz" | sha256sum -c || exit 1
tar -xzf go1.20.2.linux-arm64.tar.gz -C $HOME
export GOPATH=$HOME/.go
mkdir -p $GOPATH
export GOROOT="$HOME/go"
export PATH="$GOROOT/bin":$PATH
export CARGO_HOME="$HOME/.cargo"
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.68.2
export PATH=$PATH:$CARGO_HOME/bin
git config --global --add safe.directory /home/ubuntu/secp256r1/besu-native-ec
git config --global --add safe.directory /home/ubuntu/secp256r1/besu-native-ec/openssl
/home/ubuntu/build.sh
