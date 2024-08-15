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
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.75.0
export PATH=$PATH:$CARGO_HOME/bin
git config --global --add safe.directory /home/ubuntu/secp256r1/besu-native-ec
git config --global --add safe.directory /home/ubuntu/secp256r1/besu-native-ec/openssl
wget https://download.java.net/java/GA/jdk21.0.2/f2283984656d49d69e91c558476027ac/13/GPL/openjdk-21.0.2_linux-aarch64_bin.tar.gz
tar -xzf openjdk-21.0.2_linux-aarch64_bin.tar.gz -C $HOME
export JAVA_HOME=$HOME/jdk-21.0.2
export PATH=$JAVA_HOME/bin:$PATH
wget https://github.com/nim-lang/nightlies/releases/download/2024-03-28-version-2-0-b47747d31844c6bd9af4322efe55e24fefea544c/nim-2.0.4-linux_arm64.tar.xz
tar -xf nim-2.0.4-linux_arm64.tar.xz
git config --global --add safe.directory /home/ubuntu/constantine/constantine
/home/ubuntu/build.sh
