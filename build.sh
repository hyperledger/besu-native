#!/usr/bin/env bash

#############################
######### Variables #########
#############################

# Edit this variable to change the build options for secp256k1
SECP256K1_BUILD_OPTS="--enable-module-recovery"

#############################
####### End Variables #######
#############################

# Exit script if you try to use an uninitialized variable.
set -o nounset

# Exit script if a statement returns a non-true return value.
set -o errexit

# Use the error status of the first failure, rather than that of the last item in a pipeline.
set -o pipefail

# Resolve the directory that contains this script. We have to jump through a few
# hoops for this because the usual one-liners for this don't work if the script
# is a symlink
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
SCRIPTDIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"


# Determine core count for parallel make
if [[ "$OSTYPE" == "linux-gnu" ]];  then
  CORE_COUNT=$(nproc)
fi

if [[ "$OSTYPE" == "darwin"* ]];  then
  CORE_COUNT=$(sysctl -n hw.ncpu)
fi

#############################
###### build secp256k1 ######
#############################

cd "$SCRIPTDIR/secp256k1/bitcoin-core-secp256k1"

# delete old build dir, if exists
rm -rf "$SCRIPTDIR/secp256k1/built" || true



make clean && \
  ./autogen.sh && \
  ./configure --prefix="$SCRIPTDIR/secp256k1/built" $SECP256K1_BUILD_OPTS && \
  make -j $CORE_COUNT && \
  make -j $CORE_COUNT install

#TODO: kick off gradle steps here

#############################
#### end secp256k1 build ####
#############################

