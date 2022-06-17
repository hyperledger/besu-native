# Changelog

# 0.5.1-SNAPSHOT


# 0.5.0 

* Add linux-arm64 native support [#61](https://github.com/hyperledger/besu-native/pull/61)
* Add ipa-multipoint library support [#56](https://github.com/hyperledger/besu-native/pull/56)

## 0.4.3

* Use non-blocking PRNG to generate secp256k1 context [#51](https://github.com/hyperledger/besu-native/pull/51)
* Padding R and S components if smaller than 31 bytes in SECP256R1 keys [#52](https://github.com/hyperledger/besu-native/pull/52)

## 0.4.2

* Fix Besu integration on MacOS [#48](https://github.com/hyperledger/besu-native/pull/48)

## 0.4.1

* Fix native representation of native secp256r1 signatures [#45](https://github.com/hyperledger/besu-native/pull/45)

## 0.4.0

* Added support for secp256r1 via OpenSSL libraries.

## 0.3.0

* Upgraded secp256k1 to commit ac05f61fcf639a15b5101131561620303e4bd808, which
  improves performance by using efficiently-computable endomorphism.
* Add support for MatterLab's EIP196/197 for ECPairings, which are faster than
  the sputnikvm code.
  
## 0.2.0

* Add support for EIP-2537 (BLS12-381 precompiles ) via MatterLabs library
* Randomize secp256k1 context by default, with java property 
  `secp256k1.randomize` escape hatch to disable. In tight testing loop this 
  flag should be set to false.
  
## 0.1.0

* Add support for AltBN128 precompiles via sputnik VM
* Add support for secp256k1 via Bitcoin core library