# Changelog

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