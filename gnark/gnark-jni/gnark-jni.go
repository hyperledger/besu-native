package main

import "C"
import (
	"unsafe"

	mimcBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	mimcBn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func MiMCBls12377Hash(b []byte) []byte {
	hasher := mimcBls12377.NewMiMC()
	hasher.Write(b)
	return hasher.Sum(nil)
}

func MiMCBn254Hash(b []byte) []byte {
	hasher := mimcBn254.NewMiMC()
	hasher.Write(b)
	return hasher.Sum(nil)
}

//export computeMimcBn254
func computeMimcBn254(input *C.char, inputLength C.int, output *C.char) C.int {
	inputSlice := C.GoBytes(unsafe.Pointer(input), inputLength)
	outputSlice := (*[32]byte)(unsafe.Pointer(output))[:]
	hash := MiMCBn254Hash(inputSlice)
	copy(outputSlice, hash)
	return C.int(len(hash))
}

//export computeMimcBls12377
func computeMimcBls12377(input *C.char, inputLength C.int, output *C.char) C.int {
	inputSlice := C.GoBytes(unsafe.Pointer(input), inputLength)
	outputSlice := (*[32]byte)(unsafe.Pointer(output))[:]
	hash := MiMCBls12377Hash(inputSlice)
	copy(outputSlice, hash)
	return C.int(len(hash))
}

func main() {}
