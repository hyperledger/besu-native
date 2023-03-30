package main

import "C"
import "unsafe"
import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func MiMCHash(b []byte) []byte {
     hasher := mimc.NewMiMC()
     hasher.Write(b)
     return hasher.Sum(nil)
}


//export compute
func compute(input *C.char, inputLength C.int) *C.char {
       inputSlice := C.GoBytes(unsafe.Pointer(input), inputLength)
       hash := MiMCHash(inputSlice)
       return C.CString(string(hash))
}

func main() {}