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
func compute(input *C.char, inputLength C.int, output *C.char) C.int {
       inputSlice := C.GoBytes(unsafe.Pointer(input), inputLength)
       outputSlice := (*[32]byte)(unsafe.Pointer(output))[:]
       hash := MiMCHash(inputSlice)
       copy(outputSlice, hash)
       return C.int(len(hash))
}

func main() {}