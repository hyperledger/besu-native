package main

import "C"
import (
    "encoding/hex"
	"errors"
    "fmt"
	"unsafe"
    "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const (
	EIP2537PreallocateForResultBytes = 64 * 2 * 2 // maximum for G2 point
	EIP2537PreallocateForG1 = 64 * 2 // G1 points are 48 bytes, left padded with zero for 16 bytes
)

//export eip2537blsG1Add
func eip2537blsG1Add(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {

    fmt.Printf("Expected outputLen: %d\n", outputLen)
    fmt.Printf("Expected inputLen: %d\n", cInputLen)

    var inputLen = int(cInputLen)

    if outputLen != EIP2537PreallocateForResultBytes {
        fmt.Printf("found invalid output len size : %d\n", outputLen)
        return -1
    }
    output := (*[EIP2537PreallocateForResultBytes]byte)(unsafe.Pointer(javaOutputBuf))[:outputLen:outputLen]
    fmt.Printf("go output array size: %d\n", len(output))

    if inputLen != 2*EIP2537PreallocateForG1 {
        fmt.Printf("found invalid input len size : %d\n", inputLen)
        copy(output, "invalid input parameters, invalid input length for G1 addition\x00")
        return -1
    }

    // Convert C pointers to Go slices
    input := (*[2*EIP2537PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]
    fmt.Printf("go input array size: %d\n", len(input))
    fmt.Printf("g1x1 point encoding plus 16 byte padding: %s\n", hex.EncodeToString(input[:64]))
    fmt.Printf("g1y1 point encoding plus 16 byte padding: %s\n", hex.EncodeToString(input[64:128]))
    fmt.Printf("g1x2 point encoding plus 16 byte padding: %s\n", hex.EncodeToString(input[128:192]))
    fmt.Printf("g1y2 point encoding plus 16 byte padding: %s\n", hex.EncodeToString(input[192:]))

    p0, err := g1AffineDecode(input[:128])

    if err != nil {
        fmt.Printf("error decoding p0: %s\n", err.Error())
        copy(output, err.Error())
        return -1
    }
//     fmt.Printf("point p0: ", p0)

    p1, err := g1AffineDecode(input[128:])

    if err != nil {
        fmt.Printf("error decoding p1: %s\n", err.Error())
        copy(output, err.Error())
        return -1
    }

    result := p0.Add(p0, p1) // Use the Add method to combine points
    ret := result.Marshal()
    fmt.Printf("nothing exploded, val %s", hex.EncodeToString(ret))
    copy(output, ret)
    return 1 // marshal the resulting point

}

func eip2537ExecutorG1Mul(input []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func eip2537ExecutorG1MultiExp(input []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func eip2537ExecutorG2Add(input []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func eip2537ExecutorG2Mul(input []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func eip2537ExecutorG2MultiExp(input []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func eip2537ExecutorPair(input []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func eip2537ExecutorMapFpToG1(input []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func eip2537ExecutorMapFp2ToG2(input []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func g1AffineDecode(input []byte) (*bls12381.G1Affine, error) {
    // TODO check 0:16 and 64:80 for zeroes

    g1x := input[16:64]
    g1y := input[80:128]
    g1 := &bls12381.G1Affine{};
    // this does subgroup checks by default, could be slow according to Marius, consider using setBytes
    err := g1.Unmarshal(append(g1x, g1y...))
    return g1, err
}

func main() {}
