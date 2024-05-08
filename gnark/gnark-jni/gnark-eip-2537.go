package main

/*
#include <string.h>
*/
import "C"
import (
	"errors"
	"unsafe"
    "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const (
	EIP2537PreallocateForResultBytes = 64 * 2 * 2 // maximum for G2 point
	EIP2537PreallocateForG1 = 64 * 2 // G1 points are 48 bytes, left padded with zero for 16 bytes
)

//export eip2537blsG1Add
func eip2537blsG1Add(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {

    var inputLen = int(cInputLen)

    if outputLen != EIP2537PreallocateForResultBytes {
        return -1
    }
    // Convert output C pointers to Go slices
    output := (*[EIP2537PreallocateForResultBytes]byte)(unsafe.Pointer(javaOutputBuf))[:outputLen:outputLen]

    if inputLen != 2*EIP2537PreallocateForG1 {
        copy(output, "invalid input parameters, invalid input length for G1 addition\x00")
        return -1
    }

    // Convert input C pointers to Go slices
    input := (*[2*EIP2537PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

    // generate p0 g1 affine
    p0, err := g1AffineDecode(input[:128])

    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // generate p0 g1 affine
    p1, err := g1AffineDecode(input[128:])

    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // Use the Add method to combine points
    result := p0.Add(p0, p1)
    // marshal the resulting point and enocde directly to the output buffer
    ret := result.Marshal()
    g1AffineEncode(ret, javaOutputBuf)
    return 1

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
    // TODO check 0:16 and 64:80 are zeroes
    g1x := input[16:64]
    g1y := input[80:128]
    g1 := &bls12381.G1Affine{};
    // Unmarshal does point-in-curve and subgroup checks by default, consider setBytes instead for G1Add
    err := g1.Unmarshal(append(g1x, g1y...))
    return g1, err
}

func g1AffineEncode(g1Point []byte, output *C.char) (error) {
    // Check if point is not nil
    if g1Point == nil {
        return errors.New("point cannot be nil")
    }

    // gnark returns two 48 byte points in a packed array,
    // we need two 64 byte points with prepended zeroes, in a packed array
    g1x := unsafe.Pointer(&g1Point[0])
    g1y := unsafe.Pointer(&g1Point[48])

    // java should pass a zero-initialized ByteBuffer, copy x to output[16:64],
    C.memcpy(unsafe.Pointer(uintptr(unsafe.Pointer(output))+16), g1x, 48)

    // Copy y to output[80:128]
    C.memcpy(unsafe.Pointer(uintptr(unsafe.Pointer(output))+80), g1y, 48)

    return nil
}

func main() {}
