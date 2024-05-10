package main

/*
#include <string.h>
*/
import "C"
import (
	"errors"
// 	"fmt"
	"math/big"
// 	"time"
	"unsafe"
    "github.com/consensys/gnark-crypto/ecc/bls12-381"
    "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

const (
	EIP2537PreallocateForResultBytes = 64 * 2 * 2 // maximum for G2 point
	EIP2537PreallocateForG1 = 64 * 2 // G1 points are 48 bytes, left padded with zero for 16 bytes
	EIP2537PreallocateForScalar = 32 // scalar int is 32 byte
)

var ErrSubgroupCheckFailed = errors.New("invalid point: subgroup check failed")
var ErrPointOnCurveCheckFailed = errors.New("invalid point: point is not on curve")


//export eip2537blsG1Add
func eip2537blsG1Add(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
//     startTime := time.Now()
//     fmt.Printf("start time: %v\n", time.Since(startTime))
    var inputLen = int(cInputLen)
//     fmt.Printf("convert int time: %v\n", time.Since(startTime))

    if outputLen != EIP2537PreallocateForResultBytes {
        return -1
    }
    // Convert output C pointers to Go slices
    output := (*[EIP2537PreallocateForResultBytes]byte)(unsafe.Pointer(javaOutputBuf))[:outputLen:outputLen]
//     fmt.Printf("convert output array time: %v\n", time.Since(startTime))

    if inputLen != 2*EIP2537PreallocateForG1 {
        copy(output, "invalid input parameters, invalid input length for G1 addition\x00")
        return -1
    }

    // Convert input C pointers to Go slices
    input := (*[2*EIP2537PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]
//     fmt.Printf("convert input array time: %v\n", time.Since(startTime))

    // generate p0 g1 affine
    p0, err := g1AffineDecodeOnCurve(input[:128])
//     fmt.Printf("convert g1 p0 affine time: %v\n", time.Since(startTime))

    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // generate p0 g1 affine
    p1, err := g1AffineDecodeOnCurve(input[128:])
//     fmt.Printf("convert g1 p1 affine time: %v\n", time.Since(startTime))

    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // Use the Add method to combine points
    result := p0.Add(p0, p1)
//     fmt.Printf("add p0 p1 time: %v\n", time.Since(startTime))

    // marshal the resulting point and enocde directly to the output buffer
    ret := result.Marshal()
//     fmt.Printf("marshal time: %v\n", time.Since(startTime))
    g1AffineEncode(ret, javaOutputBuf)
//     fmt.Printf("g1 affine encode time: %v\n", time.Since(startTime))
    return 1

}

//export eip2537blsG1Mul
func eip2537blsG1Mul(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    //TODO: DRY up
    var inputLen = int(cInputLen)
    if outputLen != EIP2537PreallocateForResultBytes {
        return -1
    }
    output := (*[EIP2537PreallocateForResultBytes]byte)(unsafe.Pointer(javaOutputBuf))[:outputLen:outputLen]

    if inputLen != (EIP2537PreallocateForG1 + EIP2537PreallocateForScalar){
        copy(output, "invalid input parameters, invalid input length for G1 multiplication\x00")
        return -1
    }

    // Convert input C pointers to Go slice
    input := (*[EIP2537PreallocateForG1 + EIP2537PreallocateForScalar]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

    // generate p0 g1 affine
    p0, err := g1AffineDecodeInSubGroup(input[:128])

    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // Convert byte slice to *big.Int
    scalar := big.NewInt(0)
    scalar.SetBytes(input[128:160])

    // multiply g1 point by scalar
    result := p0.ScalarMultiplication(p0, scalar)

    // marshal the resulting point and encode directly to the output buffer
    ret := result.Marshal()
    g1AffineEncode(ret, javaOutputBuf)
    return 1
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

func g1AffineDecodeInSubGroup(input []byte) (*bls12381.G1Affine, error) {
    // TODO check 0:16 and 64:80 are zeroes
    var g1x, g1y fp.Element
    g1x.Unmarshal(input[16:64])
    g1y.Unmarshal(input[80:128])
    // construct g1affine directly rather than unmarshalling
    g1 := &bls12381.G1Affine{X: g1x, Y: g1y}

    // do explicit subgroup check
    if (!g1.IsInSubGroup()) {
        if (!g1.IsOnCurve()) {
            return nil, ErrPointOnCurveCheckFailed
        }
        return nil, ErrSubgroupCheckFailed
    }
    return g1, nil;
}

func g1AffineDecodeOnCurve(input []byte) (*bls12381.G1Affine, error) {
    // TODO check 0:16 and 64:80 are zeroes
    var g1x, g1y fp.Element
    g1x.Unmarshal(input[16:64])
    g1y.Unmarshal(input[80:128])
    // construct g1affine directly rather than unmarshalling
    g1 := &bls12381.G1Affine{X: g1x, Y: g1y}
    // do not do subgroup checks, only point-on-curve.  G1Add is spec'd this way for 2537
    if (!g1.IsOnCurve()) {
        return nil, ErrPointOnCurveCheckFailed
    }

    return g1, nil;
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
