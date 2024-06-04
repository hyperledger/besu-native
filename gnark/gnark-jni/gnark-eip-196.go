package main

/*
#include <string.h>
*/
import "C"
import (
//     "bytes"
	"errors"
	"math/big"
	"unsafe"
    "github.com/consensys/gnark-crypto/ecc/bn254"
    "github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

const (
	EIP196PreallocateForScalar = 32 // scalar int is 32 byte
	EIP196PreallocateForFp = 32  // field elements are 32 bytes
	EIP196PreallocateForG1 = EIP196PreallocateForFp * 2 // G1 points are encoded as 2 concatenated field elements
	EIP196PreallocateForG2 = EIP196PreallocateForG1 * 2 // G2 points are encoded as 2 concatenated G1 points
)

var ErrPointOnCurveCheckFailed = errors.New("invalid point: point is not on curve")
var ErrMalformedOutputBytes = errors.New("malformed output buffer parameter")

// Predefine a zero slice of length 16
var zeroSlice = make([]byte, 16)

//export eip196altbn128G1Add
func eip196altbn128G1Add(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    var inputLen = int(cInputLen)

    if outputLen != EIP196PreallocateForG1 {
        return -1
    }
    // Convert output C pointers to Go slices
    output := (*[EIP196PreallocateForG1]byte)(unsafe.Pointer(javaOutputBuf))[:outputLen:outputLen]

    if inputLen != 2*EIP196PreallocateForG1 {
        copy(output, "invalid input parameters, invalid input length for G1 addition\x00")
        return -1
    }

    // Convert input C pointers to Go slices
    input := (*[2*EIP196PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]
//     fmt.Printf("convert input array time: %v\n", time.Since(startTime))

    // generate p0 g1 affine
    p0, err := g1AffineDecodeOnCurve(input[:64])

    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // generate p0 g1 affine
    p1, err := g1AffineDecodeOnCurve(input[64:])

    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // Use the Add method to combine points
    result := p0.Add(p0, p1)

    // marshal the resulting point and enocde directly to the output buffer
    ret := result.Marshal()
    g1AffineEncode(ret, javaOutputBuf)
    return 0

}

//export eip196altbn128G1Mul
func eip196altbn128G1Mul(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    var inputLen = int(cInputLen)

    output := castOutputBuffer(javaOutputBuf, outputLen)
    if inputLen != (EIP196PreallocateForG1 + EIP196PreallocateForScalar){
        copy(output, "invalid input parameters, invalid input length for G1 multiplication\x00")
        return -1
    }

    // Convert input C pointers to Go slice
    input := (*[EIP196PreallocateForG1 + EIP196PreallocateForScalar]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

    // generate p0 g1 affine
    p0, err := g1AffineDecodeOnCurve(input[:64])

    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // Convert byte slice to *big.Int
    scalar := big.NewInt(0)
    scalar.SetBytes(input[32:64])

    // multiply g1 point by scalar
    result := p0.ScalarMultiplication(p0, scalar)

    // marshal the resulting point and encode directly to the output buffer
    ret := result.Marshal()
    g1AffineEncode(ret, javaOutputBuf)
    return 0
}

//export eip196altbn128Pairing
func eip196altbn128Pairing(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    var inputLen = int(cInputLen)
    output := castOutputBuffer(javaOutputBuf, outputLen)

    if inputLen < (EIP196PreallocateForG2 + EIP196PreallocateForG1) {
        copy(output, "invalid input parameters, invalid number of pairs\x00")
        return -1
    }
    if inputLen % (EIP196PreallocateForG2 + EIP196PreallocateForG1) != 0 {
        copy(output, "invalid input parameters, invalid input length for pairing\x00")
        return -1
    }

    // Convert input C pointers to Go slice
    input := (*[EIP196PreallocateForG2 + EIP196PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

    var pairCount = inputLen / (EIP196PreallocateForG2 + EIP196PreallocateForG1)
    g1Points := make([]bn254.G1Affine, pairCount)
    g2Points := make([]bn254.G2Affine, pairCount)


    for i := 0 ; i < pairCount ; i++ {

        // get g1
        g1, err := g1AffineDecodeOnCurve(input[i*192:i*192+64])
        if err != nil {
            copy(output, err.Error())
            return -1
        }

        // get g2
        g2, err := g2AffineDecodeOnCurve(input[i*192+64:(i+1)*192])
        if err != nil {
            copy(output, err.Error())
            return -1
        }

        // collect g1, g2 points
        g1Points[i] = *g1
        g2Points[i] = *g2
    }

    isOne, err := bn254.PairingCheck(g1Points, g2Points)
    if err != nil {
        copy(output, err.Error())
        return -1
    }

    if (isOne) {
        // respond with 1 if pairing check was true, leave 0's intact otherwise
        output[31]=0x01
    }

    return 0

}



func g1AffineDecodeOnCurve(input []byte) (*bn254.G1Affine, error) {
    var g1x, g1y fp.Element
    g1x.Unmarshal(input[:32])
    g1y.Unmarshal(input[32:])
    // construct g1affine directly rather than unmarshalling
    g1 := &bn254.G1Affine{X: g1x, Y: g1y}
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

    // gnark bn254 returns two 32 byte points in a packed array
    unsafeG1Ptr := unsafe.Pointer(&g1Point[0])

    // copy unsafe to output[0:64],
    C.memcpy(unsafe.Pointer(uintptr(unsafe.Pointer(output))), unsafeG1Ptr, 64)

    return nil
}

func g2AffineDecodeOnCurve(input []byte) (*bn254.G2Affine, error) {
    var g2 bn254.G2Affine
    g2.X.A0.Unmarshal(input[0:32])
    g2.X.A1.Unmarshal(input[32:64])
    g2.Y.A0.Unmarshal(input[64:96])
    g2.Y.A1.Unmarshal(input[96:128])

    if (!g2.IsOnCurve()) {
        return nil, ErrPointOnCurveCheckFailed
    }
    return &g2, nil;
}

func castOutputBuffer(javaOutputBuf *C.char, outputLen C.int) []byte {
    if outputLen != EIP196PreallocateForG1 {
        return nil
    }
    return (*[EIP196PreallocateForG1]byte)(unsafe.Pointer(javaOutputBuf))[:outputLen:outputLen]
}
func main() {}
