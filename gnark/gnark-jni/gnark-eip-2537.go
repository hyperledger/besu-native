package main

/*
#include <string.h>
*/
import "C"
import (
    "bytes"
	"errors"
	"math/big"
	"reflect"
	"unsafe"
    "github.com/consensys/gnark-crypto/ecc/bls12-381"
    "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

const (
	EIP2537PreallocateForScalar = 32 // scalar int is 32 byte
	EIP2537PreallocateForFp = 64  // G1 points are 48 bytes, left padded with zero for 16 bytes
	EIP2537PreallocateForG1 = EIP2537PreallocateForFp * 2 // G1 points are 48 bytes, left padded with zero for 16 bytes
	EIP2537PreallocateForG2 = EIP2537PreallocateForG1 * 2 // G2 comprise 2 G1 points, left padded with zero for 16 bytes
	EIP2537PreallocateForResultBytes = EIP2537PreallocateForG2 // maximum for G2 point
)

var ErrSubgroupCheckFailed = errors.New("invalid point: subgroup check failed")
var ErrPointOnCurveCheckFailed = errors.New("invalid point: point is not on curve")
var ErrMalformedPointPadding = errors.New("invalid point: point is not left padded with zero")
var ErrMalformedOutputBytes = errors.New("malformed output buffer parameter")

// Predefine a zero slice of length 16
var zeroSlice = make([]byte, 16)

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
//     fmt.Printf("convert input array time: %v\n", time.Since(startTime))

    // generate p0 g1 affine
    p0, err := g1AffineDecodeOnCurve(input[:128])

    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // generate p0 g1 affine
    p1, err := g1AffineDecodeOnCurve(input[128:])

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

//export eip2537blsG1Mul
func eip2537blsG1Mul(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    var inputLen = int(cInputLen)

    output := castOutputBuffer(javaOutputBuf, outputLen)
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

//export eip2537blsG1MultiExp
func eip2537blsG1MultiExp(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    var inputLen = int(cInputLen)
    output := castOutputBuffer(javaOutputBuf, outputLen)

    if inputLen < (EIP2537PreallocateForG1 + EIP2537PreallocateForScalar) {
        copy(output, "invalid input parameters, invalid number of pairs\x00")
        return -1
    }
    if inputLen % (EIP2537PreallocateForG1 + EIP2537PreallocateForScalar) != 0 {
        copy(output, "invalid input parameters, invalid input length for G1 multiplication\x00")
        return -1
    }

    // Convert input C pointers to Go slice
    input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

    var exprCount = inputLen / (EIP2537PreallocateForG1 + EIP2537PreallocateForScalar)

    // get the first scalar mult operation
    p0, err := g1AffineDecodeInSubGroup (input[:128])
    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // Convert byte slice to *big.Int and do the initial scalar multiplication
    scalar := big.NewInt(0)
    scalar.SetBytes(input[128:160])
    result := p0.ScalarMultiplication(p0, scalar)

    for i := 1 ; i < exprCount ; i++ {
        // for each subsequent operation, decode, mul, and add to the result
        p1, err := g1AffineDecodeInSubGroup(input[i*160 : (i*160)+128])
        if err != nil {
            copy(output, err.Error())
            return -1
        }

        scalar = big.NewInt(0)
        scalar.SetBytes(input[(i*160)+128 : (i+1)*160])
        p1.ScalarMultiplication(p1, scalar)
        // add to the result:
        result = result.Add(result, p1)
    }

    // marshal the resulting point and encode directly to the output buffer
    ret := result.Marshal()
    g1AffineEncode(ret, javaOutputBuf)
    return 1
}

//export eip2537blsG2Add
func eip2537blsG2Add(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    var inputLen = int(cInputLen)
    output := castOutputBuffer(javaOutputBuf, outputLen)

    if inputLen != 2 * EIP2537PreallocateForG2 {
        copy(output, "invalid input parameters, invalid input length for G2 addition\x00")
        return -1
    }
    // Convert input C pointers to Go slice
    input := (*[2 *EIP2537PreallocateForG2]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]


    // obtain p0
    p0, err := g2AffineDecodeOnCurve(input[:256])
    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // obtain p1
    p1, err := g2AffineDecodeOnCurve(input[256:])
    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // add p0,p1
    result := p0.Add(p0, p1)
    // marshal the resulting point and encode directly to the output buffer
    ret := result.Marshal()
    g2AffineEncode(ret, javaOutputBuf)

    return 1

}

//export eip2537blsG2Mul
func eip2537blsG2Mul(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    var inputLen = int(cInputLen)
    output := castOutputBuffer(javaOutputBuf, outputLen)

    if inputLen != EIP2537PreallocateForG2 + EIP2537PreallocateForScalar {
        copy(output, "invalid input parameters, invalid input length for G2 multiplication\x00")
        return -1
    }
    // Convert input C pointers to Go slice
    input := (*[2 *EIP2537PreallocateForG2]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]


    // obtain p0
    p0, err := g2AffineDecodeInSubGroup(input[:256])
    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // Convert byte slice to *big.Int
    scalar := big.NewInt(0)
    scalar.SetBytes(input[256:288])

    result := p0.ScalarMultiplication(p0, scalar)

    // marshal the resulting point and encode directly to the output buffer
    ret := result.Marshal()
    g2AffineEncode(ret, javaOutputBuf)
    return 1

}

//export eip2537blsG2MultiExp
func eip2537blsG2MultiExp(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    var inputLen = int(cInputLen)
    output := castOutputBuffer(javaOutputBuf, outputLen)

    if inputLen < (EIP2537PreallocateForG2 + EIP2537PreallocateForScalar) {
        copy(output, "invalid input parameters, invalid number of pairs\x00")
        return -1
    }
    if inputLen % (EIP2537PreallocateForG2 + EIP2537PreallocateForScalar) != 0 {
        copy(output, "invalid input parameters, invalid input length for G2 multiplication\x00")
        return -1
    }

    // Convert input C pointers to Go slice
    input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

    var exprCount = inputLen / (EIP2537PreallocateForG2 + EIP2537PreallocateForScalar)

    // get the first scalar mult operation
    p0, err := g2AffineDecodeInSubGroup (input[:128])
    if err != nil {
        copy(output, err.Error())
        return -1
    }

    // Convert byte slice to *big.Int and do the initial scalar multiplication
    scalar := big.NewInt(0)
    scalar.SetBytes(input[256:288])
    result := p0.ScalarMultiplication(p0, scalar)

    for i := 1 ; i < exprCount ; i++ {
        // for each subsequent operation, decode, mul, and add to the result
        p1, err := g2AffineDecodeInSubGroup(input[i*288 : (i*288)+256])
        if err != nil {
            copy(output, err.Error())
            return -1
        }

        scalar = big.NewInt(0)
        scalar.SetBytes(input[(i*288)+256 : (i+1)*288])
        p1.ScalarMultiplication(p1, scalar)
        // add to the result:
        result = result.Add(result, p1)
    }

    // marshal the resulting point and encode directly to the output buffer
    ret := result.Marshal()
    g2AffineEncode(ret, javaOutputBuf)
    return 1
}

//export eip2537blsPairing
func eip2537blsPairing(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    var inputLen = int(cInputLen)
    output := castOutputBuffer(javaOutputBuf, outputLen)

    if inputLen < (EIP2537PreallocateForG2 + EIP2537PreallocateForG1) {
        copy(output, "invalid input parameters, invalid number of pairs\x00")
        return -1
    }
    if inputLen % (EIP2537PreallocateForG2 + EIP2537PreallocateForG1) != 0 {
        copy(output, "invalid input parameters, invalid input length for pairing\x00")
        return -1
    }

    // Convert input C pointers to Go slice
    input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)
    var pairCount = inputLen / (EIP2537PreallocateForG2 + EIP2537PreallocateForG1)
    g1Points := make([]bls12381.G1Affine, pairCount)
    g2Points := make([]bls12381.G2Affine, pairCount)


    for i := 0 ; i < pairCount ; i++ {

        // get g1
        g1, err := g1AffineDecodeInSubGroup(input[i*384:i*384+128])
        if err != nil {
            copy(output, err.Error())
            return -1
        }

        // get g2
        g2, err := g2AffineDecodeInSubGroup(input[i*384+128:(i+1)*384])
        if err != nil {
            copy(output, err.Error())
            return -1
        }

        // collect g1, g2 points
        g1Points[i] = *g1
        g2Points[i] = *g2
    }

    isOne, err := bls12381.PairingCheck(g1Points, g2Points)
    if err != nil {
        copy(output, err.Error())
        return -1
    }

    if (isOne) {
        // respond with 1 if pairing check was true, leave 0's intact otherwise
        output[31]=0x01
    }

    return 1

}

//export eip2537blsMapFpToG1
func eip2537blsMapFpToG1(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    //TODO: DRY up
    var inputLen = int(cInputLen)
    output := castOutputBuffer(javaOutputBuf, outputLen)

    if inputLen != (EIP2537PreallocateForFp){
        copy(output, "invalid input parameters, invalid input length for Fp to G1 to curve mapping\x00")
        return -1
    }

    // Convert input C pointers to Go slice
    input := (*[EIP2537PreallocateForFp]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

    // TODO: DRY up
    var fp fp.Element
    fp.Unmarshal(input[16:64])

    result := bls12381.MapToG1(fp)
    // marshal the resulting point and encode directly to the output buffer
    ret := result.Marshal()
    g1AffineEncode(ret, javaOutputBuf)
    return 1
}

//export eip2537blsMapFp2ToG2
func eip2537blsMapFp2ToG2(javaInputBuf, javaOutputBuf *C.char, cInputLen, outputLen C.int) C.int {
    //TODO: DRY up
    var inputLen = int(cInputLen)
    output := castOutputBuffer(javaOutputBuf, outputLen)

    if inputLen != (2*EIP2537PreallocateForFp){
        copy(output, "invalid input parameters, invalid input length for Fp2 to G2 to curve mapping\x00")
        return -1
    }

    // Convert input C pointers to Go slice
    input := (*[2*EIP2537PreallocateForFp]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

    var g2 bls12381.G2Affine
    g2.X.A0.Unmarshal(input[16:64])
    g2.X.A1.Unmarshal(input[80:128])

    result := bls12381.MapToG2(g2.X)
    // marshal the resulting point and encode directly to the output buffer
    ret := result.Marshal()
    g2AffineEncode(ret, javaOutputBuf)
    return 1
}


// Function to check if the first 16 bytes of a slice are zero
func isZero(slice []byte) bool {
    return bytes.Equal(slice[:16], zeroSlice)
}

func hasWrongG1Padding(input []byte) bool {
    return !isZero(input[:16]) || !isZero(input[64:80])
}

func hasWrongG2Padding(input []byte) bool {
    return !isZero(input[:16]) || !isZero(input[64:80] )|| !isZero(input[128:144]) || !isZero(input[192:208])
}


func g1AffineDecodeInSubGroup(input []byte) (*bls12381.G1Affine, error) {
    if hasWrongG1Padding(input) {
        return nil, ErrMalformedPointPadding
    }
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
    if hasWrongG1Padding(input) {
        return nil, ErrMalformedPointPadding
    }
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

func g2AffineDecodeInSubGroup(input []byte) (*bls12381.G2Affine, error) {
    if hasWrongG2Padding(input) {
        return nil, ErrMalformedPointPadding
    }

    var g2 bls12381.G2Affine
    g2.X.A0.Unmarshal(input[16:64])
    g2.X.A1.Unmarshal(input[80:128])
    g2.Y.A0.Unmarshal(input[144:192])
    g2.Y.A1.Unmarshal(input[208:256])

    // do explicit subgroup check
    if (!g2.IsInSubGroup()) {
        if (!g2.IsOnCurve()) {
            return nil, ErrPointOnCurveCheckFailed
        }
        return nil, ErrSubgroupCheckFailed
    }
    return &g2, nil;
}

func g2AffineDecodeOnCurve(input []byte) (*bls12381.G2Affine, error) {
    if hasWrongG2Padding(input) {
        return nil, ErrMalformedPointPadding
    }

    var g2 bls12381.G2Affine
    g2.X.A0.Unmarshal(input[16:64])
    g2.X.A1.Unmarshal(input[80:128])
    g2.Y.A0.Unmarshal(input[144:192])
    g2.Y.A1.Unmarshal(input[208:256])

    if (!g2.IsOnCurve()) {
        return nil, ErrPointOnCurveCheckFailed
    }
    return &g2, nil;
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

func g2AffineEncode(g2Point []byte, output *C.char) (error) {
    // Check if point is not nil
    if g2Point == nil {
        return errors.New("point cannot be nil")
    }

    // gnark g2 returns two two-48 byte component points in a packed array,
    // we need to encode these four 64 byte points with prepended zeroes, in a packed array
    g2x1 := unsafe.Pointer(&g2Point[0])
    g2x0 := unsafe.Pointer(&g2Point[48])
    g2y1 := unsafe.Pointer(&g2Point[96])
    g2y0 := unsafe.Pointer(&g2Point[144])

    // java should pass a zero-initialized ByteBuffer, copy x1 to output[16:64],
    C.memcpy(unsafe.Pointer(uintptr(unsafe.Pointer(output))+16), g2x0, 48)

    // Copy x2 to output[80:128]
    C.memcpy(unsafe.Pointer(uintptr(unsafe.Pointer(output))+80), g2x1, 48)

    // Copy y1 to output[144:192]
    C.memcpy(unsafe.Pointer(uintptr(unsafe.Pointer(output))+144), g2y0, 48)

    // Copy y2 to output[208:256]
    C.memcpy(unsafe.Pointer(uintptr(unsafe.Pointer(output))+208), g2y1, 48)

    return nil
}


func castBufferToSlice(buf unsafe.Pointer, length int) []byte {
    var slice []byte
    // Obtain the slice header
    header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
    header.Data = uintptr(buf)   // point directly to the data
    header.Len = length          // set the length of the slice
    header.Cap = length          // set the capacity of the slice

    return slice
}

func castOutputBuffer(javaOutputBuf *C.char, outputLen C.int) []byte {
    if outputLen != EIP2537PreallocateForResultBytes {
        return nil
    }
    return (*[EIP2537PreallocateForResultBytes]byte)(unsafe.Pointer(javaOutputBuf))[:outputLen:outputLen]
}
func main() {}
