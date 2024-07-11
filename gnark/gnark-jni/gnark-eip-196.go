package main

/*
#include <string.h>
*/
import "C"
import (
    cryptorand "crypto/rand"
    "encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"unsafe"
    "github.com/consensys/gnark-crypto/ecc/bn254"
    "github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

var ErrMalformedPointEIP196 = errors.New("invalid point encoding")
var ErrInvalidInputPairingLengthEIP196 = errors.New("invalid input parameters, invalid input length for pairing")
var ErrPointNotInFieldEIP196 = errors.New("point not in field")
var ErrPointOnCurveCheckFailedEIP196 = errors.New("point is not on curve")

const (
    EIP196PreallocateForResult = 128
    EIP196PreallocateForError = 256
	EIP196PreallocateForScalar = 32 // scalar int is 32 byte
	EIP196PreallocateForFp = 32  // field elements are 32 bytes
	EIP196PreallocateForG1 = EIP196PreallocateForFp * 2 // G1 points are encoded as 2 concatenated field elements
	EIP196PreallocateForG2 = EIP196PreallocateForG1 * 2 // G2 points are encoded as 2 concatenated G1 points
)


// bn254Modulus is the value 21888242871839275222246405745257275088696311157297823662689037894645226208583
var bn254Modulus = new(big.Int).SetBytes([]byte{
	0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
	0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
	0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
	0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
})

// Predefine a zero slice of length 16
var zeroEIP196Slice = make([]byte, 16)

//export eip196altbn128G1Add
func eip196altbn128G1Add(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen C.int, cOutputLen, cErrorLen *C.int) C.int {
    inputLen := int(cInputLen)
    errorLen := (*int)(unsafe.Pointer(cErrorLen))
    outputLen := (*int)(unsafe.Pointer(cOutputLen))

    // Convert error C pointers to Go slices
    errorBuf := castErrorBufferEIP196(javaErrorBuf, errorLen)

    if (inputLen > 2*EIP196PreallocateForG1) {
        // trunc if input too long
        inputLen = 2*EIP196PreallocateForG1
    }

    // Convert input C pointers to Go slices
    input := (*[2*EIP196PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

    if (inputLen == 0) {
        *outputLen = 0
        return 0
    }

    // generate p0 g1 affine
    p0, err := safeUnmarshalEIP196(input, 0)

    if err != nil {
        dryError(err, errorBuf, outputLen, errorLen)
        return 1
    }

    if inputLen < 2*EIP196PreallocateForG1 {
        // if incomplete input is all zero, return p0
        if isAllZeroEIP196(input, 64) {
            ret := p0.Marshal()
            g1AffineEncode(ret, javaOutputBuf)
            *outputLen = EIP196PreallocateForG1
            return 0;
        }
    }
    // generate p1 g1 affine
    p1, err := safeUnmarshalEIP196(input, 64)

    if err != nil {
        dryError(err, errorBuf, outputLen, errorLen)
        return 1
    }

    // Use the Add method to combine points
    result := p0.Add(p0, p1)

    // marshal the resulting point and encode directly to the output buffer
    ret := result.Marshal()
    g1AffineEncode(ret, javaOutputBuf)
    *outputLen = EIP196PreallocateForG1
    return 0

}

//export eip196altbn128G1Mul
func eip196altbn128G1Mul(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen C.int, cOutputLen, cErrorLen *C.int) C.int {
    inputLen := int(cInputLen)
    errorLen := (*int)(unsafe.Pointer(cErrorLen))
    outputLen := (*int)(unsafe.Pointer(cOutputLen))

    // Convert error C pointers to Go slices
    errorBuf := castErrorBufferEIP196(javaErrorBuf, errorLen)

    if inputLen < EIP196PreallocateForG1 {
        // if we do not have complete input, return 0
        *outputLen = 0
        return 0
    }

    if (inputLen > EIP196PreallocateForG1 + EIP196PreallocateForScalar) {
      // trunc if input too long
      inputLen = EIP196PreallocateForG1 + EIP196PreallocateForScalar
    }

    // Convert input C pointers to Go slice
    input := (*[EIP196PreallocateForG1 + EIP196PreallocateForScalar]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

    // generate p0 g1 affine
    p0, err := safeUnmarshalEIP196(input, 0)

    if err != nil {
        dryError(err, errorBuf, outputLen, errorLen)
        return 1
    }

    // Convert byte slice to *big.Int
    scalarBytes := input[64:]
    if (96 > int(cInputLen)) {
      // if the input is truncated, copy the bytes to the high order portion of the scalar
      scalarBytes = make([]byte, 32)
      copy(scalarBytes[:], input[64:int(cInputLen)])
    }

    scalar := big.NewInt(0)
    scalar.SetBytes(scalarBytes[:])

    // multiply g1 point by scalar
    result := p0.ScalarMultiplication(p0, scalar)

    // marshal the resulting point and encode directly to the output buffer
    ret := result.Marshal()
    g1AffineEncode(ret, javaOutputBuf)
    *outputLen = EIP196PreallocateForG1
    return 0
}

//export eip196altbn128Pairing
func eip196altbn128Pairing(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen C.int, cOutputLen, cErrorLen *C.int) C.int {
    inputLen := int(cInputLen)
    errorLen := (*int)(unsafe.Pointer(cErrorLen))
    outputLen := (*int)(unsafe.Pointer(cOutputLen))

    // Convert error C pointers to Go slices
    output := castBufferEIP196(javaOutputBuf, outputLen)

    // Convert error C pointers to Go slices
    errorBuf := castErrorBufferEIP196(javaErrorBuf, errorLen)

    *outputLen = 32

    if inputLen == 0 {
        output[31]=0x01
        return 0
    }

    if inputLen % (EIP196PreallocateForG2 + EIP196PreallocateForG1) != 0 {
        dryError(ErrInvalidInputPairingLengthEIP196, errorBuf, outputLen, errorLen)
        return 1
    }

    // Convert input C pointers to Go slice
    input := castBufferToSliceEIP196(unsafe.Pointer(javaInputBuf), inputLen)

    var pairCount = inputLen / (EIP196PreallocateForG2 + EIP196PreallocateForG1)
    g1Points := make([]bn254.G1Affine, pairCount)
    g2Points := make([]bn254.G2Affine, pairCount)


    for i := 0 ; i < pairCount ; i++ {

        // g1 x and y are the first 64 bytes of each 192 byte pair
        var g1 bn254.G1Affine
        err := g1.Unmarshal(input[i*192:i*192+64])

        if err != nil {
            dryError(err, errorBuf, outputLen, errorLen)
            return 1
        }

        // g2 points are latter 128 bytes of each 192 byte pair
        var g2 bn254.G2Affine
        err = g2.Unmarshal(input[i*192+64:(i+1)*192])

        if err != nil {
            dryError(err, errorBuf, outputLen, errorLen)
            return 1
        }

        // collect g1, g2 points
        g1Points[i] = g1
        g2Points[i] = g2
    }

    isOne, err := bn254.PairingCheck(g1Points, g2Points)
    if err != nil {
        dryError(err, errorBuf, outputLen, errorLen)
        return -1
    }

    if (isOne) {
        // respond with 1 if pairing check was true, leave 0's intact otherwise
        output[31]=0x01
    }
    return 0

}

func g1AffineEncode(g1Point []byte, output *C.char) (error) {
    // Check if point is not nil
    if g1Point == nil || len(g1Point) != 64 {
        return errors.New("point cannot be nil")
    }

    // gnark bn254 returns two 32 byte points in a packed array
    unsafeG1Ptr := unsafe.Pointer(&g1Point[0])

    // copy unsafe to output[0:64],
    C.memcpy(unsafe.Pointer(uintptr(unsafe.Pointer(output))), unsafeG1Ptr, 64)

    return nil
}

func safeUnmarshalEIP196(input []byte, offset int) (*bn254.G1Affine, error) {
    var g1 bn254.G1Affine

    if (len(input) - offset < 64) {
        return nil, ErrMalformedPointEIP196
    }

    if !checkInFieldEIP196(input[offset: offset + 32]) {
        return nil, ErrPointNotInFieldEIP196
    }

    err := g1.X.SetBytesCanonical(input[offset:offset + 32])

    if (err == nil) {

        if !checkInFieldEIP196(input[offset + 32: offset + 64]) {
            return nil, ErrPointNotInFieldEIP196
        }
        err := g1.Y.SetBytesCanonical(input[offset + 32:offset + 64])
        if (err == nil) {
            if (!g1.IsOnCurve()) {
                return nil, ErrPointOnCurveCheckFailedEIP196
            }
            return &g1, nil
        }
    }


    return nil, err
}

// checkInField checks that an element is in the field, not-in-field will normally
// be caught during unmarshal, but here in case of no-op calls of a single parameter
func checkInFieldEIP196(data []byte) bool {

	// Convert the byte slice to a big.Int
	elem := new(big.Int).SetBytes(data)

	// Compare the value to the bn254Modulus
	return bn254Modulus.Cmp(elem) == 1
}

// isAllZero checks if all elements in the byte slice are zero
func isAllZeroEIP196(data []byte, offset int) bool {
    if len(data) > 64 {
        slice := data [offset:]
        for _, b := range slice {
            if b != 0 {
                return false
            }
        }
    }
    return true
}

func dryError(err error, errorBuf []byte, outputLen, errorLen *int) {
    errStr := "invalid input parameters, " + err.Error();
    copy(errorBuf, errStr)
    *outputLen = 0
    *errorLen = len(errStr)
}

func castBufferToSliceEIP196(buf unsafe.Pointer, length int) []byte {
    var slice []byte
    // Obtain the slice header
    header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
    header.Data = uintptr(buf)   // point directly to the data
    header.Len = length          // set the length of the slice
    header.Cap = length          // set the capacity of the slice

    return slice
}

func castBufferEIP196(javaOutputBuf *C.char, length *int) []byte {
    bufSize := *length
    if bufSize != EIP196PreallocateForResult {
      bufSize = EIP196PreallocateForResult
    }
    return (*[EIP196PreallocateForResult]byte)(unsafe.Pointer(javaOutputBuf))[:bufSize:bufSize]
}

func castErrorBufferEIP196(javaOutputBuf *C.char, length *int) []byte {
    bufSize := *length
    if bufSize != EIP196PreallocateForError {
      bufSize = EIP196PreallocateForError
    }
    return (*[EIP196PreallocateForError]byte)(unsafe.Pointer(javaOutputBuf))[:bufSize:bufSize]
}

// generate g1Add test data suitable for unit test input csv
func generateTestDataForAdd() {
    // generate a point from a field element

    for i := 0 ; i < 100; i++ {
        a := fp.NewElement(rand.Uint64())
        b := fp.NewElement(rand.Uint64())
        g := bn254.MapToG1(a)
        gg := bn254.MapToG1(b)
        fmt.Printf("%032x%032x",
            g.Marshal(),
            gg.Marshal())
        res := g.Add(&g, &gg)
        fmt.Printf(",%032x,500,\n", res.Marshal())
    }
}

// generate g1Mul test data suitable for unit test input csv
func generateTestDataForMul() {
    // generate test data
    //var p, res1, res2 bn254.G1Jac
    var a = fp.NewElement(0)

    for i := 0 ; i < 100 ; i++ {
        a.SetRandom()
        randScalar, _ := GenerateRandomUint256()

        g := bn254.MapToG1(a)
        fmt.Printf("%032x%s",
          g.Marshal(),
          Uint256ToStringBigEndian(randScalar))

        res := g.ScalarMultiplication(&g, randScalar)
        fmt.Printf(",%032x,40000,\n",
          res.Marshal())
    }
}

// GenerateRandomUint256 generates a random 32-byte unsigned number.
func GenerateRandomUint256() (*big.Int, error) {
	bytes := make([]byte, 32)
	_, err := cryptorand.Read(bytes)
	if err != nil {
		return nil, err
	}
	number := new(big.Int).SetBytes(bytes)
	return number, nil
}

// Uint256ToStringBigEndian serializes a 32-byte unsigned number to a string in big-endian format.
func Uint256ToStringBigEndian(number *big.Int) string {
	bytes := number.FillBytes(make([]byte, 32))
	return hex.EncodeToString(bytes)
}

func main() {
}
