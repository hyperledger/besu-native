package main

/*
#include <string.h>
*/
import "C"
import (
	"bytes"
	"errors"
	"math/big"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	EIP2537PreallocateForScalar      = 32                          // scalar int is 32 byte
	EIP2537PreallocateForFp          = 64                          // G1 points are 48 bytes, left padded with zero for 16 bytes
	EIP2537PreallocateForG1          = EIP2537PreallocateForFp * 2 // G1 points are 48 bytes, left padded with zero for 16 bytes
	EIP2537PreallocateForG2          = EIP2537PreallocateForG1 * 2 // G2 comprise 2 G1 points, left padded with zero for 16 bytes
	EIP2537PreallocateForResultBytes = EIP2537PreallocateForG2     // maximum for G2 point
	EIP2537PreallocateForErrorBytes  = 256                         // max error length

)

var ErrSubgroupCheckFailed = errors.New("invalid point: subgroup check failed")
var ErrPointOnCurveCheckFailed = errors.New("invalid point: point is not on curve")
var ErrMalformedPointPadding = errors.New("invalid point: point is not left padded with zero")
var ErrMalformedOutputBytes = errors.New("malformed output buffer parameter")

// Predefine a zero slice of length 16
var zeroSlice = make([]byte, 16)

// bls12381 modulus
var q *fp.Element

func init() {
	q = new(fp.Element).SetBigInt(fp.Modulus())
}

//export eip2537blsG1Add
func eip2537blsG1Add(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	if inputLen != 2*EIP2537PreallocateForG1 {
		copy(errorBuf, "invalid input parameters, invalid input length for G1 addition\x00")
		return 1
	}

	// Convert input C pointers to Go slices
	input := (*[2 * EIP2537PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// generate p0 g1 affine
	p0, err := g1AffineDecodeOnCurve(input[:128])

	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// generate p0 g1 affine
	p1, err := g1AffineDecodeOnCurve(input[128:])

	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Use the Add method to combine points
	result := p0.Add(p0, p1)

	// marshal the resulting point and encode directly to the output buffer
	return nonMontgomeryMarshalG1(result, javaOutputBuf, errorBuf)
}

//export eip2537blsG1Mul
func eip2537blsG1Mul(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	if inputLen != (EIP2537PreallocateForG1 + EIP2537PreallocateForScalar) {
		copy(errorBuf, "invalid input parameters, invalid input length for G1 multiplication\x00")
		return 1
	}

	// Convert input C pointers to Go slice
	input := (*[EIP2537PreallocateForG1 + EIP2537PreallocateForScalar]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// generate p0 g1 affine
	p0, err := g1AffineDecodeInSubGroup(input[:128])

	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Convert byte slice to *big.Int
	scalar := big.NewInt(0)
	scalar.SetBytes(input[128:160])

	// multiply g1 point by scalar
	result := p0.ScalarMultiplication(p0, scalar)

	// marshal the resulting point and encode directly to the output buffer
	return nonMontgomeryMarshalG1(result, javaOutputBuf, errorBuf)
}

//export eip2537blsG1MultiExp
func eip2537blsG1MultiExp(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	if inputLen == 0 {
		copy(errorBuf, "invalid input parameters, invalid number of pairs\x00")
		return 1
	}

	if inputLen%(EIP2537PreallocateForG1+EIP2537PreallocateForScalar) != 0 {
		copy(errorBuf, "invalid input parameters, invalid input length for G1 multiplication\x00")
		return 1
	}

	// Convert input C pointers to Go slice
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

	var exprCount = inputLen / (EIP2537PreallocateForG1 + EIP2537PreallocateForScalar)

	// get the first scalar mult operation
	p0, err := g1AffineDecodeInSubGroup(input[:128])
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Convert byte slice to *big.Int and do the initial scalar multiplication
	scalar := big.NewInt(0)
	scalar.SetBytes(input[128:160])
	result := p0.ScalarMultiplication(p0, scalar)

	for i := 1; i < exprCount; i++ {
		// for each subsequent operation, decode, mul, and add to the result
		p1, err := g1AffineDecodeInSubGroup(input[i*160 : (i*160)+128])
		if err != nil {
			copy(errorBuf, err.Error())
			return 1
		}

		scalar = big.NewInt(0)
		scalar.SetBytes(input[(i*160)+128 : (i+1)*160])
		p1.ScalarMultiplication(p1, scalar)
		// add to the result:
		result = result.Add(result, p1)
	}

	// marshal the resulting point and encode directly to the output buffer
	return nonMontgomeryMarshalG1(result, javaOutputBuf, errorBuf)
}

//export eip2537blsG1MultiExpParallel
func eip2537blsG1MultiExpParallel(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int, nbTasks C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	if inputLen == 0 {
		copy(errorBuf, "invalid input parameters, invalid number of pairs\x00")
		return 1
	}

	if inputLen%(EIP2537PreallocateForG1+EIP2537PreallocateForScalar) != 0 {
		copy(errorBuf, "invalid input parameters, invalid input length for G1 multiplication\x00")
		return 1
	}

	// Convert input C pointers to Go slice
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

	var exprCount = inputLen / (EIP2537PreallocateForG1 + EIP2537PreallocateForScalar)

	g1Points := make([]bls12381.G1Affine, exprCount)
	scalars := make([]fr.Element, exprCount)

	for i := 0; i < exprCount; i++ {
		_, err := g1AffineDecodeInSubGroupVal(&g1Points[i], input[i*160:(i*160)+128])
		if err != nil {
			copy(errorBuf, err.Error())
			return 1
		}

		scalars[i].SetBytes(input[(i*160)+128 : (i+1)*160])
	}

	var affineResult bls12381.G1Affine
	// leave nbTasks unset, allow golang to use available cpu cores as the parallelism limit
	_, err := affineResult.MultiExp(g1Points, scalars, ecc.MultiExpConfig{NbTasks: int(nbTasks)})
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// marshal the resulting point and encode directly to the output buffer
	return nonMontgomeryMarshalG1(&affineResult, javaOutputBuf, errorBuf)
}

//export eip2537blsG2Add
func eip2537blsG2Add(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	if inputLen != 2*EIP2537PreallocateForG2 {
		copy(errorBuf, "invalid input parameters, invalid input length for G2 addition\x00")
		return 1
	}
	// Convert input C pointers to Go slice
	input := (*[2 * EIP2537PreallocateForG2]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// obtain p0
	p0, err := g2AffineDecodeOnCurve(input[:256])
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// obtain p1
	p1, err := g2AffineDecodeOnCurve(input[256:])
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// add p0,p1
	result := p0.Add(p0, p1)
	// marshal the resulting point and encode directly to the output buffer
	return nonMontgomeryMarshalG2(result, javaOutputBuf, errorBuf)
}

//export eip2537blsG2Mul
func eip2537blsG2Mul(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	if inputLen != EIP2537PreallocateForG2+EIP2537PreallocateForScalar {
		copy(errorBuf, "invalid input parameters, invalid input length for G2 multiplication\x00")
		return 1
	}
	// Convert input C pointers to Go slice
	input := (*[2 * EIP2537PreallocateForG2]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// obtain p0
	p0, err := g2AffineDecodeInSubGroup(input[:256])
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Convert byte slice to *big.Int
	scalar := big.NewInt(0)
	scalar.SetBytes(input[256:288])

	result := p0.ScalarMultiplication(p0, scalar)

	// marshal the resulting point and encode directly to the output buffer
	return nonMontgomeryMarshalG2(result, javaOutputBuf, errorBuf)
}

//export eip2537blsG2MultiExp
func eip2537blsG2MultiExp(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	if inputLen == 0 {
		copy(errorBuf, "invalid input parameters, invalid number of pairs\x00")
		return 1
	}

	if inputLen%(EIP2537PreallocateForG2+EIP2537PreallocateForScalar) != 0 {
		copy(errorBuf, "invalid input parameters, invalid input length for G2 multiplication\x00")
		return 1
	}

	// Convert input C pointers to Go slice
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

	var exprCount = inputLen / (EIP2537PreallocateForG2 + EIP2537PreallocateForScalar)

	// get the first scalar mult operation
	p0, err := g2AffineDecodeInSubGroup(input[:128])
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Convert byte slice to *big.Int and do the initial scalar multiplication
	scalar := big.NewInt(0)
	scalar.SetBytes(input[256:288])
	result := p0.ScalarMultiplication(p0, scalar)
	for i := 1; i < exprCount; i++ {
		// for each subsequent operation, decode, mul, and add to the result
		p1, err := g2AffineDecodeInSubGroup(input[i*288 : (i*288)+256])
		if err != nil {
			copy(errorBuf, err.Error())
			return 1
		}

		scalar = big.NewInt(0)
		scalar.SetBytes(input[(i*288)+256 : (i+1)*288])
		p1.ScalarMultiplication(p1, scalar)
		// add to the result:
		result = result.Add(result, p1)
	}

	// marshal the resulting point and encode directly to the output buffer
	return nonMontgomeryMarshalG2(result, javaOutputBuf, errorBuf)
}

//export eip2537blsG2MultiExpParallel
func eip2537blsG2MultiExpParallel(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int, nbTasks C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	if inputLen == 0 {
		copy(errorBuf, "invalid input parameters, invalid number of pairs\x00")
		return 1
	}

	if inputLen%(EIP2537PreallocateForG2+EIP2537PreallocateForScalar) != 0 {
		copy(errorBuf, "invalid input parameters, invalid input length for G2 multiplication\x00")
		return 1
	}

	// Convert input C pointers to Go slice
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

	var exprCount = inputLen / (EIP2537PreallocateForG2 + EIP2537PreallocateForScalar)

	g2Points := make([]bls12381.G2Affine, exprCount)
	scalars := make([]fr.Element, exprCount)

	for i := 0; i < exprCount; i++ {
		_, err := g2AffineDecodeInSubGroupVal(&g2Points[i], input[i*288:(i*288)+256])
		if err != nil {
			copy(errorBuf, err.Error())
			return 1
		}

		scalars[i].SetBytes(input[(i*288)+256 : (i+1)*288])
	}

	var affineResult bls12381.G2Affine
	// leave nbTasks unset, allow golang to use available cpu cores as the parallelism limit
	_, err := affineResult.MultiExp(g2Points, scalars, ecc.MultiExpConfig{NbTasks: int(nbTasks)})
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// marshal the resulting point and encode directly to the output buffer
	return nonMontgomeryMarshalG2(&affineResult, javaOutputBuf, errorBuf)
}

//export eip2537blsPairing
func eip2537blsPairing(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	outputLen := int(cOutputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Convert output C pointers to Go slices
	output := castBuffer(javaOutputBuf, outputLen)

	if inputLen < (EIP2537PreallocateForG2 + EIP2537PreallocateForG1) {
		copy(errorBuf, "invalid input parameters, invalid number of pairs\x00")
		return 1
	}
	if inputLen%(EIP2537PreallocateForG2+EIP2537PreallocateForG1) != 0 {
		copy(errorBuf, "invalid input parameters, invalid input length for pairing\x00")
		return 1
	}

	// Convert input C pointers to Go slice
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)
	var pairCount = inputLen / (EIP2537PreallocateForG2 + EIP2537PreallocateForG1)
	g1Points := make([]bls12381.G1Affine, pairCount)
	g2Points := make([]bls12381.G2Affine, pairCount)

	for i := 0; i < pairCount; i++ {

		// get g1
		g1, err := g1AffineDecodeInSubGroup(input[i*384 : i*384+128])
		if err != nil {
			copy(errorBuf, err.Error())
			return 1
		}

		// get g2
		g2, err := g2AffineDecodeInSubGroup(input[i*384+128 : (i+1)*384])
		if err != nil {
			copy(errorBuf, err.Error())
			return 1
		}

		// collect g1, g2 points
		g1Points[i] = *g1
		g2Points[i] = *g2
	}

	isOne, err := bls12381.PairingCheck(g1Points, g2Points)
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	if isOne {
		// respond with 1 if pairing check was true, leave 0's intact otherwise
		output[31] = 0x01
	}

	return 0

}

//export eip2537blsMapFpToG1
func eip2537blsMapFpToG1(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	if inputLen != (EIP2537PreallocateForFp) {
		copy(errorBuf, "invalid input parameters, invalid input length for Fp to G1 to curve mapping\x00")
		return 1
	}

	// Convert input C pointers to Go slice
	input := (*[EIP2537PreallocateForFp]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	if !isZero(input[:16]) {
		copy(errorBuf, ErrMalformedPointPadding.Error())
		return 1
	}

	var fp fp.Element
	err := fp.SetBytesCanonical(input[16:64])

	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	result := bls12381.MapToG1(fp)
	// marshal the resulting point and encode directly to the output buffer
	return nonMontgomeryMarshalG1(&result, javaOutputBuf, errorBuf)
}

//export eip2537blsMapFp2ToG2
func eip2537blsMapFp2ToG2(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cOutputLen)

	// Convert error C pointers to Go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	if inputLen != (2 * EIP2537PreallocateForFp) {
		copy(errorBuf, "invalid input parameters, invalid input length for Fp2 to G2 to curve mapping\x00")
		return 1
	}

	// Convert input C pointers to Go slice
	input := (*[2 * EIP2537PreallocateForFp]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	if hasWrongG1Padding(input) {
		copy(errorBuf, ErrMalformedPointPadding.Error())
		return 1
	}

	var g2 bls12381.G2Affine

	err := g2.X.A0.SetBytesCanonical(input[16:64])
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}
	err = g2.X.A1.SetBytesCanonical(input[80:128])
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	result := bls12381.MapToG2(g2.X)
	// marshal the resulting point and encode directly to the output buffer
	return nonMontgomeryMarshalG2(&result, javaOutputBuf, errorBuf)
}

// Function to check if the first 16 bytes of a slice are zero
func isZero(slice []byte) bool {
	return bytes.Equal(slice[:16], zeroSlice)
}

func hasWrongG1Padding(input []byte) bool {
	return !isZero(input[:16]) || !isZero(input[64:80])
}

func hasWrongG2Padding(input []byte) bool {
	return !isZero(input[:16]) || !isZero(input[64:80]) || !isZero(input[128:144]) || !isZero(input[192:208])
}
func g1AffineDecodeInSubGroup(input []byte) (*bls12381.G1Affine, error) {
	var g1 bls12381.G1Affine
	return g1AffineDecodeInSubGroupVal(&g1, input)
}

func g1AffineDecodeInSubGroupVal(g1 *bls12381.G1Affine, input []byte) (*bls12381.G1Affine, error) {
	if hasWrongG1Padding(input) {
		return nil, ErrMalformedPointPadding
	}
	err := g1.X.SetBytesCanonical(input[16:64])
	if err != nil {
		return nil, err
	}
	err = g1.Y.SetBytesCanonical(input[80:128])
	if err != nil {
		return nil, err
	}

	// do explicit on-curve check first
	if !g1.IsOnCurve() {
		return nil, ErrPointOnCurveCheckFailed
	}

	// do explicit subgroup check
	if !g1.IsInSubGroup() {
		return nil, ErrSubgroupCheckFailed
	}
	return g1, nil
}

func g1AffineDecodeOnCurve(input []byte) (*bls12381.G1Affine, error) {
	if hasWrongG1Padding(input) {
		return nil, ErrMalformedPointPadding
	}
	var g1x, g1y fp.Element
	err := g1x.SetBytesCanonical(input[16:64])
	if err != nil {
		return nil, err
	}
	err = g1y.SetBytesCanonical(input[80:128])
	if err != nil {
		return nil, err
	}

	// construct g1affine directly rather than unmarshalling
	g1 := &bls12381.G1Affine{X: g1x, Y: g1y}
	// do not do subgroup checks, only point-on-curve.  G1Add is spec'd this way for 2537
	if !g1.IsOnCurve() {
		return nil, ErrPointOnCurveCheckFailed
	}

	return g1, nil
}

func g2AffineDecodeInSubGroup(input []byte) (*bls12381.G2Affine, error) {
	var g2 bls12381.G2Affine
	return g2AffineDecodeInSubGroupVal(&g2, input)
}

func g2AffineDecodeInSubGroupVal(g2 *bls12381.G2Affine, input []byte) (*bls12381.G2Affine, error) {
	if hasWrongG2Padding(input) {
		return nil, ErrMalformedPointPadding
	}

	err := g2.X.A0.SetBytesCanonical(input[16:64])
	if err != nil {
		return nil, err
	}
	err = g2.X.A1.SetBytesCanonical(input[80:128])
	if err != nil {
		return nil, err
	}
	err = g2.Y.A0.SetBytesCanonical(input[144:192])
	if err != nil {
		return nil, err
	}
	err = g2.Y.A1.SetBytesCanonical(input[208:256])
	if err != nil {
		return nil, err
	}
	if !g2.IsOnCurve() {
		return nil, ErrPointOnCurveCheckFailed
	}

	// do explicit subgroup check
	if !g2.IsInSubGroup() {
		return nil, ErrSubgroupCheckFailed
	}
	return g2, nil
}

func g2AffineDecodeOnCurve(input []byte) (*bls12381.G2Affine, error) {
	if hasWrongG2Padding(input) {
		return nil, ErrMalformedPointPadding
	}

	var g2 bls12381.G2Affine
	err := g2.X.A0.SetBytesCanonical(input[16:64])
	if err != nil {
		return nil, err
	}
	err = g2.X.A1.SetBytesCanonical(input[80:128])
	if err != nil {
		return nil, err
	}
	err = g2.Y.A0.SetBytesCanonical(input[144:192])
	if err != nil {
		return nil, err
	}
	err = g2.Y.A1.SetBytesCanonical(input[208:256])
	if err != nil {
		return nil, err
	}

	if !g2.IsOnCurve() {
		return nil, ErrPointOnCurveCheckFailed
	}
	return &g2, nil
}

func castBufferToSlice(buf unsafe.Pointer, length int) []byte {
	return unsafe.Slice((*byte)(buf), length)
}

func castBuffer(javaOutputBuf *C.char, length int) []byte {
	bufSize := length
	if bufSize < EIP2537PreallocateForResultBytes {
		bufSize = EIP2537PreallocateForResultBytes
	}
	return (*[EIP2537PreallocateForResultBytes]byte)(unsafe.Pointer(javaOutputBuf))[:bufSize:bufSize]
}

func nonMontgomeryMarshal(xVal, yVal *fp.Element, output *C.char, outputOffset int) error {
	// Convert g1.X and g1.Y to big.Int using the BigInt method
	var x big.Int
	xVal.BigInt(&x)
	xBytes := x.Bytes()
	xLen := len(xBytes)

	if xLen > 0 {
		// Copy x to output at offset (64 - xLen)
		C.memcpy(unsafe.Pointer(uintptr(unsafe.Pointer(output))+uintptr(outputOffset+64-xLen)), unsafe.Pointer(&xBytes[0]), C.size_t(xLen))
	}

	var y big.Int
	yVal.BigInt(&y)
	yBytes := y.Bytes()
	yLen := len(yBytes)

	if yLen > 0 {
		// Copy y to output at offset (128 - yLen)
		C.memcpy(unsafe.Pointer(uintptr(unsafe.Pointer(output))+uintptr(outputOffset+128-yLen)), unsafe.Pointer(&yBytes[0]), C.size_t(yLen))
	}
	return nil
}

func nonMontgomeryMarshalG1(g1 *bls12381.G1Affine, output *C.char, errorBuf []byte) C.int {
	if nil == nonMontgomeryMarshal(&g1.X, &g1.Y, output, 0) {
		return 0
	} else {
		copy(errorBuf, ErrMalformedOutputBytes.Error())
		return 1
	}
}

func nonMontgomeryMarshalG2(g2 *bls12381.G2Affine, output *C.char, errorBuf []byte) C.int {
	if nil == nonMontgomeryMarshal(&g2.X.A0, &g2.X.A1, output, 0) &&
		nil == nonMontgomeryMarshal(&g2.Y.A0, &g2.Y.A1, output, 128) {
		return 0
	} else {
		copy(errorBuf, ErrMalformedOutputBytes.Error())
		return 1
	}
}

func main() {}
