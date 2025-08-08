/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
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

var (
	ErrSubgroupCheckFailed     = errors.New("invalid point: subgroup check failed")
	ErrPointOnCurveCheckFailed = errors.New("invalid point: point is not on curve")
	ErrMalformedPointPadding   = errors.New("invalid point: point is not left padded with zero")
	ErrMalformedOutputBytes    = errors.New("malformed output buffer parameter")
)

// Predefine a zero slice of length 16
var zeroSlice = make([]byte, 16)

// bls12381 modulus
var q *fp.Element

func init() {
	q = new(fp.Element).SetBigInt(fp.Modulus())
}

/*

eip2537blsG1Add adds two G1 points together and returns a G1 Point.

- Input:
	- javaInputBuf: Pointer to a buffer containing two G1 points
	- javaOutputBuf: Pointer to a buffer where the resulting G1 point will be written
	- javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
	- cInputLen: Length of the input buffer in bytes
	- cOutputLen: Length of the output buffer in bytes
	- cErrorLen: Length of the error buffer in bytes
- Returns:
	- zero is returned if successful, result is written to javaOutputBuf
	- one is returned if there is an error, error message is written to javaErrorBuf
- Cryptography:
	- The field elements that comprise the G1 input points must be checked to be canonical.
	- Check that both G1 input points are on the curve
	- Do not check that input points are in the correct subgroup (See EIP-2537)
- JNI:
	- javaInputBuf must be at least 2*EIP2537PreallocateForG1 bytes (two G1 points)
	- javaOutputBuf must be at least EIP2537PreallocateForG1 bytes to safely store the result
	- javaOutputBuf must be zero initialized

*/
//export eip2537blsG1Add
func eip2537blsG1Add(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error buffer into a Go slice
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Convert C pointer to input buffer into a Go slice
	if inputLen != 2*EIP2537PreallocateForG1 {
		copy(errorBuf, "invalid input parameters, invalid input length for G1 addition\x00")
		return 1
	}
	input := (*[2 * EIP2537PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// Compute G1 Addition
	result, err := _blsG1Add(input)
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Store the result of the G1 addition into the output buffer
	nonMontgomeryMarshalG1(result, javaOutputBuf)
	return 0
}

func _blsG1Add(input []byte) (*bls12381.G1Affine, error) {

	// generate p0 g1 affine
	p0, err := g1AffineDecodeOnCurve(input[:128])
	if err != nil {
		return nil, err
	}

	// generate p0 g1 affine
	p1, err := g1AffineDecodeOnCurve(input[128:])
	if err != nil {
		return nil, err
	}

	// Use the Add method to combine points
	result := p0.Add(p0, p1)

	return result, nil
}

/*

eip2537blsG1MultiExp performs multi-scalar multiplication on multiple G1 points in parallel.

- Input:
	- javaInputBuf: Pointer to a buffer containing a series of G1 point and scalar pairs
	- javaOutputBuf: Pointer to a buffer where the resulting G1 point will be written
	- javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
	- cInputLen: Length of the input buffer in bytes
	- cOutputLen: Length of the output buffer in bytes
	- cErrorLen: Length of the error buffer in bytes
	- nbTasks: Number of parallel tasks to use for computation
- Returns:
	- zero is returned if successful, result is written to javaOutputBuf
	- one is returned if there is an error, error message is written to javaErrorBuf
- Cryptography:
	- The field elements that comprise the G1 input points must be checked to be canonical.
	- The scalars are not required to be canonical.
	- Check that all input points are on the curve and in the correct subgroup.
- JNI:
	- javaInputBuf must be at least n*(EIP2537PreallocateForG1 + EIP2537PreallocateForScalar) bytes, where n is the number of point-scalar pairs
	- javaOutputBuf must be at least EIP2537PreallocateForG1 bytes to safely store the result
	- javaOutputBuf must be zero initialized

*/
//export eip2537blsG1MultiExp
func eip2537blsG1MultiExp(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int, nbTasks C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error buffer into a Go slice
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Validate input length and convert C pointer to input buffer into a Go slice
	if inputLen == 0 {
		copy(errorBuf, "invalid input parameters, invalid number of pairs\x00")
		return 1
	}
	if inputLen%(EIP2537PreallocateForG1+EIP2537PreallocateForScalar) != 0 {
		copy(errorBuf, "invalid input parameters, invalid input length for G1 multiplication\x00")
		return 1
	}
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

	// Compute G1 multi-scalar multiplication in parallel
	result, err := _blsG1MultiExp(input, int(nbTasks))
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Store the result of the G1 multi-scalar multiplication into the output buffer
	nonMontgomeryMarshalG1(result, javaOutputBuf)
	return 0
}

func _blsG1MultiExp(input []byte, nbTasks int) (*bls12381.G1Affine, error) {
	var exprCount = len(input) / (EIP2537PreallocateForG1 + EIP2537PreallocateForScalar)

	// Prepare arrays for points and scalars
	g1Points := make([]bls12381.G1Affine, exprCount)
	scalars := make([]fr.Element, exprCount)

	// Decode points and scalars
	for i := 0; i < exprCount; i++ {
		g1, err := g1AffineDecodeInSubGroup(input[i*160 : (i*160)+128])
		if err != nil {
			return nil, err
		}

		g1Points[i].Set(g1)
		scalars[i].SetBytes(input[(i*160)+128 : (i+1)*160])
	}

	// When the size of the multi scalar multiplication(MSM) is 1, this corresponds to
	// a scalar multiplication so we use the simpler scalar multiplication algorithm to
	// compute the MSM instead of using the general MSM algorithm. This is in accordance
	// with EIP-2537.
	//
	// When the MSM is of size 2 -- heuristically it has been shown to be faster than
	// using the general MSM algorithm, so we also special case it.
	if exprCount == 1 {
		var result bls12381.G1Affine

		var bi big.Int

		scalars[0].BigInt(&bi)
		result.ScalarMultiplication(&g1Points[0], &bi)

		return &result, nil
	} else if exprCount == 2 {
		var result bls12381.G1Affine
		var tmp bls12381.G1Affine

		var bi big.Int

		scalars[0].BigInt(&bi)
		tmp.ScalarMultiplication(&g1Points[0], &bi)

		scalars[1].BigInt(&bi)
		result.ScalarMultiplication(&g1Points[1], &bi)

		result.Add(&result, &tmp)

		return &result, nil
	}

	// Perform parallel multi-exponentiation
	var affineResult bls12381.G1Affine
	_, err := affineResult.MultiExp(g1Points, scalars, ecc.MultiExpConfig{NbTasks: nbTasks})
	if err != nil {
		return nil, err
	}

	return &affineResult, nil
}

/*

eip2537blsG2Add adds two G2 points together and returns a G2 Point.

- Input:
	- javaInputBuf: Pointer to a buffer containing two G2 points
	- javaOutputBuf: Pointer to a buffer where the resulting G2 point will be written
	- javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
	- cInputLen: Length of the input buffer in bytes
	- cOutputLen: Length of the output buffer in bytes
	- cErrorLen: Length of the error buffer in bytes
- Returns:
	- zero is returned if successful, result is written to javaOutputBuf
	- one is returned if there is an error, error message is written to javaErrorBuf
- Cryptography:
	- The field elements that comprise the G2 input points must be checked to be canonical.
	- Check that both input points are on the curve
	- Do not check that input points are in the correct subgroup (See EIP-2537)
- JNI:
	- javaInputBuf must be at least 2*EIP2537PreallocateForG2 bytes (two G2 points)
	- javaOutputBuf must be at least EIP2537PreallocateForG2 bytes to safely store the result
	- javaOutputBuf must be zero initialized

*/
//export eip2537blsG2Add
func eip2537blsG2Add(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error buffer into a Go slice
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Validate input length and convert C pointer to input buffer into a Go slice
	if inputLen != 2*EIP2537PreallocateForG2 {
		copy(errorBuf, "invalid input parameters, invalid input length for G2 addition\x00")
		return 1
	}
	input := (*[2 * EIP2537PreallocateForG2]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// Compute G2 Addition
	result, err := _blsG2Add(input)
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Store the result of the G2 addition into the output buffer
	nonMontgomeryMarshalG2(result, javaOutputBuf)
	return 0
}

func _blsG2Add(input []byte) (*bls12381.G2Affine, error) {
	// Decode the first G2 point
	p0, err := g2AffineDecodeOnCurve(input[:256])
	if err != nil {
		return nil, err
	}

	// Decode the second G2 point
	p1, err := g2AffineDecodeOnCurve(input[256:])
	if err != nil {
		return nil, err
	}

	// Add the G2 points
	result := p0.Add(p0, p1)

	return result, nil
}

/*

eip2537blsG2MultiExp performs multi-scalar multiplication on multiple G2 points in parallel.

- Input:
	- javaInputBuf: Pointer to a buffer containing a series of G2 point and scalar pairs
	- javaOutputBuf: Pointer to a buffer where the resulting G2 point will be written
	- javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
	- cInputLen: Length of the input buffer in bytes
	- cOutputLen: Length of the output buffer in bytes
	- cErrorLen: Length of the error buffer in bytes
	- nbTasks: Number of parallel tasks to use for computation.
- Returns:
	- zero is returned if successful, result is written to javaOutputBuf
	- one is returned if there is an error, error message is written to javaErrorBuf
- Cryptography:
	- The field elements that comprise the G2 input points must be checked to be canonical.
	- Check that all input points are on the curve and in the correct subgroup.
- JNI:
	- javaInputBuf must be at least n*(EIP2537PreallocateForG2 + EIP2537PreallocateForScalar) bytes, where n is the number of point-scalar pairs
	- javaOutputBuf must be at least EIP2537PreallocateForG2 bytes to safely store the result
	- javaOutputBuf must be zero initialized

*/
//export eip2537blsG2MultiExp
func eip2537blsG2MultiExp(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int, nbTasks C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error buffer into a Go slice
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Validate input length and convert C pointer to input buffer into a Go slice
	if inputLen == 0 {
		copy(errorBuf, "invalid input parameters, invalid number of pairs\x00")
		return 1
	}
	if inputLen%(EIP2537PreallocateForG2+EIP2537PreallocateForScalar) != 0 {
		copy(errorBuf, "invalid input parameters, invalid input length for G2 multiplication\x00")
		return 1
	}
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

	// Compute G2 multi-scalar multiplication in parallel
	result, err := _blsG2MultiExp(input, int(nbTasks))
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Store the result of the G2 multi-scalar multiplication into the output buffer
	nonMontgomeryMarshalG2(result, javaOutputBuf)
	return 0
}

func _blsG2MultiExp(input []byte, nbTasks int) (*bls12381.G2Affine, error) {
	var exprCount = len(input) / (EIP2537PreallocateForG2 + EIP2537PreallocateForScalar)

	// Prepare arrays for points and scalars
	g2Points := make([]bls12381.G2Affine, exprCount)
	scalars := make([]fr.Element, exprCount)

	// Decode points and scalars
	for i := 0; i < exprCount; i++ {
		g2Point, err := g2AffineDecodeInSubGroup(input[i*288 : (i*288)+256])
		if err != nil {
			return nil, err
		}

		g2Points[i].Set(g2Point)
		scalars[i].SetBytes(input[(i*288)+256 : (i+1)*288])
	}

	// When the size of the multi scalar multiplication(MSM) is 1, this corresponds to
	// a scalar multiplication so we use the simpler scalar multiplication algorithm to
	// compute the MSM instead of using the general MSM algorithm. This is in accordance
	// with EIP-2537.
	//
	// When the MSM is of size 2 -- heuristically it has been shown to be faster than
	// using the general MSM algorithm, so we also special case it.
	if exprCount == 1 {
		var result bls12381.G2Affine

		var bi big.Int

		scalars[0].BigInt(&bi)
		result.ScalarMultiplication(&g2Points[0], &bi)

		return &result, nil
	} else if exprCount == 2 {
		var result bls12381.G2Affine
		var tmp bls12381.G2Affine

		var bi big.Int

		scalars[0].BigInt(&bi)
		tmp.ScalarMultiplication(&g2Points[0], &bi)

		scalars[1].BigInt(&bi)
		result.ScalarMultiplication(&g2Points[1], &bi)

		result.Add(&result, &tmp)

		return &result, nil
	}

	// Perform parallel multi-exponentiation
	var affineResult bls12381.G2Affine
	_, err := affineResult.MultiExp(g2Points, scalars, ecc.MultiExpConfig{NbTasks: nbTasks})
	if err != nil {
		return nil, err
	}

	return &affineResult, nil
}

/*

eip2537blsPairing performs a pairing check on a collection of G1 and G2 point pairs.

- Input:
	- javaInputBuf: Pointer to a buffer containing a series of G1 and G2 point pairs
	- javaOutputBuf: Pointer to a buffer where the result (32-byte value) will be written
	- javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
	- cInputLen: Length of the input buffer in bytes
	- cOutputLen: Length of the output buffer in bytes
	- cErrorLen: Length of the error buffer in bytes
- Returns:
	- zero is returned if successful, javaOutputBuf contains a 32-byte value: 0x01 if pairing check succeeded, 0x00 otherwise
	- one is returned if there is an error, error message is written to javaErrorBuf
- Cryptography:
	- The field elements that comprise the input points must be checked to be canonical.
	- Check that all input points are on the curve and in the correct subgroup.
- JNI:
	- javaInputBuf must be at least n*(EIP2537PreallocateForG1 + EIP2537PreallocateForG2) bytes, where n is the number of G1-G2 point pairs
	- javaOutputBuf must be at least 32 bytes to safely store the result (0x01 for success, 0x00 otherwise)
	- javaOutputBuf must be zero initialized

*/
//export eip2537blsPairing
func eip2537blsPairing(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	outputLen := int(cOutputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error and output buffers into go slices
	errorBuf := castBuffer(javaErrorBuf, errorLen)
	output := castBuffer(javaOutputBuf, outputLen)

	// Validate input length and convert C pointer to input buffer into a Go slice
	if inputLen < (EIP2537PreallocateForG2 + EIP2537PreallocateForG1) {
		copy(errorBuf, "invalid input parameters, invalid number of pairs\x00")
		return 1
	}
	if inputLen%(EIP2537PreallocateForG2+EIP2537PreallocateForG1) != 0 {
		copy(errorBuf, "invalid input parameters, invalid input length for pairing\x00")
		return 1
	}
	input := castBufferToSlice(unsafe.Pointer(javaInputBuf), inputLen)

	// Perform pairing check
	isOne, err := _blsPairing(input)
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Store the result of the pairing check into the output buffer
	if isOne {
		// respond with 1 if pairing check was true, leave 0's intact otherwise
		output[31] = 0x01
	}

	return 0
}

func _blsPairing(input []byte) (bool, error) {
	var pairCount = len(input) / (EIP2537PreallocateForG2 + EIP2537PreallocateForG1)

	// Prepare arrays for G1 and G2 points
	g1Points := make([]bls12381.G1Affine, pairCount)
	g2Points := make([]bls12381.G2Affine, pairCount)

	// Decode G1 and G2 points
	for i := 0; i < pairCount; i++ {
		// Decode G1 point
		g1, err := g1AffineDecodeInSubGroup(input[i*384 : i*384+128])
		if err != nil {
			return false, err
		}

		// Decode G2 point
		g2, err := g2AffineDecodeInSubGroup(input[i*384+128 : (i+1)*384])
		if err != nil {
			return false, err
		}

		// Store decoded points
		g1Points[i] = *g1
		g2Points[i] = *g2
	}

	// Perform pairing check
	isOne, err := bls12381.PairingCheck(g1Points, g2Points)
	if err != nil {
		return false, err
	}

	return isOne, nil

}

/*

eip2537blsMapFpToG1 maps a field element to a point on the G1 curve.

- Input:
	- javaInputBuf: Pointer to a buffer containing one Fp field element
	- javaOutputBuf: Pointer to a buffer where the resulting G1 point will be written
	- javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
	- cInputLen: Length of the input buffer in bytes
	- cOutputLen: Length of the output buffer in bytes
	- cErrorLen: Length of the error buffer in bytes
- Returns:
	- zero is returned if successful, result is written to javaOutputBuf
	- one is returned if there is an error, error message is written to javaErrorBuf
- Cryptography:
	- The input field element must be checked to be canonical.
	- The resulting point is guaranteed to be on the curve and in the correct subgroup.
- JNI:
	- javaInputBuf must be at least EIP2537PreallocateForFp bytes to store the input field element
	- javaOutputBuf must be at least EIP2537PreallocateForG1 bytes to safely store the result
	- javaOutputBuf must be zero initialized

*/
//export eip2537blsMapFpToG1
func eip2537blsMapFpToG1(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error buffer into a Go slice
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Validate input length and convert C pointer to input buffer into a Go slice
	if inputLen != (EIP2537PreallocateForFp) {
		copy(errorBuf, "invalid input parameters, invalid input length for Fp to G1 to curve mapping\x00")
		return 1
	}
	input := (*[EIP2537PreallocateForFp]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// Map Fp field element to a G1 point
	result, err := _blsMapFpToG1(input)
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Store the result of the mapping into the output buffer
	nonMontgomeryMarshalG1(result, javaOutputBuf)
	return 0
}

func _blsMapFpToG1(input []byte) (*bls12381.G1Affine, error) {
	// Check that the input has correct padding
	if !isZero(input[:16]) {
		return nil, ErrMalformedPointPadding
	}

	// Decode the Fp field element
	var fp fp.Element
	err := fp.SetBytesCanonical(input[16:64])
	if err != nil {
		return nil, err
	}

	// Map the field element to a G1 point
	result := bls12381.MapToG1(fp)

	return &result, nil
}

/*

eip2537blsMapFp2ToG2 maps a field element in the quadratic extension field Fp^2 to a point on the G2 curve.

- Input:
	- javaInputBuf: Pointer to a buffer containing one Fp^2 field element (two Fp elements)
	- javaOutputBuf: Pointer to a buffer where the resulting G2 point will be written
	- javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
	- cInputLen: Length of the input buffer in bytes
	- cOutputLen: Length of the output buffer in bytes
	- cErrorLen: Length of the error buffer in bytes
- Returns:
	- zero is returned if successful, result is written to javaOutputBuf
	- one is returned if there is an error, error message is written to javaErrorBuf
- Cryptography:
	- The input field elements must be checked to be canonical.
	- The resulting point is guaranteed to be on the curve and in the correct subgroup.
- JNI:
	- javaInputBuf must be at least 2*EIP2537PreallocateForFp bytes to store the input Fp^2 field element (two Fp elements)
	- javaOutputBuf must be at least EIP2537PreallocateForG2 bytes to safely store the result
	- javaOutputBuf must be zero initialized

*/
//export eip2537blsMapFp2ToG2
func eip2537blsMapFp2ToG2(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen, cOutputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error buffer into a Go slice
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Validate input length and convert C pointer to input buffer into a Go slice
	if inputLen != (2 * EIP2537PreallocateForFp) {
		copy(errorBuf, "invalid input parameters, invalid input length for Fp2 to G2 to curve mapping\x00")
		return 1
	}
	input := (*[2 * EIP2537PreallocateForFp]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// Map Fp2 field element to a G2 point
	result, err := _blsMapFp2ToG2(input)
	if err != nil {
		copy(errorBuf, err.Error())
		return 1
	}

	// Store the result of the mapping into the output buffer
	nonMontgomeryMarshalG2(result, javaOutputBuf)
	return 0
}

func _blsMapFp2ToG2(input []byte) (*bls12381.G2Affine, error) {
	// Check that the input has correct padding
	if hasWrongG1Padding(input) {
		return nil, ErrMalformedPointPadding
	}

	// Decode the Fp2 field element
	var g2 bls12381.G2Affine
	err := g2.X.A0.SetBytesCanonical(input[16:64])
	if err != nil {
		return nil, err
	}
	err = g2.X.A1.SetBytesCanonical(input[80:128])
	if err != nil {
		return nil, err
	}

	// Map the field element to a G2 point
	result := bls12381.MapToG2(g2.X)

	return &result, nil
}

// isZero checks if the first 16 bytes of a byte slice are all zeros.
//
// This function is used for padding verification in BLS12-381 point decoding.
// EIP-2537 states that field elements are serialized as 48 bytes, but are expected to have
// 16 bytes of leading zeros for 32-byte alignment.
//
// This function checks that the padding bytes are correctly set to zero.
func isZero(slice []byte) bool {
	return bytes.Equal(slice[:16], zeroSlice)
}

// hasWrongG1Padding returns true if the G1 element is not correctly padded.
//
// G1 elements can be represented using two 48 byte field elements (x, y). To be 32-byte
// aligned, these two elements are zero padded by 16 bytes.
//
// This would look like the following: `16 zeroes + x + 16 zeroes + y`
// where `x` and `y` are 48 bytes each
//
// This function checks that the zeroes are correctly placed.
func hasWrongG1Padding(input []byte) bool {
	return !isZero(input[:16]) || !isZero(input[64:80])
}

// hasWrongG2Padding returns true if the G2 element is not correctly aligned.
//
// G2 elements can be represented in 96 bytes (2 fp elements for x, 2 fp elements for y).
// However, to be 32 byte aligned, 16 bytes are used to pad each field element.
//
// This would look like the following:
// `16 zeroes + x.a0 + 16 zeroes + x.a1 + 16 zeroes + y.a0 + 16 zeroes + y.a1`
// where each field element is 48 bytes
//
// This function checks that the zeroes are correctly placed.
func hasWrongG2Padding(input []byte) bool {
	return !isZero(input[:16]) || !isZero(input[64:80]) || !isZero(input[128:144]) || !isZero(input[192:208])
}

/*

eip2537G1IsInSubGroup checks if a G1 point is in the correct subgroup.

- Input:
    - javaInputBuf: Pointer to a buffer containing a G1 point
    - javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
    - cInputLen: Length of the input buffer in bytes
    - cErrorLen: Length of the error buffer in bytes
- Returns:
    - 1 if the G1 point is in the subgroup, 0 otherwise
- Cryptography:
    - The field elements that comprise the G1 input point must be checked to be canonical.
    - Check that the input point is on the curve and in the correct subgroup.
- JNI:
    - javaInputBuf must be at least EIP2537PreallocateForG1 bytes to store the G1 point
    - javaErrorBuf must be at least 256 bytes to safely store the error message
    - javaErrorBuf must be zero initialized
*/
//export eip2537G1IsInSubGroup
func eip2537G1IsInSubGroup(javaInputBuf, javaErrorBuf *C.char, cInputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error buffer into a Go slice
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Validate input length
	if inputLen != EIP2537PreallocateForG1 {
		copy(errorBuf, "invalid input parameters, invalid input length for G1 point validation\x00")
		return 0
	}
	input := (*[EIP2537PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// Check if G1 point is in subgroup
	_, err := g1AffineDecodeInSubGroup(input)
	if err != nil {
		copy(errorBuf, err.Error())
		return 0
	}

	return 1
}

// g1AffineDecodeInSubGroup decodes a byte slice into a G1 affine point and verifies
// that the point is on the curve and in the correct subgroup.
//
// Returns the decoded G1 point if successful, or an error if the decoding fails
// or the point is not on the curve or not in the correct subgroup.
func g1AffineDecodeInSubGroup(input []byte) (*bls12381.G1Affine, error) {
	g1, err := g1AffineDecodeOnCurve(input)
	if err != nil {
		return nil, err
	}

	// do explicit subgroup check
	if !g1.IsInSubGroup() {
		return nil, ErrSubgroupCheckFailed
	}
	return g1, nil
}

/*

eip2537G1IsOnCurve checks if a G1 point is on the curve.

- Input:
    - javaInputBuf: Pointer to a buffer containing a G1 point
    - javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
    - cInputLen: Length of the input buffer in bytes
    - cErrorLen: Length of the error buffer in bytes
- Returns:
    - 1 if the G1 point is on the curve, 0 otherwise
- Cryptography:
    - The field elements that comprise the G1 input point must be checked to be canonical.
    - Check that the input point is on the curve, without performing a subgroup check.
- JNI:
    - javaInputBuf must be at least EIP2537PreallocateForG1 bytes to store the G1 point
    - javaErrorBuf must be at least 256 bytes to safely store the error message
    - javaErrorBuf must be zero initialized
*/
//export eip2537G1IsOnCurve
func eip2537G1IsOnCurve(javaInputBuf, javaErrorBuf *C.char, cInputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error buffer into a Go slice
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Validate input length
	if inputLen != EIP2537PreallocateForG1 {
		copy(errorBuf, "invalid input parameters, invalid input length for G1 point validation\x00")
		return 0
	}
	input := (*[EIP2537PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// Check if G1 point is on curve
	_, err := g1AffineDecodeOnCurve(input)
	if err != nil {
		copy(errorBuf, err.Error())
		return 0
	}

	return 1
}

// g1AffineDecodeOnCurve decodes a byte slice into a G1 affine point and verifies
// that the point is on the curve, without performing a subgroup check.
//
// Returns the decoded G1 point if successful, or an error if the decoding fails
// or the point is not on the curve.
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

/*

eip2537G2IsInSubGroup checks if a G2 point is in the correct subgroup.

- Input:
    - javaInputBuf: Pointer to a buffer containing a G2 point
    - javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
    - cInputLen: Length of the input buffer in bytes
    - cErrorLen: Length of the error buffer in bytes
- Returns:
    - 1 if the G2 point is in the subgroup, 0 otherwise
- Cryptography:
    - The field elements that comprise the G2 input point must be checked to be canonical.
    - Check that the input point is on the curve and in the correct subgroup.
- JNI:
    - javaInputBuf must be at least EIP2537PreallocateForG2 bytes to store the G2 point
    - javaErrorBuf must be at least 256 bytes to safely store the error message
    - javaErrorBuf must be zero initialized
*/
//export eip2537G2IsInSubGroup
func eip2537G2IsInSubGroup(javaInputBuf, javaErrorBuf *C.char, cInputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error buffer into a Go slice
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Validate input length
	if inputLen != EIP2537PreallocateForG2 {
		copy(errorBuf, "invalid input parameters, invalid input length for G2 point validation\x00")
		return 0
	}
	input := (*[EIP2537PreallocateForG2]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// Check if G2 point is in subgroup
	_, err := g2AffineDecodeInSubGroup(input)
	if err != nil {
		copy(errorBuf, err.Error())
		return 0
	}

	return 1
}

// g2AffineDecodeInSubGroup decodes a byte slice into a G2 affine point and verifies
// that the point is on the curve and in the correct subgroup.
//
// Returns the decoded G2 point if successful, or an error if the decoding fails
// or the point is not on the curve or not in the correct subgroup.
func g2AffineDecodeInSubGroup(input []byte) (*bls12381.G2Affine, error) {
	g2, err := g2AffineDecodeOnCurve(input)
	if err != nil {
		return nil, err
	}
	// do explicit subgroup check
	if !g2.IsInSubGroup() {
		return nil, ErrSubgroupCheckFailed
	}
	return g2, nil
}

/*

eip2537G2IsOnCurve checks if a G2 point is on the curve.

- Input:
    - javaInputBuf: Pointer to a buffer containing a G2 point
    - javaErrorBuf: Pointer to a buffer where error messages will be written if an error occurs
    - cInputLen: Length of the input buffer in bytes
    - cErrorLen: Length of the error buffer in bytes
- Returns:
    - 1 if the G2 point is on the curve, 0 otherwise
- Cryptography:
    - The field elements that comprise the G2 input point must be checked to be canonical.
    - Check that the input point is on the curve, without performing a subgroup check.
- JNI:
    - javaInputBuf must be at least EIP2537PreallocateForG2 bytes to store the G2 point
    - javaErrorBuf must be at least 256 bytes to safely store the error message
    - javaErrorBuf must be zero initialized
*/
//export eip2537G2IsOnCurve
func eip2537G2IsOnCurve(javaInputBuf, javaErrorBuf *C.char, cInputLen, cErrorLen C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := int(cErrorLen)

	// Convert C pointer to error buffer into a Go slice
	errorBuf := castBuffer(javaErrorBuf, errorLen)

	// Validate input length
	if inputLen != EIP2537PreallocateForG2 {
		copy(errorBuf, "invalid input parameters, invalid input length for G2 point validation\x00")
		return 0
	}
	input := (*[EIP2537PreallocateForG2]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// Check if G2 point is on curve
	_, err := g2AffineDecodeOnCurve(input)
	if err != nil {
		copy(errorBuf, err.Error())
		return 0
	}

	return 1
}

// g2AffineDecodeOnCurve decodes a byte slice into a G2 affine point and verifies
// that the point is on the curve, without performing a subgroup check.
//
// Returns the decoded G2 point if successful, or an error if the decoding fails
// or the point is not on the curve.
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

// castBufferToSlice converts an unsafe.Pointer to a Go byte slice of specified length.
//
// This allows direct access to memory allocated by Java code without copying.
//
// SAFETY: unsafe.Slice creates a slice that directly references
// the underlying memory. The caller must ensure that the memory remains valid for the
// lifetime of the slice.
func castBufferToSlice(buf unsafe.Pointer, length int) []byte {
	return unsafe.Slice((*byte)(buf), length)
}

// castBuffer converts a C char pointer to a Go byte slice with ensured minimum capacity.
//
// Unlike castBufferToSlice, this function ensures the buffer has
// at least EIP2537PreallocateForResultBytes bytes of capacity.
//
// Note: The caller must ensure that the memory remains valid for the lifetime of the
// returned slice and that no writes occur beyond the actual buffer size allocated by Java.
func castBuffer(javaOutputBuf *C.char, length int) []byte {
	bufSize := length
	if bufSize < EIP2537PreallocateForResultBytes {
		bufSize = EIP2537PreallocateForResultBytes
	}
	return (*[EIP2537PreallocateForResultBytes]byte)(unsafe.Pointer(javaOutputBuf))[:bufSize:bufSize]
}

// nonMontgomeryMarshal encodes a pair of base field elements as byte slices
// in big-endian form and writes them to the output buffer at the specified offset.
//
// The output format follows EIP-2537 serialization, with each field element using 64 bytes,
// (padded with 16 leading zeros). The total output size is 128 bytes
// (64 bytes for each coordinate).
//
// Returns nil on success or an error if the marshaling fails.
func nonMontgomeryMarshal(xVal, yVal *fp.Element, output *C.char, outputOffset int) {
	// Convert g1.X and g1.Y to big.Int using the BigInt method
	var x big.Int
	xVal.BigInt(&x)
	xBytes := x.Bytes()
	xLen := len(xBytes)

	if xLen > 0 {
		// Copy x to output at offset (64 - xLen)

		// Calculate source and destination addresses
		srcPtr := unsafe.Pointer(&xBytes[0])
		destAddr := uintptr(unsafe.Pointer(output)) + uintptr(outputOffset+64-xLen)
		destPtr := unsafe.Pointer(destAddr)

		// Copy from source to destination
		C.memcpy(destPtr, srcPtr, C.size_t(xLen))
	}

	var y big.Int
	yVal.BigInt(&y)
	yBytes := y.Bytes()
	yLen := len(yBytes)

	if yLen > 0 {
		// Copy y to output at offset (128 - yLen)

		// Calculate source and destination addresses
		srcPtr := unsafe.Pointer(&yBytes[0])
		destAddr := uintptr(unsafe.Pointer(output)) + uintptr(outputOffset+128-yLen)
		destPtr := unsafe.Pointer(destAddr)

		// Copy from source to destination
		C.memcpy(destPtr, srcPtr, C.size_t(yLen))
	}
}

// nonMontgomeryMarshalG1 converts a G1 affine point to its serialized form following EIP-2537
// and writes it to the output buffer.
//
// The G1 point is serialized as:
// - 16 zero bytes + 48-byte x-coordinate in big-endian form
// - 16 zero bytes + 48-byte y-coordinate in big-endian form
//
// The total output size is 128 bytes (EIP2537PreallocateForG1).
func nonMontgomeryMarshalG1(g1 *bls12381.G1Affine, output *C.char) {
	nonMontgomeryMarshal(&g1.X, &g1.Y, output, 0)
}

// nonMontgomeryMarshalG2 converts a G2 affine point to its serialized form following EIP-2537
// and writes it to the output buffer.
//
// The G2 point is serialized as:
// - 16 zero bytes + 48-byte x.a0 coordinate in big-endian form
// - 16 zero bytes + 48-byte x.a1 coordinate in big-endian form
// - 16 zero bytes + 48-byte y.a0 coordinate in big-endian form
// - 16 zero bytes + 48-byte y.a1 coordinate in big-endian form
//
// The total output size is 256 bytes (EIP2537PreallocateForG2).
func nonMontgomeryMarshalG2(g2 *bls12381.G2Affine, output *C.char) {
	nonMontgomeryMarshal(&g2.X.A0, &g2.X.A1, output, 0)
	nonMontgomeryMarshal(&g2.Y.A0, &g2.Y.A1, output, 128)
}

func main() {}
