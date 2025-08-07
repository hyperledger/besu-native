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
	"errors"
	"math/big"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

var ErrMalformedPointEIP196 = errors.New("invalid point encoding")
var ErrInvalidInputPairingLengthEIP196 = errors.New("invalid input parameters, invalid input length for pairing")
var ErrPointNotInFieldEIP196 = errors.New("point not in field")
var ErrPointInSubgroupCheckFailedEIP196 = errors.New("point is not in subgroup")
var ErrPointOnCurveCheckFailedEIP196 = errors.New("point is not on curve")

const (
	EIP196PreallocateForResult = 128
	EIP196PreallocateForError  = 256
	EIP196PreallocateForScalar = 32                         // scalar int is 32 byte
	EIP196PreallocateForFp     = 32                         // field elements are 32 bytes
	EIP196PreallocateForG1     = EIP196PreallocateForFp * 2 // G1 points are encoded as 2 concatenated field elements
	EIP196PreallocateForG2     = EIP196PreallocateForG1 * 2 // G2 points are encoded as 2 concatenated G1 points
)

var EIP196ScalarTwo = big.NewInt(2)

// bn254Modulus is the value 21888242871839275222246405745257275088696311157297823662689037894645226208583
var bn254Modulus = new(big.Int).SetBytes([]byte{
	0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
	0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
	0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
	0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
})

//export eip196altbn128G1Add
func eip196altbn128G1Add(javaInputBuf, javaOutputBuf, javaErrorBuf *C.char, cInputLen C.int, cOutputLen, cErrorLen *C.int) C.int {
	inputLen := int(cInputLen)
	errorLen := (*int)(unsafe.Pointer(cErrorLen))
	outputLen := (*int)(unsafe.Pointer(cOutputLen))

	// Convert error C pointers to Go slices
	errorBuf := castErrorBufferEIP196(javaErrorBuf, errorLen)

	if inputLen > 2*EIP196PreallocateForG1 {
		// trunc if input too long
		inputLen = 2 * EIP196PreallocateForG1
	}

	// Convert input C pointers to Go slices
	input := (*[2 * EIP196PreallocateForG1]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	if inputLen == 0 {
		*outputLen = EIP196PreallocateForG1
		return 0
	}

	// generate p0 g1 affine
	var p0 bn254.G1Affine

	err := safeUnmarshalEIP196(&p0, input, 0)

	if err != nil {
		dryError(err, errorBuf, outputLen, errorLen)
		return 1
	}

	if inputLen < 2*EIP196PreallocateForG1 {
		// if incomplete input is all zero, return p0
		if isAllZeroEIP196(input, 64, 64) {
			ret := p0.Marshal()
			g1AffineEncode(ret, javaOutputBuf)
			*outputLen = EIP196PreallocateForG1
			return 0
		}
	}
	// generate p1 g1 affine
	var p1 bn254.G1Affine
	err = safeUnmarshalEIP196(&p1, input, 64)

	if err != nil {
		dryError(err, errorBuf, outputLen, errorLen)
		return 1
	}
	var result *bn254.G1Affine

	// Use the Add method to combine points
	result = p0.Add(&p0, &p1)

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

	if inputLen == 0 {
		// zero input returns 0
		*outputLen = EIP196PreallocateForG1
		return 0
	}

	if inputLen > EIP196PreallocateForG1+EIP196PreallocateForScalar {
		// trunc if input too long
		inputLen = EIP196PreallocateForG1 + EIP196PreallocateForScalar
	}

	// Convert input C pointers to Go slice
	input := (*[EIP196PreallocateForG1 + EIP196PreallocateForScalar]byte)(unsafe.Pointer(javaInputBuf))[:inputLen:inputLen]

	// infinity check:
	if isAllZeroEIP196(input, 0, 64) {
		*outputLen = EIP196PreallocateForG1
		return 0
	}

	// generate p0 g1 affine
	var p0 bn254.G1Affine
	err := safeUnmarshalEIP196(&p0, input, 0)

	if err != nil {
		dryError(err, errorBuf, outputLen, errorLen)
		return 1
	}

	if inputLen < EIP196PreallocateForG1+1 {
		// if there is not even a partial input scalar, return 0
		*outputLen = EIP196PreallocateForG1
		return 0
	}

	// Convert byte slice to *big.Int
	scalarBytes := input[EIP196PreallocateForG1:]
	if 96 > int(cInputLen) {
		// if the input is truncated, copy the bytes to the high order portion of the scalar
		scalarBytes = make([]byte, 32)
		copy(scalarBytes[:], input[64:int(cInputLen)])
	}

	scalar := big.NewInt(0)
	scalar.SetBytes(scalarBytes[:])

	var result *bn254.G1Affine
	if scalar.Cmp(EIP196ScalarTwo) == 0 {
		// if scalar == 2, double is faster
		result = p0.Double(&p0)
	} else {
		// multiply g1 point by scalar
		result = p0.ScalarMultiplication(&p0, scalar)
	}

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
		output[31] = 0x01
		return 0
	}

	if inputLen%(EIP196PreallocateForG2+EIP196PreallocateForG1) != 0 {
		dryError(ErrInvalidInputPairingLengthEIP196, errorBuf, outputLen, errorLen)
		return 1
	}

	// Convert input C pointers to Go slice
	input := castBufferToSliceEIP196(unsafe.Pointer(javaInputBuf), inputLen)

	var pairCount = inputLen / (EIP196PreallocateForG2 + EIP196PreallocateForG1)
	g1Points := make([]bn254.G1Affine, pairCount)
	g2Points := make([]bn254.G2Affine, pairCount)

	for i := 0; i < pairCount; i++ {

		// g1 x and y are the first 64 bytes of each 192 byte pair
		var g1 bn254.G1Affine
		err := safeUnmarshalEIP196(&g1, input[i*192:i*192+64], 0)

		if err != nil {
			dryError(err, errorBuf, outputLen, errorLen)
			return 1
		}

		// g2 points are latter 128 bytes of each 192 byte pair
		var g2 bn254.G2Affine
		err = safeUnmarshalG2EIP196(&g2, input[i*192+64:(i+1)*192])

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

	if isOne {
		// respond with 1 if pairing check was true, leave 0's intact otherwise
		output[31] = 0x01
	}
	return 0

}

func g1AffineEncode(g1Point []byte, output *C.char) error {
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

func safeUnmarshalEIP196(g1 *bn254.G1Affine, input []byte, offset int) error {
	var pointBytes []byte

	// If we effectively have _NO_ input, return empty
	if len(input)-offset <= 0 {
		return nil
	} else if len(input)-offset < 64 {
		// If we have some input, but it is incomplete, pad with zero
		pointBytes = make([]byte, 64)
		shortLen := len(input) - offset
		copy(pointBytes, input[offset:len(input)])
		for i := shortLen; i < 64; i++ {
			pointBytes[i] = 0
		}
	} else {
		pointBytes = input[offset : offset+64]
	}

	if !checkInFieldEIP196(pointBytes[0:32]) {
		return ErrPointNotInFieldEIP196
	}

	err := g1.X.SetBytesCanonical(pointBytes[0:32])

	if err == nil {

		if !checkInFieldEIP196(pointBytes[32:64]) {
			return ErrPointNotInFieldEIP196
		}
		err := g1.Y.SetBytesCanonical(pointBytes[32:64])
		if err == nil {
			if !g1.IsOnCurve() {
				return ErrPointOnCurveCheckFailedEIP196
			}
			return nil
		}
	}

	return err
}

func safeUnmarshalG2EIP196(g2 *bn254.G2Affine, input []byte) error {
	if len(input) < EIP196PreallocateForG2 {
		return ErrInvalidInputPairingLengthEIP196
	}

	if !(checkInFieldEIP196(input[0:32]) && checkInFieldEIP196(input[32:64]) &&
		checkInFieldEIP196(input[64:96]) && checkInFieldEIP196(input[96:128])) {
		return ErrPointNotInFieldEIP196
	}

	g2.X.A1.SetBytesCanonical(input[:32])
	g2.X.A0.SetBytesCanonical(input[32:64])
	g2.Y.A1.SetBytesCanonical(input[64:96])
	g2.Y.A0.SetBytesCanonical(input[96:128])

	if !g2.IsOnCurve() {
		return ErrPointOnCurveCheckFailedEIP196
	}
	if !g2.IsInSubGroup() {
		return ErrPointInSubgroupCheckFailedEIP196
	}

	return nil
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
func isAllZeroEIP196(data []byte, offset, length int) bool {

	if len(data) > offset {
		tail := offset + length
		if len(data) < tail {
			tail = len(data)
		}
		slice := data[offset:tail]
		for _, b := range slice {
			if b != 0 {
				return false
			}
		}
	}
	return true
}

func dryError(err error, errorBuf []byte, outputLen, errorLen *int) {
	errStr := "invalid input parameters, " + err.Error()
	copy(errorBuf, errStr)
	*outputLen = 0
	*errorLen = len(errStr)
}

func castBufferToSliceEIP196(buf unsafe.Pointer, length int) []byte {
	return unsafe.Slice((*byte)(buf), length)
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

func main() {
}
