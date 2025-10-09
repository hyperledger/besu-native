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
package org.hyperledger.besu.nativelib.gnark;

import org.graalvm.nativeimage.c.CContext;
import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.CIntPointer;

import java.util.Collections;
import java.util.List;

/**
 * GraalVM native-image compatible interface to gnark EIP-196 static library
 */
public class LibGnarkEIP196Graal {

    public static final int EIP196_PREALLOCATE_FOR_RESULT_BYTES = 128;
    public static final int EIP196_PREALLOCATE_FOR_ERROR_BYTES = 256;
    public static final byte EIP196_ADD_OPERATION_RAW_VALUE = 1;
    public static final byte EIP196_MUL_OPERATION_RAW_VALUE = 2;
    public static final byte EIP196_PAIR_OPERATION_RAW_VALUE = 3;

    @CContext(LibGnarkEIP196Graal.Directives.class)
    public static class Directives implements CContext.Directives {
        @Override
        public List<String> getHeaderFiles() {
            return Collections.singletonList("<libgnark_eip_196.h>");
        }

        @Override
        public List<String> getLibraries() {
            return Collections.singletonList("gnark_eip_196");
        }

        @Override
        public List<String> getLibraryPaths() {
            // Library paths should be configured via native-image build arguments
            return Collections.emptyList();
        }
    }

    @CFunction(value = "eip196altbn128G1Add")
    public static native int eip196altbn128G1AddNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            CIntPointer outputSize,
            CIntPointer errorSize);

    @CFunction(value = "eip196altbn128G1Mul")
    public static native int eip196altbn128G1MulNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            CIntPointer outputSize,
            CIntPointer errorSize);

    @CFunction(value = "eip196altbn128Pairing")
    public static native int eip196altbn128PairingNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            CIntPointer outputSize,
            CIntPointer errorSize);

    /**
     * Here as a compatibility shim for the pre-existing matter-labs implementation.
     */
    public static int eip196_perform_operation(
            byte op,
            byte[] input,
            int inputLength,
            byte[] output,
            int[] outputSize,
            byte[] error,
            int[] errorSize) {

        int ret = -1;
        switch(op) {
            case EIP196_ADD_OPERATION_RAW_VALUE:
                ret = eip196altbn128G1Add(input, output, error, inputLength, outputSize, errorSize);
                break;
            case EIP196_MUL_OPERATION_RAW_VALUE:
                ret = eip196altbn128G1Mul(input, output, error, inputLength, outputSize, errorSize);
                break;
            case EIP196_PAIR_OPERATION_RAW_VALUE:
                ret = eip196altbn128Pairing(input, output, error, inputLength, outputSize, errorSize);
                break;
            default:
                throw new RuntimeException("Not Implemented EIP-196 operation " + op);
        }

        return ret;
    }

    /**
     * Java-friendly wrapper for eip196altbn128G1Add
     */
    public static int eip196altbn128G1Add(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int[] outputSize,
            int[] errorSize) {
        return GraalVMHelper.callWithByteArraysAndRefs(
            input, output, error, inputSize, outputSize, errorSize,
            (inPtr, outPtr, errPtr, inSize, outSizePtr, errSizePtr) ->
                eip196altbn128G1AddNative(inPtr, outPtr, errPtr, inSize, outSizePtr, errSizePtr)
        );
    }

    /**
     * Java-friendly wrapper for eip196altbn128G1Mul
     */
    public static int eip196altbn128G1Mul(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int[] outputSize,
            int[] errorSize) {
        return GraalVMHelper.callWithByteArraysAndRefs(
            input, output, error, inputSize, outputSize, errorSize,
            (inPtr, outPtr, errPtr, inSize, outSizePtr, errSizePtr) ->
                eip196altbn128G1MulNative(inPtr, outPtr, errPtr, inSize, outSizePtr, errSizePtr)
        );
    }

    /**
     * Java-friendly wrapper for eip196altbn128Pairing
     */
    public static int eip196altbn128Pairing(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int[] outputSize,
            int[] errorSize) {
        return GraalVMHelper.callWithByteArraysAndRefs(
            input, output, error, inputSize, outputSize, errorSize,
            (inPtr, outPtr, errPtr, inSize, outSizePtr, errSizePtr) ->
                eip196altbn128PairingNative(inPtr, outPtr, errPtr, inSize, outSizePtr, errSizePtr)
        );
    }
}
