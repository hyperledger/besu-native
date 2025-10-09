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

import java.util.Collections;
import java.util.List;

/**
 * GraalVM native-image compatible interface to gnark EIP-2537 static library
 */
public class LibGnarkEIP2537Graal {

    public static final int EIP2537_PREALLOCATE_FOR_RESULT_BYTES = 256;
    public static final int EIP2537_PREALLOCATE_FOR_ERROR_BYTES = 256;

    public static final byte BLS12_G1ADD_OPERATION_SHIM_VALUE = 1;
    public static final byte BLS12_G1MULTIEXP_OPERATION_SHIM_VALUE = 2;
    public static final byte BLS12_G2ADD_OPERATION_SHIM_VALUE = 3;
    public static final byte BLS12_G2MULTIEXP_OPERATION_SHIM_VALUE = 4;
    public static final byte BLS12_PAIR_OPERATION_SHIM_VALUE = 5;
    public static final byte BLS12_MAP_FP_TO_G1_OPERATION_SHIM_VALUE = 6;
    public static final byte BLS12_MAP_FP2_TO_G2_OPERATION_SHIM_VALUE = 7;

    // zero implies 'default' degree of parallelism, which is the number of cpu cores available
    private static int degreeOfMSMParallelism = 0;

    @CContext(LibGnarkEIP2537Graal.Directives.class)
    public static class Directives implements CContext.Directives {
        @Override
        public List<String> getHeaderFiles() {
            return Collections.singletonList("<libgnark_eip_2537.h>");
        }

        @Override
        public List<String> getLibraries() {
            return Collections.singletonList("gnark_eip_2537");
        }

        @Override
        public List<String> getLibraryPaths() {
            // Library paths should be configured via native-image build arguments
            return Collections.emptyList();
        }
    }

    @CFunction(value = "eip2537blsG1Add")
    public static native int eip2537blsG1AddNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength);

    @CFunction(value = "eip2537blsG1MultiExp")
    public static native int eip2537blsG1MultiExpNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength,
            int nbTasks);

    @CFunction(value = "eip2537blsG2Add")
    public static native int eip2537blsG2AddNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength);

    @CFunction(value = "eip2537blsG2MultiExp")
    public static native int eip2537blsG2MultiExpNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength,
            int nbTasks);

    @CFunction(value = "eip2537blsPairing")
    public static native int eip2537blsPairingNative(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength);

    @CFunction(value = "eip2537blsMapFpToG1")
    public static native int eip2537blsMapFpToG1Native(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength);

    @CFunction(value = "eip2537blsMapFp2ToG2")
    public static native int eip2537blsMapFp2ToG2Native(
            CCharPointer input,
            CCharPointer output,
            CCharPointer error,
            int inputSize,
            int outputLength,
            int errorLength);

    @CFunction(value = "eip2537G1IsOnCurve")
    public static native boolean eip2537G1IsOnCurveNative(
            CCharPointer input,
            CCharPointer error,
            int inputSize,
            int errorLength);

    @CFunction(value = "eip2537G2IsOnCurve")
    public static native boolean eip2537G2IsOnCurveNative(
            CCharPointer input,
            CCharPointer error,
            int inputSize,
            int errorLength);

    @CFunction(value = "eip2537G1IsInSubGroup")
    public static native boolean eip2537G1IsInSubGroupNative(
            CCharPointer input,
            CCharPointer error,
            int inputSize,
            int errorLength);

    @CFunction(value = "eip2537G2IsInSubGroup")
    public static native boolean eip2537G2IsInSubGroupNative(
            CCharPointer input,
            CCharPointer error,
            int inputSize,
            int errorLength);

    /**
     * Here as a compatibility shim for the pre-existing matter-labs implementation.
     *
     * IMPORTANT: The output buffer MUST be zero-initialized before calling this method.
     * The native implementation relies on this pre-initialization for proper functioning.
     */
    public static int eip2537_perform_operation(
            byte op,
            byte[] input,
            int inputLength,
            byte[] output,
            int[] outputLength,
            byte[] error,
            int[] errorLength) {

        int ret = -1;
        switch(op) {
            case BLS12_G1ADD_OPERATION_SHIM_VALUE:
                ret = eip2537blsG1Add(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
                outputLength[0] = 128;
                break;
            case BLS12_G1MULTIEXP_OPERATION_SHIM_VALUE:
                ret = eip2537blsG1MultiExp(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES,
                    degreeOfMSMParallelism);
                outputLength[0] = 128;
                break;
            case BLS12_G2ADD_OPERATION_SHIM_VALUE:
                ret = eip2537blsG2Add(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
                outputLength[0] = 256;
                break;
            case BLS12_G2MULTIEXP_OPERATION_SHIM_VALUE:
                ret = eip2537blsG2MultiExp(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES,
                    degreeOfMSMParallelism);
                outputLength[0] = 256;
                break;
            case BLS12_PAIR_OPERATION_SHIM_VALUE:
                ret = eip2537blsPairing(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
                outputLength[0] = 32;
                break;
            case BLS12_MAP_FP_TO_G1_OPERATION_SHIM_VALUE:
                ret = eip2537blsMapFpToG1(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
                outputLength[0] = 128;
                break;
            case BLS12_MAP_FP2_TO_G2_OPERATION_SHIM_VALUE:
                ret = eip2537blsMapFp2ToG2(input, output, error, inputLength,
                    EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
                    EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
                outputLength[0] = 256;
                break;
            default:
                throw new RuntimeException("Not Implemented EIP-2537 operation " + op);
        }

        if (ret != 0) {
            errorLength[0] = LibGnarkUtils.findFirstTrailingZeroIndex(error);
            outputLength[0] = 0;
        } else {
            errorLength[0] = 0;
        }
        return ret;
    }

    /**
     * Java-friendly wrapper for eip2537blsG1Add
     */
    public static int eip2537blsG1Add(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength) {
        return GraalVMHelper.callWithByteArraysAndSizes(
            input, output, error, inputSize, outputLength, errorLength,
            (inPtr, outPtr, errPtr, inSize, outLen, errLen) ->
                eip2537blsG1AddNative(inPtr, outPtr, errPtr, inSize, outLen, errLen)
        );
    }

    /**
     * Java-friendly wrapper for eip2537blsG1MultiExp
     */
    public static int eip2537blsG1MultiExp(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength,
            int nbTasks) {
        return GraalVMHelper.callWithByteArraysSizesAndTasks(
            input, output, error, inputSize, outputLength, errorLength, nbTasks,
            (inPtr, outPtr, errPtr, inSize, outLen, errLen, tasks) ->
                eip2537blsG1MultiExpNative(inPtr, outPtr, errPtr, inSize, outLen, errLen, tasks)
        );
    }

    /**
     * Java-friendly wrapper for eip2537blsG2Add
     */
    public static int eip2537blsG2Add(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength) {
        return GraalVMHelper.callWithByteArraysAndSizes(
            input, output, error, inputSize, outputLength, errorLength,
            (inPtr, outPtr, errPtr, inSize, outLen, errLen) ->
                eip2537blsG2AddNative(inPtr, outPtr, errPtr, inSize, outLen, errLen)
        );
    }

    /**
     * Java-friendly wrapper for eip2537blsG2MultiExp
     */
    public static int eip2537blsG2MultiExp(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength,
            int nbTasks) {
        return GraalVMHelper.callWithByteArraysSizesAndTasks(
            input, output, error, inputSize, outputLength, errorLength, nbTasks,
            (inPtr, outPtr, errPtr, inSize, outLen, errLen, tasks) ->
                eip2537blsG2MultiExpNative(inPtr, outPtr, errPtr, inSize, outLen, errLen, tasks)
        );
    }

    /**
     * Java-friendly wrapper for eip2537blsPairing
     */
    public static int eip2537blsPairing(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength) {
        return GraalVMHelper.callWithByteArraysAndSizes(
            input, output, error, inputSize, outputLength, errorLength,
            (inPtr, outPtr, errPtr, inSize, outLen, errLen) ->
                eip2537blsPairingNative(inPtr, outPtr, errPtr, inSize, outLen, errLen)
        );
    }

    /**
     * Java-friendly wrapper for eip2537blsMapFpToG1
     */
    public static int eip2537blsMapFpToG1(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength) {
        return GraalVMHelper.callWithByteArraysAndSizes(
            input, output, error, inputSize, outputLength, errorLength,
            (inPtr, outPtr, errPtr, inSize, outLen, errLen) ->
                eip2537blsMapFpToG1Native(inPtr, outPtr, errPtr, inSize, outLen, errLen)
        );
    }

    /**
     * Java-friendly wrapper for eip2537blsMapFp2ToG2
     */
    public static int eip2537blsMapFp2ToG2(
            byte[] input,
            byte[] output,
            byte[] error,
            int inputSize,
            int outputLength,
            int errorLength) {
        return GraalVMHelper.callWithByteArraysAndSizes(
            input, output, error, inputSize, outputLength, errorLength,
            (inPtr, outPtr, errPtr, inSize, outLen, errLen) ->
                eip2537blsMapFp2ToG2Native(inPtr, outPtr, errPtr, inSize, outLen, errLen)
        );
    }

    /**
     * Java-friendly wrapper for eip2537G1IsOnCurve
     */
    public static boolean eip2537G1IsOnCurve(
            byte[] input,
            byte[] error,
            int inputSize,
            int errorLength) {
        return GraalVMHelper.callBooleanWithByteArrays(
            input, error, inputSize, errorLength,
            (inPtr, errPtr, inSize, errLen) ->
                eip2537G1IsOnCurveNative(inPtr, errPtr, inSize, errLen)
        );
    }

    /**
     * Java-friendly wrapper for eip2537G2IsOnCurve
     */
    public static boolean eip2537G2IsOnCurve(
            byte[] input,
            byte[] error,
            int inputSize,
            int errorLength) {
        return GraalVMHelper.callBooleanWithByteArrays(
            input, error, inputSize, errorLength,
            (inPtr, errPtr, inSize, errLen) ->
                eip2537G2IsOnCurveNative(inPtr, errPtr, inSize, errLen)
        );
    }

    /**
     * Java-friendly wrapper for eip2537G1IsInSubGroup
     */
    public static boolean eip2537G1IsInSubGroup(
            byte[] input,
            byte[] error,
            int inputSize,
            int errorLength) {
        return GraalVMHelper.callBooleanWithByteArrays(
            input, error, inputSize, errorLength,
            (inPtr, errPtr, inSize, errLen) ->
                eip2537G1IsInSubGroupNative(inPtr, errPtr, inSize, errLen)
        );
    }

    /**
     * Java-friendly wrapper for eip2537G2IsInSubGroup
     */
    public static boolean eip2537G2IsInSubGroup(
            byte[] input,
            byte[] error,
            int inputSize,
            int errorLength) {
        return GraalVMHelper.callBooleanWithByteArrays(
            input, error, inputSize, errorLength,
            (inPtr, errPtr, inSize, errLen) ->
                eip2537G2IsInSubGroupNative(inPtr, errPtr, inSize, errLen)
        );
    }

    public static void setDegreeOfMSMParallelism(int nbTasks) {
        degreeOfMSMParallelism = nbTasks;
    }
}
