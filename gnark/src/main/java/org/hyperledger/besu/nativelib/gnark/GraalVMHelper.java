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

import org.graalvm.nativeimage.PinnedObject;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.CIntPointer;

/**
 * Helper class for converting between Java byte arrays and GraalVM native pointers.
 * Provides safe memory management by pinning Java byte arrays while calling native functions.
 */
public class GraalVMHelper {

    /** Private constructor to prevent instantiation of utility class. */
    private GraalVMHelper() {}

    /**
     * Functional interface for native calls with 3 arguments: input buffer, length, output buffer.
     */
    @FunctionalInterface
    public interface NativeCall3 {
        /**
         * Calls the native function.
         *
         * @param input pointer to input buffer
         * @param length size of input data
         * @param output pointer to output buffer
         * @return result code from native function
         */
        int call(CCharPointer input, int length, CCharPointer output);
    }

    /**
     * Functional interface for native calls with input, output, error buffers and their sizes.
     */
    @FunctionalInterface
    public interface NativeCall4 {
        /**
         * Calls the native function.
         *
         * @param input pointer to input buffer
         * @param output pointer to output buffer
         * @param error pointer to error buffer
         * @param inputSize size of input buffer
         * @param outputSize size of output buffer
         * @param errorSize size of error buffer
         * @return result code from native function
         */
        int call(CCharPointer input, CCharPointer output, CCharPointer error, int inputSize, int outputSize, int errorSize);
    }

    /**
     * Functional interface for native calls with buffers, sizes, and parallelism control.
     */
    @FunctionalInterface
    public interface NativeCall5 {
        /**
         * Calls the native function.
         *
         * @param input pointer to input buffer
         * @param output pointer to output buffer
         * @param error pointer to error buffer
         * @param inputSize size of input buffer
         * @param outputSize size of output buffer
         * @param errorSize size of error buffer
         * @param nbTasks number of parallel tasks
         * @return result code from native function
         */
        int call(CCharPointer input, CCharPointer output, CCharPointer error, int inputSize, int outputSize, int errorSize, int nbTasks);
    }

    /**
     * Functional interface for native calls with buffers and size references (output parameters).
     */
    @FunctionalInterface
    public interface NativeCall6 {
        /**
         * Calls the native function.
         *
         * @param input pointer to input buffer
         * @param output pointer to output buffer
         * @param error pointer to error buffer
         * @param inputSize size of input buffer
         * @param outputSizePtr pointer to output size variable
         * @param errorSizePtr pointer to error size variable
         * @return result code from native function
         */
        int call(CCharPointer input, CCharPointer output, CCharPointer error, int inputSize, CIntPointer outputSizePtr, CIntPointer errorSizePtr);
    }

    /**
     * Functional interface for boolean native calls with input and error buffers.
     */
    @FunctionalInterface
    public interface BooleanNativeCall {
        /**
         * Calls the native function.
         *
         * @param input pointer to input buffer
         * @param error pointer to error buffer
         * @param inputSize size of input buffer
         * @param errorSize size of error buffer
         * @return boolean result from native function
         */
        boolean call(CCharPointer input, CCharPointer error, int inputSize, int errorSize);
    }

    /**
     * Helper for calling native functions with byte arrays (3 arguments).
     *
     * @param input input byte array
     * @param inputLength length of input data
     * @param output output byte array
     * @param nativeCall functional interface wrapping the native call
     * @return result code from native function
     */
    public static int callWithByteArrays(byte[] input, int inputLength, byte[] output, NativeCall3 nativeCall) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output)) {
            return nativeCall.call(
                pinnedInput.addressOfArrayElement(0),
                inputLength,
                pinnedOutput.addressOfArrayElement(0)
            );
        }
    }

    /**
     * Helper for calling native functions with byte arrays and sizes (4 arguments).
     *
     * @param input input byte array
     * @param output output byte array
     * @param error error byte array
     * @param inputSize size of input buffer
     * @param outputSize size of output buffer
     * @param errorSize size of error buffer
     * @param nativeCall functional interface wrapping the native call
     * @return result code from native function
     */
    public static int callWithByteArraysAndSizes(
            byte[] input, byte[] output, byte[] error,
            int inputSize, int outputSize, int errorSize,
            NativeCall4 nativeCall) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return nativeCall.call(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize,
                outputSize,
                errorSize
            );
        }
    }

    /**
     * Helper for calling native functions with byte arrays, sizes, and parallelism (5 arguments).
     *
     * @param input input byte array
     * @param output output byte array
     * @param error error byte array
     * @param inputSize size of input buffer
     * @param outputSize size of output buffer
     * @param errorSize size of error buffer
     * @param nbTasks number of parallel tasks
     * @param nativeCall functional interface wrapping the native call
     * @return result code from native function
     */
    public static int callWithByteArraysSizesAndTasks(
            byte[] input, byte[] output, byte[] error,
            int inputSize, int outputSize, int errorSize, int nbTasks,
            NativeCall5 nativeCall) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return nativeCall.call(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize,
                outputSize,
                errorSize,
                nbTasks
            );
        }
    }

    /**
     * Helper for calling native functions with byte arrays and size references (6 arguments).
     *
     * @param input input byte array
     * @param output output byte array
     * @param error error byte array
     * @param inputSize size of input buffer
     * @param outputSize output size reference (updated by native function)
     * @param errorSize error size reference (updated by native function)
     * @param nativeCall functional interface wrapping the native call
     * @return result code from native function
     */
    public static int callWithByteArraysAndRefs(
            byte[] input, byte[] output, byte[] error,
            int inputSize, int[] outputSize, int[] errorSize,
            NativeCall6 nativeCall) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedError = PinnedObject.create(error);
             PinnedObject pinnedOutputSize = PinnedObject.create(outputSize);
             PinnedObject pinnedErrorSize = PinnedObject.create(errorSize)) {
            return nativeCall.call(
                pinnedInput.addressOfArrayElement(0),
                pinnedOutput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize,
                pinnedOutputSize.addressOfArrayElement(0),
                pinnedErrorSize.addressOfArrayElement(0)
            );
        }
    }

    /**
     * Helper for calling boolean native functions.
     *
     * @param input input byte array
     * @param error error byte array
     * @param inputSize size of input buffer
     * @param errorSize size of error buffer
     * @param nativeCall functional interface wrapping the native call
     * @return boolean result from native function
     */
    public static boolean callBooleanWithByteArrays(
            byte[] input, byte[] error,
            int inputSize, int errorSize,
            BooleanNativeCall nativeCall) {
        try (PinnedObject pinnedInput = PinnedObject.create(input);
             PinnedObject pinnedError = PinnedObject.create(error)) {
            return nativeCall.call(
                pinnedInput.addressOfArrayElement(0),
                pinnedError.addressOfArrayElement(0),
                inputSize,
                errorSize
            );
        }
    }
}
