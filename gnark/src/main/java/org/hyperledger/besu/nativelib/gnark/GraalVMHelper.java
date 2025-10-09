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
 * Helper class for converting between Java byte arrays and GraalVM native pointers
 */
public class GraalVMHelper {

    @FunctionalInterface
    public interface NativeCall3 {
        int call(CCharPointer input, int length, CCharPointer output);
    }

    @FunctionalInterface
    public interface NativeCall4 {
        int call(CCharPointer input, CCharPointer output, CCharPointer error, int inputSize, int outputSize, int errorSize);
    }

    @FunctionalInterface
    public interface NativeCall5 {
        int call(CCharPointer input, CCharPointer output, CCharPointer error, int inputSize, int outputSize, int errorSize, int nbTasks);
    }

    @FunctionalInterface
    public interface NativeCall6 {
        int call(CCharPointer input, CCharPointer output, CCharPointer error, int inputSize, CIntPointer outputSizePtr, CIntPointer errorSizePtr);
    }

    @FunctionalInterface
    public interface BooleanNativeCall {
        boolean call(CCharPointer input, CCharPointer error, int inputSize, int errorSize);
    }

    /**
     * Helper for calling native functions with byte arrays (3 arguments)
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
     * Helper for calling native functions with byte arrays and sizes (4 arguments)
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
     * Helper for calling native functions with byte arrays, sizes, and parallelism (5 arguments)
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
     * Helper for calling native functions with byte arrays and size references (6 arguments)
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
     * Helper for calling boolean native functions
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
