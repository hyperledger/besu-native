/*
 * Copyright ConsenSys AG.
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
 */

package org.hyperledger.besu.nativelib.secp256r1.besuNativeEC;

import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.KeyRecoveryResult.KeyRecoveryResultByValue;
import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.SignResult.SignResultByValue;
import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.VerifyResult.VerifyResultByValue;

import com.sun.jna.Library;
import com.sun.jna.Native;

public interface BesuNativeEC extends Library {
	Library OPEN_SSL_LIB_CRYPTO = Native.load("besu_native_ec_crypto", Library.class);
	BesuNativeEC INSTANCE = Native.load("besu_native_ec", BesuNativeEC.class);

	/**
	 * Original signature : <code>key_recovery_result p256_key_recovery(const char[], const int, const char[], const char[], int)</code><br>
	 */
	KeyRecoveryResultByValue p256_key_recovery(byte[] data_hash, int data_hash_len, byte[] signature_r_hex, byte[] signature_s_hex, int signature_v);

	/**
	 * Original signature : <code>sign_result p256_sign(const char[], const int, const char[], const char[])</code><br>
	 */
	SignResultByValue p256_sign(byte[] data_hash, int data_hash_length, byte[] private_key_data, byte[] public_key_data);

	/**
	 * Original signature : <code>verify_result p256_verify(const char[], const int, const char[], const char[], const char[])</code><br>
	 */
	VerifyResultByValue p256_verify(byte[] data_hash, int data_hash_length, byte[] signature_r, byte[] signature_s, byte[] public_key_data);
}
