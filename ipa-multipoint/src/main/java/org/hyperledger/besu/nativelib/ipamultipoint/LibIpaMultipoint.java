/*
 * Copyright The Machine Consultancy LLC
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
package org.hyperledger.besu.nativelib.ipamultipoint;

/**
 * Java interface to ipa-multipoint.
 *
 * Allows to compute commitments for Verkle tree nodes.
 */
public class LibIpaMultipoint {

  public static native byte[] commit(byte[] input1, byte[] input2, byte[] input3, byte[] input4);
}
