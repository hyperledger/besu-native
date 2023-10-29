/* Copyright Hyperledger Besu Contributors.
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
package org.hyperledger.besu.ethereum.trie.verkle;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class NullNode<V> implements Node<V> {
    @SuppressWarnings("rawtypes")
    private static final NullNode instance = new NullNode();

    protected NullNode() {}

    @SuppressWarnings("unchecked")
    public static <V> NullNode<V> instance() {
        return instance;
    }

    @Override
    public Node<V> accept(final PathNodeVisitor<V> visitor, final Bytes path) {
        return visitor.visit(this, path);
    }

    @Override
    public Node<V> accept(final NodeVisitor<V> visitor) {
        return visitor.visit(this);
    }

    @Override
    public Optional<Bytes32> getHash() {
        return Optional.of(EMPTY_HASH);
    }

    @Override
    public Node<V> replacePath(final Bytes path) {
        return this;
    }

    @Override
    public String print() {
        return "[NULL]";
    }

    @Override
    public boolean isDirty() {
        return false;
    }

    @Override
    public void markDirty() {
        // do nothing
    }
}