/*
 * Copyright Hyperledger Besu Contributors.
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

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;


public class SimpleVerkleTrie<K extends Bytes, V extends Bytes> implements VerkleTrie<K, V> {
    private Node<V> root;

    public SimpleVerkleTrie() {
        this.root = NullNode.instance();
    }

    public SimpleVerkleTrie(Node<V> root) {
        this.root = root;
    }

    public Node<V> getRoot() {
        return root;
    }

    @Override
    public Optional<V> get(final K key) {
        checkNotNull(key);
        return root.accept(new GetVisitor<V>(), key).getValue();
    }

    @Override
    public void put(final K key, final V value) {
        checkNotNull(key);
        checkNotNull(value);
        this.root = root.accept(new PutVisitor<V>(value), key);
    }

    @Override
    public void remove(final K key) {
        checkNotNull(key);
        this.root = root.accept(new RemoveVisitor<V>(), key);
    }

    @Override
    public Bytes32 getRootHash() {
        root = root.accept(new HashVisitor<V>(), root.getPath());
        return root.getHash().get();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getRootHash() + "]";
    }

    @Override
    public void commit(final NodeUpdater nodeUpdater) {
        root = root.accept(new HashVisitor<V>(), root.getPath());
        root = root.accept(new CommitVisitor<V>(nodeUpdater), Bytes.EMPTY);
    }
}