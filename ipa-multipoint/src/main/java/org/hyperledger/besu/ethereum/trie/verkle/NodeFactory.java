package org.hyperledger.besu.ethereum.trie.verkle;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public interface NodeFactory<V> {
    Optional<Node<V>> retrieve(final Bytes location, final Bytes32 hash);
}