package org.hyperledger.besu.ethereum.trie.verkle;

import org.apache.tuweni.bytes.Bytes32;


public interface Hasher<V> {

    public Bytes32 commit(V[] inputs);

    // public Bytes32 commit_sparse(V[] input, int[] index)
}