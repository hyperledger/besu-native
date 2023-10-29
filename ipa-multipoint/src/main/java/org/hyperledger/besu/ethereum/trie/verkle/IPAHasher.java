package org.hyperledger.besu.ethereum.trie.verkle;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.nativelib.ipamultipoint.LibIpaMultipoint;


public class IPAHasher implements Hasher<Bytes32> {
    @Override
    public Bytes32 commit(Bytes32[] inputs) {
        Bytes input_serialized = Bytes.concatenate(inputs);
        return Bytes32.wrap(LibIpaMultipoint.commit(input_serialized.toArray()));
    }
}
