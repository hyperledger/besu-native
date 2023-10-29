package org.hyperledger.besu.ethereum.trie.verkle;

import java.util.HashMap;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;


public class NodeLoaderMock implements NodeLoader {

    public HashMap<Bytes, Bytes> storage;
    
    public NodeLoaderMock(HashMap<Bytes, Bytes> storage) {
        this.storage = storage;
    }

    public Optional<Bytes> getNode(Bytes location, Bytes32 hash) {
        return Optional.ofNullable(storage.get(location));
    }
}
