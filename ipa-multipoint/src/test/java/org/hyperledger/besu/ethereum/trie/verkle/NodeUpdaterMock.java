package org.hyperledger.besu.ethereum.trie.verkle;

import java.util.HashMap;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class NodeUpdaterMock implements NodeUpdater {

    public HashMap<Bytes, Bytes> storage;
    
    public NodeUpdaterMock() {
        this.storage = new HashMap<Bytes, Bytes>();
    }

    public NodeUpdaterMock(HashMap<Bytes, Bytes> storage) {
        this.storage = storage;
    }

    public void store(Bytes location, Bytes32 hash, Bytes value) {
        storage.put(location, value);
    }
}
