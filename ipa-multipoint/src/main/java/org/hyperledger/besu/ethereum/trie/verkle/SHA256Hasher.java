package org.hyperledger.besu.ethereum.trie.verkle;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;


public class SHA256Hasher implements Hasher<Bytes32> {
    @Override
    public Bytes32 commit(Bytes32[] inputs) {
        Bytes32 out;
        Bytes inputs_serialized = Bytes.concatenate(inputs);
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            out = Bytes32.wrap(sha256.digest(inputs_serialized.toArray()));
        } catch (NoSuchAlgorithmException e) {
            out = Bytes32.ZERO;
        }
        return out;
    }
}
