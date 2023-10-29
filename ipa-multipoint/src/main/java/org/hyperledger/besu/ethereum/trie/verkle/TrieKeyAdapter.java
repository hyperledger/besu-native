package org.hyperledger.besu.ethereum.trie.verkle;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;


public class TrieKeyAdapter {
    private final UInt256 VERSION_LEAF_KEY = UInt256.valueOf(0);
    private final UInt256 BALANCE_LEAF_KEY = UInt256.valueOf(1);
    private final UInt256 NONCE_LEAF_KEY = UInt256.valueOf(2);
    private final UInt256 CODE_KECCAK_LEAF_KEY = UInt256.valueOf(3);
    private final UInt256 CODE_SIZE_LEAF_KEY = UInt256.valueOf(4);
    private final UInt256 HEADER_STORAGE_OFFSET = UInt256.valueOf(64);
    private final UInt256 CODE_OFFSET = UInt256.valueOf(128);
    private final UInt256 VERKLE_NODE_WIDTH = UInt256.valueOf(256);
    private final UInt256 MAIN_STORAGE_OFFSET = UInt256.valueOf(256).pow(31);

    private Hasher<Bytes32> hasher;

    public TrieKeyAdapter(Hasher<Bytes32> hasher) {
        this.hasher = hasher;
    }

    Bytes32 swapLastByte(Bytes32 base, UInt256 subIndex) {
        Bytes32 key = (Bytes32) Bytes.concatenate(base.slice(0, 31), Bytes.of(subIndex.toBytes().get(31)));
        return key;
    }

    Bytes32 baseKey(Bytes32 address, UInt256 treeIndex) {
        int type_encoding = 2;
        UInt256 encoding = UInt256.valueOf(type_encoding).add(VERKLE_NODE_WIDTH.multiply(UInt256.valueOf(16)));

        Bytes32[] input = new Bytes32[] {
            Bytes32.rightPad(encoding.toBytes().slice(16, 16).reverse()),
            Bytes32.rightPad(address.slice(0, 16)),
            Bytes32.rightPad(address.slice(16, 16)),
            Bytes32.rightPad(treeIndex.toBytes().slice(16, 16).reverse()),
            Bytes32.rightPad(treeIndex.toBytes().slice(0, 16).reverse())
        };
        Bytes32 key = hasher.commit(input);
        return key;
    }

    public Bytes32 storageKey(Bytes32 address, UInt256 storageKey) {
        UInt256 headerOffset = CODE_OFFSET.subtract(HEADER_STORAGE_OFFSET);
        UInt256 offset = ((storageKey.compareTo(headerOffset) < 0) ? HEADER_STORAGE_OFFSET : MAIN_STORAGE_OFFSET);
        UInt256 pos = offset.add(storageKey);
        Bytes32 base = baseKey(address, pos.divide(VERKLE_NODE_WIDTH));
        Bytes32 key = swapLastByte(base, pos.mod(VERKLE_NODE_WIDTH));
        return key;
    }

    public Bytes32 codeChunkKey(Bytes32 address, UInt256 chunkId) {
        UInt256 pos = CODE_OFFSET.add(chunkId);
        Bytes32 base = baseKey(address, pos.divide(VERKLE_NODE_WIDTH));
        Bytes32 key = swapLastByte(base, pos.mod(VERKLE_NODE_WIDTH));
        return key;
    }

    // Headers
    Bytes32 headerKey(Bytes32 address, UInt256 leafKey) {
        Bytes32 base = baseKey(address, UInt256.valueOf(0));
        Bytes32 key = swapLastByte(base, leafKey);
        return key;
    }

    public Bytes32 versionKey(Bytes32 address) {
        return headerKey(address, VERSION_LEAF_KEY);
    }

    public Bytes32 balanceKey(Bytes32 address) {
        return headerKey(address, BALANCE_LEAF_KEY);
    }

    public Bytes32 nonceKey(Bytes32 address) {
        return headerKey(address, NONCE_LEAF_KEY);
    }

    public Bytes32 codeKeccakKey(Bytes32 address) {
        return headerKey(address, CODE_KECCAK_LEAF_KEY);
    }

    public Bytes32 codeSizeKey(Bytes32 address) {
        return headerKey(address, CODE_SIZE_LEAF_KEY);
    }
}