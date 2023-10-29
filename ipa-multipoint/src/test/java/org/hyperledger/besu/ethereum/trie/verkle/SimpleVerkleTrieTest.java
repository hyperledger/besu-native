package org.hyperledger.besu.ethereum.trie.verkle;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class SimpleVerkleTrieTest {
    
    @Test
    public void testEmptyTrie() {
        SimpleVerkleTrie<Bytes32, Bytes32> trie = new SimpleVerkleTrie<Bytes32, Bytes32>();
        Node<Bytes32> root = trie.getRoot();
        assertThat(root).as("Empty Trie is a NullNode").isInstanceOf(NullNode.class);
        assertThat(trie.getRootHash()).as("Retrieve root hash").isEqualByComparingTo(Bytes32.ZERO);
    }

    @Test
    public void testOneValue() {
        SimpleVerkleTrie<Bytes32, Bytes32> trie = new SimpleVerkleTrie<Bytes32, Bytes32>();
        Bytes32 key = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        Bytes32 value = Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
        trie.put(key, value);
        Node<Bytes32> root = trie.getRoot();
        assertThat(root).as("One value trie's root is a LeafNode").isInstanceOf(LeafNode.class);
        assertThat(trie.get(key)).as("Get one value should be the inserted value").isEqualTo(Optional.of(value));
        Bytes32 expectedRootHash = Bytes32.fromHexString("0x0919cd252910ea715338943554cdf800fe9b951f47182f8d7ae5be9ce4f5ec65");
        assertThat(trie.getRootHash()).as("Retrieve root hash").isEqualByComparingTo(expectedRootHash);
    }

    @Test
    public void testTwoValuesAtSameStem() throws Exception {
        SimpleVerkleTrie<Bytes32, Bytes32> trie = new SimpleVerkleTrie<Bytes32, Bytes32>();
        Bytes32 key1 = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        Bytes32 value1 = Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
        Bytes32 key2 = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddee00");
        Bytes32 value2 = Bytes32.fromHexString("0x0100000000000000000000000000000000000000000000000000000000000000");
        Bytes path = Bytes.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddee");
        byte index1 = key1.get(31);
        byte index2 = key2.get(31);
        byte index3 = (byte) 2;
        trie.put(key1, value1);
        trie.put(key2, value2);
        Node<Bytes32> root = trie.getRoot();
        assertThat(root).as("Many values trie is a BranchNode").isInstanceOf(BranchNode.class);
        BranchNode<Bytes32> branchRoot = (BranchNode<Bytes32>) root;
        assertThat(branchRoot.child(index1)).as("Child at index of first key is a LeafNode").isInstanceOf(LeafNode.class);
        assertThat(branchRoot.child(index2)).as("Child at index of second key is a LeafNode").isInstanceOf(LeafNode.class);
        assertThat(branchRoot.child(index3)).as("Child at another index is a NullNode").isInstanceOf(NullNode.class);
        assertThat(branchRoot.getPath()).as("Path is the common stem").isEqualTo(path);
        assertThat(trie.get(key1)).as("Retrieve first value").isEqualTo(Optional.of(value1));
        assertThat(trie.get(key2)).as("Retrieve second value").isEqualTo(Optional.of(value2));
        Bytes32 expectedRootHash = Bytes32.fromHexString("0x0664595728997574720abefebd044352ab20b353f5c8bdb5558d1f17d71d171c");
        assertThat(trie.getRootHash()).as("Retrieve root hash").isEqualByComparingTo(expectedRootHash);
    }

    @Test
    public void testTwoValuesAtDifferentIndex() throws Exception {
        SimpleVerkleTrie<Bytes32, Bytes32> trie = new SimpleVerkleTrie<Bytes32, Bytes32>();
        Bytes32 key1 = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        Bytes32 value1 = Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
        Bytes32 key2 = Bytes32.fromHexString("0xff112233445566778899aabbccddeeff00112233445566778899aabbccddee00");
        Bytes32 value2 = Bytes32.fromHexString("0x0100000000000000000000000000000000000000000000000000000000000000");
        Bytes path = Bytes.fromHexString("0x");
        byte index1 = key1.get(0);
        byte index2 = key2.get(0);
        byte index3 = (byte) 2;
        trie.put(key1, value1);
        trie.put(key2, value2);
        Node<Bytes32> root = trie.getRoot();
        assertThat(root).as("Many values trie's root is a BranchNode").isInstanceOf(BranchNode.class);
        BranchNode<Bytes32> branchRoot = (BranchNode<Bytes32>) root;
        assertThat(branchRoot.child(index1)).as("Child at index of first key is a LeafNode").isInstanceOf(LeafNode.class);
        assertThat(branchRoot.child(index2)).as("Child at index of second key is a LeafNode").isInstanceOf(LeafNode.class);
        assertThat(branchRoot.child(index3)).as("Child at another index is a NullNode").isInstanceOf(NullNode.class);
        assertThat(branchRoot.getPath()).as("Path is the common stem").isEqualTo(path);
        assertThat(trie.get(key1)).as("Retrieve first value").isEqualTo(Optional.of(value1));
        assertThat(trie.get(key2)).as("Retrieve second value").isEqualTo(Optional.of(value2));
        Bytes32 expectedRootHash = Bytes32.fromHexString("0x18344e51ea6f0699b227f8a00871547430aebba457d4f7d0830315e7b683bba1");
        assertThat(trie.getRootHash()).as("Retrieve root hash").isEqualByComparingTo(expectedRootHash);
    }

    @Test
    public void testTwoValuesWithDivergentStemsAtDepth2() throws Exception {
        SimpleVerkleTrie<Bytes32, Bytes32> trie = new SimpleVerkleTrie<Bytes32, Bytes32>();
        Bytes32 key1 = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        Bytes32 value1 = Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
        Bytes32 key2 = Bytes32.fromHexString("0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddee");
        Bytes32 value2 = Bytes32.fromHexString("0x0100000000000000000000000000000000000000000000000000000000000000");
        Bytes path = Bytes.fromHexString("0x00");
        byte index1 = key1.get(1);
        byte index2 = key2.get(1);
        byte index3 = (byte) 0;
        trie.put(key1, value1);
        trie.put(key2, value2);
        Node<Bytes32> root = trie.getRoot();
        assertThat(root).as("Many values trie's root is a BranchNode").isInstanceOf(BranchNode.class);
        BranchNode<Bytes32> branchRoot = (BranchNode<Bytes32>) root;
        assertThat(branchRoot.child(index1)).as("Child at index of first key is a LeafNode").isInstanceOf(LeafNode.class);
        assertThat(branchRoot.child(index2)).as("Child at index of second key is a LeafNode").isInstanceOf(LeafNode.class);
        assertThat(branchRoot.child(index3)).as("Child at another index is a NullNode").isInstanceOf(NullNode.class);
        assertThat(branchRoot.getPath()).as("Path is the common stem").isEqualTo(path);
        assertThat(trie.get(key1)).as("Retrieve first value").isEqualTo(Optional.of(value1));
        assertThat(trie.get(key2)).as("Retrieve second value").isEqualTo(Optional.of(value2));
        Bytes32 expectedRootHash = Bytes32.fromHexString("0x0c0f178f291e1113c56903cfcfd7023e64550058127d8de4995461760262a7be");
        assertThat(trie.getRootHash()).as("Retrieve root hash").isEqualByComparingTo(expectedRootHash);
    }

    @Test
    public void testDeleteTwoValuesAtSameStem() throws Exception {
        SimpleVerkleTrie<Bytes32, Bytes32> trie = new SimpleVerkleTrie<Bytes32, Bytes32>();
        Bytes32 key1 = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        Bytes32 value1 = Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000001");
        Bytes32 key2 = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddee00");
        Bytes32 value2 = Bytes32.fromHexString("0x0100000000000000000000000000000000000000000000000000000000000002");
        trie.put(key1, value1);
        trie.put(key2, value2);
        trie.remove(key1);
        assertThat(trie.get(key1)).as("Make sure value is deleted").isEqualTo(Optional.empty());
        assertThat(trie.getRoot()).as("One value => flatten to one LeafNode").isInstanceOf(LeafNode.class);
        trie.remove(key2);
        assertThat(trie.get(key2)).as("Make sure value is deleted").isEqualTo(Optional.empty());
        assertThat(trie.getRoot()).as("No value => back to NullNode root").isInstanceOf(NullNode.class);
    }

    @Test
    public void testDeleteTwoValuesAtDifferentIndex() throws Exception {
        SimpleVerkleTrie<Bytes32, Bytes32> trie = new SimpleVerkleTrie<Bytes32, Bytes32>();
        Bytes32 key1 = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        Bytes32 value1 = Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
        Bytes32 key2 = Bytes32.fromHexString("0xff112233445566778899aabbccddeeff00112233445566778899aabbccddee00");
        Bytes32 value2 = Bytes32.fromHexString("0x0100000000000000000000000000000000000000000000000000000000000000");
        trie.put(key1, value1);
        trie.put(key2, value2);
        trie.remove(key1);
        assertThat(trie.get(key1)).as("Make sure value is deleted").isEqualTo(Optional.empty());
        assertThat(trie.getRoot()).as("One value => flatten to one LeafNode").isInstanceOf(LeafNode.class);
        trie.remove(key2);
        assertThat(trie.get(key2)).as("Make sure value is deleted").isEqualTo(Optional.empty());
        assertThat(trie.getRoot()).as("No value => back to NullNode root").isInstanceOf(NullNode.class);
    }

    @Test
    public void testDeleteTwoValuesWithDivergentStemsAtDepth2() throws Exception {
        SimpleVerkleTrie<Bytes32, Bytes32> trie = new SimpleVerkleTrie<Bytes32, Bytes32>();
        Bytes32 key1 = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        Bytes32 value1 = Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
        Bytes32 key2 = Bytes32.fromHexString("0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddee");
        Bytes32 value2 = Bytes32.fromHexString("0x0100000000000000000000000000000000000000000000000000000000000000");
        trie.put(key1, value1);
        trie.put(key2, value2);
        trie.remove(key1);
        assertThat(trie.get(key1)).as("Make sure value is deleted").isEqualTo(Optional.empty());
        assertThat(trie.getRoot()).as("One value => flatten to one LeafNode").isInstanceOf(LeafNode.class);
        trie.remove(key2);
        assertThat(trie.get(key2)).as("Make sure value is deleted").isEqualTo(Optional.empty());
        assertThat(trie.getRoot()).as("No value => back to NullNode root").isInstanceOf(NullNode.class);
    }

    @Test
    public void testDeleteThreeValues() throws Exception {
        SimpleVerkleTrie<Bytes32, Bytes32> trie = new SimpleVerkleTrie<Bytes32, Bytes32>();
        Bytes32 key1 = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        Bytes32 value1 = Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
        Bytes32 key2 = Bytes32.fromHexString("0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddee");
        Bytes32 value2 = Bytes32.fromHexString("0x0200000000000000000000000000000000000000000000000000000000000000");
        Bytes32 key3 = Bytes32.fromHexString("0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddff");
        Bytes32 value3 = Bytes32.fromHexString("0x0300000000000000000000000000000000000000000000000000000000000000");
        trie.put(key1, value1);
        trie.put(key2, value2);
        trie.put(key3, value3);
        trie.remove(key3);
        assertThat(trie.get(key3)).as("Make sure value is deleted").isEqualTo(Optional.empty());
        assertThat(trie.get(key2)).as("Retrieve second value").isEqualTo(Optional.of(value2));
        trie.remove(key2);
        assertThat(trie.get(key2)).as("Make sure value is deleted").isEqualTo(Optional.empty());
        assertThat(trie.get(key1)).as("Retrieve first value").isEqualTo(Optional.of(value1));
        trie.remove(key1);
        assertThat(trie.get(key1)).as("Make sure value is deleted").isEqualTo(Optional.empty());
    }

    @Test
    public void testDeleteThreeValuesWithFlattening() throws Exception {
        SimpleVerkleTrie<Bytes32, Bytes32> trie = new SimpleVerkleTrie<Bytes32, Bytes32>();
        Bytes32 key1 = Bytes32.fromHexString("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        Bytes32 value1 = Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
        Bytes32 key2 = Bytes32.fromHexString("0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddee");
        Bytes32 value2 = Bytes32.fromHexString("0x0200000000000000000000000000000000000000000000000000000000000000");
        Bytes32 key3 = Bytes32.fromHexString("0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddff");
        Bytes32 value3 = Bytes32.fromHexString("0x0300000000000000000000000000000000000000000000000000000000000000");
        trie.put(key1, value1);
        trie.put(key2, value2);
        trie.put(key3, value3);
        assertThat(trie.getRoot().getPath()).as("Initial extension path").isEqualTo(Bytes.fromHexString("0x00"));
        trie.remove(key1);
        assertThat(trie.get(key1)).as("Make sure value is deleted").isEqualTo(Optional.empty());
        assertThat(trie.getRoot().getPath()).as("First flatten: extension path").isEqualTo(Bytes.fromHexString("0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccdd"));
        assertThat(trie.get(key2)).as("Retrieve second value").isEqualTo(Optional.of(value2));
        trie.remove(key2);
        assertThat(trie.get(key2)).as("Make sure value is deleted").isEqualTo(Optional.empty());
        assertThat(trie.getRoot().getPath()).as("Second flatten: extension path").isEqualTo(Bytes.fromHexString("0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddff"));
        assertThat(trie.get(key3)).as("Retrieve first value").isEqualTo(Optional.of(value3));
        trie.remove(key3);
        assertThat(trie.get(key3)).as("Make sure value is deleted").isEqualTo(Optional.empty());
    }
}
