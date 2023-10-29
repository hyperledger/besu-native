package org.hyperledger.besu.ethereum.trie.verkle;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

public class StoredNodeFactory<V> implements NodeFactory<V>{
    private NodeLoader nodeLoader;
    private final Function<Bytes, V> valueDeserializer;

    public StoredNodeFactory(NodeLoader nodeLoader, Function<Bytes, V> valueDeserializer) {
        this.nodeLoader = nodeLoader;
        this.valueDeserializer = valueDeserializer;
    }

    public Optional<Node<V>> retrieve(final Bytes location, final Bytes32 hash) {
        Optional<Bytes> optionalEncodedValues = nodeLoader.getNode(location, hash);
        if (optionalEncodedValues.isEmpty()) {
            return Optional.empty();
        }
        Bytes encodedValues = optionalEncodedValues.get();
        List<Bytes> values = RLP.decodeToList(encodedValues, reader -> reader.readValue().copy());
        Bytes hashOrEmpty = values.get(0);
        if (hashOrEmpty.isEmpty() && values.size() == 1) {  // NullNode
            return Optional.of(NullNode.instance()); 
        } 
        Bytes path = (Bytes) values.get(1);
        if (hashOrEmpty.isEmpty() && values.size() > 1) {  // LeafNode
            V value = valueDeserializer.apply((Bytes) values.get(2));
            return Optional.of(createLeafNode(location, path, value));
        }
        if (!hashOrEmpty.isEmpty()) {  // BranchNode
            Bytes32 savedHash = (Bytes32) hashOrEmpty;
            return Optional.of(createBranchNode(location, savedHash, path));
        }
        return Optional.empty();  // should not be here.
    }

    protected BranchNode<V> createBranchNode(Bytes location, Bytes32 hash, Bytes path) {
        int nChild = BranchNode.maxChild();
        ArrayList<Node<V>> children = new ArrayList<Node<V>>(nChild);
        for (int i=0; i < nChild; i++) {
            Optional<Node<V>> child = retrieve(Bytes.concatenate(location, Bytes.of(i)), hash);
            children.add(child.orElse(NullNode.instance()));
        }
        return new BranchNode<V>(location, hash, path, children);
    }

    protected LeafNode<V> createLeafNode(Bytes location, Bytes path, V value) {
        return new LeafNode<V>(Optional.of(location), value, path);
    }
    
}
