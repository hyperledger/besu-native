package org.hyperledger.besu.ethereum.trie.verkle;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;
import org.apache.tuweni.rlp.RLPWriter;

public class LeafNode<V> implements Node<V>{
    private final Optional<Bytes> location;
    protected final V value;
    private final Bytes path;
    private final Optional<Bytes32> hash;
    private Optional<Bytes> encodedValue = Optional.empty();
    private final Function<V, Bytes> valueSerializer;
    private boolean dirty = true;

    public LeafNode(
            final Optional<Bytes> location,
            final V value,
            final Bytes path,
            final Optional<Bytes32> hash) {
        this.location = location;
        this.value = value;
        this.path = path;
        this.hash = hash;
        this.valueSerializer = val -> (Bytes) val;
    }

    public LeafNode(
            final Optional<Bytes> location,
            final V value,
            final Bytes path) {
        this.location = location;
        this.path = path;
        this.value = value;
        this.hash = Optional.empty();
        this.valueSerializer = val -> (Bytes) val;
    }

    public LeafNode(final V value, final Bytes path) {
        location = Optional.empty();
        this.value = value;
        this.path = path;
        hash = Optional.empty();
        this.valueSerializer = val -> (Bytes) val;
    }

    @Override
    public Node<V> accept(final PathNodeVisitor<V> visitor, final Bytes path) {
        return visitor.visit(this, path);
    }

    @Override
    public Node<V> accept(final NodeVisitor<V> visitor) {
        return visitor.visit(this);
    }

    @Override
    public Optional<V> getValue() {
        return Optional.ofNullable(value);
    }

    @Override
    public Optional<Bytes> getLocation() {
        return location;
    }

    @Override
    public Bytes getPath() {
        return path;
    }

    @Override
    public List<Node<V>> getChildren() {
        throw new UnsupportedOperationException("LeafNode does not have children.");
    }

    @Override
    public Optional<Bytes32> getHash() {
        return hash;
    }

    public Node<V> replaceHash(Bytes32 hash) {
        return new LeafNode<V>(location, value, path, Optional.of(hash));
    }

    @Override
    public Node<V> replacePath(Bytes path) {
        return new LeafNode<V>(location, value, path, hash);
    }

    @Override
    public Bytes getEncodedValue() {
        if (encodedValue.isPresent()) {
            return encodedValue.get();
        }
        Bytes encodedVal = getValue().isPresent() ? valueSerializer.apply(getValue().get()) : Bytes.EMPTY;
        List<Bytes> values = Arrays.asList(Bytes.EMPTY, getPath(), encodedVal);
        Bytes result = RLP.encodeList(values, RLPWriter::writeValue);
        this.encodedValue = Optional.of(result);
        return result;
    }

    @Override
    public void markDirty() {
        dirty = true;
    }

    @Override
    public boolean isDirty() {
        return dirty;
    }

    @Override
    public String print() {
        return "Leaf:"
            + getValue().map(Object::toString).orElse("empty");
    }
} 
