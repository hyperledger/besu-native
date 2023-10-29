package org.hyperledger.besu.ethereum.trie.verkle;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;
import org.apache.tuweni.rlp.RLPWriter;


public class BranchNode<V> implements Node<V> {
    private final Optional<Bytes> location;  // Location in the tree
    private final Bytes path;  // Extension path
    private final Optional<Bytes32> hash;  // vector commitment of children's commitments
    private Optional<Bytes> encodedValue = Optional.empty();
    private List<Node<V>> children;

    private boolean dirty = true;  // not persisted

    public BranchNode(
            final Bytes location,
            final Bytes32 hash,
            final Bytes path,
            final List<Node<V>> children) {
        assert (children.size() == maxChild());
        this.location = Optional.of(location);
        this.hash = Optional.of(hash);
        this.path = path;
        this.children = children;
    }

    public BranchNode(
            final Optional<Bytes> location,
            final Optional<Bytes32> hash,
            final Bytes path,
            final List<Node<V>> children) {
        assert (children.size() == maxChild());
        this.location = location;
        this.hash = hash;
        this.path = path;
        this.children = children;
    }

    public BranchNode(
            final Optional<Bytes> location,
            final Bytes path,
            final List<Node<V>> children) {
        assert (children.size() == maxChild());
        this.location = location;
        this.path = path;
        this.children = children;
        hash = Optional.empty();
    }

    public BranchNode(final Optional<Bytes> location, final Bytes path) {
        this.location = location;
        this.path = path;
        this.children = new ArrayList<>();
        for (int i = 0; i < maxChild(); i++) {
            children.add(NullNode.instance());
        }
        hash = Optional.of(EMPTY_HASH);
    }

    public static int maxChild() {
        return 256;
    }

    @Override
    public Node<V> accept(PathNodeVisitor<V> visitor, Bytes path) {
        return visitor.visit(this, path);
    }

    @Override
    public Node<V> accept(final NodeVisitor<V> visitor) {
        return visitor.visit(this);
    }

    public Node<V> child(final byte childIndex) {
        return children.get(Byte.toUnsignedInt(childIndex));
    }

    public void replaceChild(final byte index, final Node<V> childNode) {
        children.set(Byte.toUnsignedInt(index), childNode);
    }

    public Optional<Bytes32> getHash() {
        return hash;
    }

    public Node<V> replaceHash(Bytes32 hash) {
        return new BranchNode<V>(location, Optional.of(hash), path, children);
    }

    @Override
    public Optional<Bytes> getLocation() {
        return location;
    }

    public Bytes getPath() {
        return path;
    }

    @Override
    public Node<V> replacePath(Bytes path) {
        BranchNode<V> updatedNode = new BranchNode<V>(location, path, children);
        return updatedNode;
    }

    @Override
    public Bytes getEncodedValue() {
        if (encodedValue.isPresent()) {
            return encodedValue.get();
        }
        List<Bytes> values = Arrays.asList((Bytes) getHash().get(), getPath());
        Bytes result = RLP.encodeList(values, RLPWriter::writeValue);
        this.encodedValue = Optional.of(result);
        return result;
    }

    @Override
    public List<Node<V>> getChildren() {
        return children;
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
        final StringBuilder builder = new StringBuilder();
        builder.append("Branch:");
        for (int i = 0; i < maxChild(); i++) {
            final Node<V> child = child((byte) i);
            if (!Objects.equals(child, NullNode.instance())) {
                final String branchLabel = "[" + Integer.toHexString(i) + "] ";
                final String childRep = child.print().replaceAll("\n\t", "\n\t\t");
                builder.append("\n\t").append(branchLabel).append(childRep);
            }
        }
        return builder.toString();
    }
}
