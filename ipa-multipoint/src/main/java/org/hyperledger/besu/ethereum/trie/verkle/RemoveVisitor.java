package org.hyperledger.besu.ethereum.trie.verkle;

import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;

public class RemoveVisitor<V> implements PathNodeVisitor<V> {
    private final Node<V> NULL_NODE = NullNode.instance();

    protected Node<V> mergeSingleBranching(
            final Node<V> node,
            final Bytes commonPath,
            final Bytes pathSuffix, 
            final Bytes nodeSuffix) {
        final Node<V> updatedNode = node.replacePath(nodeSuffix.slice(1));
        // Should also add byte to location
        BranchNode<V> newBranchNode = new BranchNode<V>(node.getLocation(), commonPath);
        newBranchNode.replaceChild(nodeSuffix.get(0), updatedNode);
        final Node<V> insertedNode = newBranchNode.child(pathSuffix.get(0)).accept(this, pathSuffix.slice(1));
        newBranchNode.replaceChild(pathSuffix.get(0), insertedNode);
        return newBranchNode;
    }

    @Override
    public Node<V> visit(BranchNode<V> branchNode, Bytes path) {
        final Bytes leafPath = branchNode.getPath();
        final Bytes commonPath = leafPath.commonPrefix(path);
        if (commonPath.compareTo(leafPath) != 0) {
            return branchNode;
        }
        final Bytes pathSuffix = path.slice(commonPath.size());
        final byte childIndex = pathSuffix.get(0);
        final Node<V> childNode = branchNode.child(childIndex).accept(this, pathSuffix.slice(1));
        branchNode.replaceChild(childIndex, childNode);
        Node<V> resultNode = maybeFlatten(branchNode);
        return resultNode;
    }

    @Override
    public Node<V> visit(LeafNode<V> leafNode, Bytes path) {
        final Bytes nodePath = leafNode.getPath();
        final Bytes commonPath = nodePath.commonPrefix(path);
        if (commonPath.compareTo(nodePath) != 0) {
            return leafNode;
        }
        return NULL_NODE;
    }

    @Override
    public Node<V> visit(NullNode<V> nullNode, Bytes path) {
        return NULL_NODE;
    }

    protected Node<V> maybeFlatten(BranchNode<V> branchNode) {
        final Optional<Byte> onlyChildIndex = findOnlyChild(branchNode.getChildren());
        // Many children => return node as is
        if (!onlyChildIndex.isPresent()) {
            return branchNode;
        }
        // One child => merge with child: replace the path of the only child and return it
        final Node<V> onlyChild = branchNode.child(onlyChildIndex.get());
        final Bytes completePath = Bytes.concatenate(branchNode.getPath(), Bytes.of(onlyChildIndex.get()), onlyChild.getPath());
        return onlyChild.replacePath(completePath);
    }

    private Optional<Byte> findOnlyChild(final List<Node<V>> children) {
        Optional<Byte> onlyChildIndex = Optional.empty();
        for (int i = 0; i < children.size(); ++i) {
            if (children.get(i) != NULL_NODE) {
                if (onlyChildIndex.isPresent()) {
                    return Optional.empty();
                }
                onlyChildIndex = Optional.of((byte) i);
            }
        }
        return onlyChildIndex;
    }
}
