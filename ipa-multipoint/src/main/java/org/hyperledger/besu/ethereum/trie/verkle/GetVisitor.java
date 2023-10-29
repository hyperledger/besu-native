package org.hyperledger.besu.ethereum.trie.verkle;

import org.apache.tuweni.bytes.Bytes;

public class GetVisitor<V> implements PathNodeVisitor<V> {
    private final Node<V> NULL_NODE_RESULT = NullNode.instance();

    @Override
    public Node<V> visit(final BranchNode<V> branchNode, final Bytes path) {
        final Bytes nodePath = branchNode.getPath();
        final Bytes commonPath = nodePath.commonPrefix(path);
        if (commonPath.compareTo(nodePath) != 0) {
            // path diverges before the end of the extension, so it cannot match
            return NULL_NODE_RESULT;
        }
        final Bytes pathSuffix = path.slice(commonPath.size());
        final byte childIndex = pathSuffix.get(0);
        return branchNode.child(childIndex).accept(this, pathSuffix.slice(1));
    }

    @Override
    public Node<V> visit(LeafNode<V> leafNode, Bytes path) {
        final Bytes leafPath = leafNode.getPath();
        final Bytes commonPath = leafPath.commonPrefix(path);
        if (commonPath.compareTo(leafPath) != 0) {
            return NULL_NODE_RESULT;
        }
        return leafNode;
    }

    @Override
    public Node<V> visit(NullNode<V> nullNode, Bytes path) {
        return NULL_NODE_RESULT;
    }
}
