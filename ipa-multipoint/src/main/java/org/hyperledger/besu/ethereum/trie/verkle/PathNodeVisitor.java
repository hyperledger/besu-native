package org.hyperledger.besu.ethereum.trie.verkle;

import org.apache.tuweni.bytes.Bytes;

/**
 * Visit the trie with a path parameter.
 * 
 * The path parameter indicates the path visited in the Trie.
 * As Nodes are (mostly) immutable, visiting a Node returns a (possibly) new Node that should replace the old one.
 * 
 */
public interface PathNodeVisitor<V> {

    Node<V> visit(BranchNode<V> branchNode, Bytes path);

    Node<V> visit(LeafNode<V> leafNode, Bytes path);

    Node<V> visit(NullNode<V> nullNode, Bytes path);
}