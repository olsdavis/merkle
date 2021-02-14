package me.olsd.merkle

import java.util.Arrays
import java.security.MessageDigest
import java.nio.charset.StandardCharsets

/**
 * Represents a cryptographic hash function which returns its hash as an
 * array of bytes.
 */
type Hasher = Array[Byte] => Array[Byte]

/**
 * Represents a type that can be hashed to a byte array.
 */
trait ArrayHashable:
  extension(s: String)
    def asBytes: Array[Byte] =
      StandardCharsets.UTF_8.encode(s).array
  
  /**
   * @return the representation of the current instance as a byte array.
   */
  def asBytes: Array[Byte]

/**
 * Represents a Merkle tree, which produces a single hash from a collection of items.
 * 
 * @param hasher the hash function to use for this Merkle tree. It usually remains consistant
 *  at all levels of the tree. SHA-512 by default.
 */
sealed trait MerkleTree[A <: ArrayHashable](using hasher: Hasher):
  /**
   * Use SHA-512 by default.
   */
  given Hasher = x => MessageDigest.getInstance("SHA-512").digest(x)
  /**
   * @return a byte array containing the bytes of the hash of the current
   *  Merkle tree.
   */
  def hash: Array[Byte] = this match
    case n @ Node(_, _) => n.hashVal
    case l @ Leaf(_) => l.hashVal
    case Empty => Array()

  /**
   * @return `true` if the current Merkle tree is empty.
   */
  def isEmpty: Boolean = this match
    case Empty => true
    case _ => false

/**
 * Represents a node with a left subtree `left` and a right subtree `right`.
 * 
 * @param left the left subtree
 * @param right the right subtree
 * @param hasher the hash function to use
 * 
 * @tparam A the type of elements that the tree holds; must be representable hashable to a byte array.
 */
case class Node[A <: ArrayHashable](left: MerkleTree[A], right: MerkleTree[A])(using hasher: Hasher) 
  extends MerkleTree[A]:
  
  private[merkle] lazy val hashVal: Array[Byte] =
    if left.isEmpty then // usually, the right subtree is the one that can be empty
      right.hash
    else if right.isEmpty then
      left.hash
    else
      val x = left.hash
      val y = right.hash
      val arr = Arrays.copyOf(x, x.length + y.length)
      System.arraycopy(y, 0, arr, x.length, y.length)
      arr

/**
 * Represents a leaf containing an element `block` of type `A`.
 * 
 * @param block the element to hold in this instance of `Leaf`
 * @param hasher the hash function to use
 * 
 * @tparam A the type of objects held by the tree (and the current leaf)
 */
case class Leaf[A <: ArrayHashable](block: A)(using hasher: Hasher) extends MerkleTree[A]:
  private[merkle] lazy val hashVal: Array[Byte] = hasher(block.asBytes)

/**
 * Represents an empty leaf.
 */
case class Empty[A <: ArrayHashable]()(using hasher: Hasher) extends MerkleTree[A]

object MerkleTree:
  /**
   * Builds a Merkle tree from the list of elements `ls`. Adds
   * additional `Empty` elements to make the tree complete.
   * 
   * @param ls the list of elements
   * @param hasher the hash function to use
   * 
   * @return a complete Merkle tree built from the elements of `ls`.
   */
  def tree[A <: ArrayHashable](ls: List[A])(using hasher: Hasher): MerkleTree[A] =
    def build(xs: List[A]): MerkleTree[A] = xs.length match
      case 0 => new Empty[A]
      case 1 => new Leaf[A](xs.head)
      case _ =>
        val (l, r) = xs.splitAt(Math.ceil(xs.length.toDouble / 2d).toInt)
        new Node[A](build(l), build(r))
    build(ls)

  /**
   * Hashes the provided elements of list `ls`, as a Merkle tree would hash the
   * elements.
   * 
   * @param ls the list of elements
   * @param hasher the hash function to use
   * 
   * @return the hash from the provided elements.
   */
  def hash[A <: ArrayHashable](ls: List[A])(using hasher: Hasher): Array[Byte] = tree(ls).hash
