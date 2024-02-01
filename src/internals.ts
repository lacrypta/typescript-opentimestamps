// typescript-opentimestamps: An OpenTimestamps client written in TypeScript.
// Copyright (C) 2024  La Crypta
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

/**
 * This module exposes internal organizational functions.
 *
 * @packageDocumentation
 * @module
 */

'use strict';

import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha1 } from '@noble/hashes/sha1';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';

import type { Leaf, MergeMap, MergeSet, Op, Timestamp, Tree } from './types';

import {
  textEncoder,
  uint8ArrayCompare,
  uint8ArrayConcat,
  uint8ArrayFromHex,
  uint8ArrayReversed,
  uint8ArrayToHex,
} from './utils';

/**
 * A simple type alias to refer to a list of {@link Op | operations}.
 *
 */
export type Ops = Op[];

/**
 * A "Path" consists of a list of {@link Ops | operations} with a corresponding {@link Leaf}, representing a full path
 * from the message to attest to an attestation proper.
 *
 */
export type Path = {
  /**
   * The {@link Ops} in this {@link Path}.
   *
   */
  operations: Ops;

  /**
   * The {@link Leaf} in this {@link Path}.
   *
   */
  leaf: Leaf;
};

/**
 * A simple type alias to refer to a list of {@link Path}s.
 *
 */
export type Paths = Path[];

/**
 * A simple type alias to refer to a {@link Tree}'s edges.
 *
 */
export type Edge = [Op, Tree];

/**
 * Tags are single-byte values used to indicate the structural components found in an `ots` file.
 *
 */
export enum Tag {
  /**
   * Tag indicating that the next element in the `ots` file is an attestation.
   *
   */
  attestation = 0x00,

  /**
   * Tag indicating that the next element in the `ots` file is a SHA1 {@link Op}.
   *
   */
  sha1 = 0x02,

  /**
   * Tag indicating that the next element in the `ots` file is a RIPEMD160 {@link Op}.
   *
   */
  ripemd160 = 0x03,

  /**
   * Tag indicating that the next element in the `ots` file is a SHA256 {@link Op}.
   *
   */
  sha256 = 0x08,

  /**
   * Tag indicating that the next element in the `ots` file is a KECCAK256 {@link Op}.
   *
   */
  keccak256 = 0x67,

  /**
   * Tag indicating that the next element in the `ots` file is an append {@link Op}.
   *
   */
  append = 0xf0,

  /**
   * Tag indicating that the next element in the `ots` file is a prepend {@link Op}.
   *
   */
  prepend = 0xf1,

  /**
   * Tag indicating that the next element in the `ots` file is a reverse {@link Op}.
   *
   */
  reverse = 0xf2,

  /**
   * Tag indicating that the next element in the `ots` file is a "hexlify" {@link Op}.
   *
   */
  hexlify = 0xf3,
}

/**
 * Headers are used to identify {@link Leaf} types in an `ots` file.
 *
 * Headers are 8-byte sequences, and each {@link Leaf} type has an associated one.
 * Unknown {@link Leaf | leaves} carry their `header` with them.
 *
 */
export enum LeafHeader {
  /**
   * 8-byte header describing a Bitcoin {@link Leaf}.
   *
   * This header consists of bytes `05:88:96:0d:73:d7:19:01`.
   *
   */
  bitcoin = '0588960d73d71901',

  /**
   * 8-byte header describing a Litecoin {@link Leaf}.
   *
   * This header consists of bytes `06:86:9a:0d:73:d7:1b:45`.
   *
   */
  litecoin = '06869a0d73d71b45',

  /**
   * 8-byte header describing an Ethereum {@link Leaf}.
   *
   * This header consists of bytes `30:fe:80:87:b5:c7:ea:d7`.
   *
   */
  ethereum = '30fe8087b5c7ead7',

  /**
   * 8-byte header describing a pending {@link Leaf}.
   *
   * This header consists of bytes `83:df:e3:0d:2e:f9:0c:8e`.
   *
   */
  pending = '83dfe30d2ef90c8e',
}

/**
 * This 31-byte header is used to identify `ots` files, it is simply a magic constant.
 *
 * The header consists of bytes `00:4f:70:65:6e:54:69:6d:65:73:74:61:6d:70:73:00:00:50:72:6f:6f:66:00:bf:89:e2:e8:84:e8:92:94`.
 *
 */
export const magicHeader: Uint8Array = uint8ArrayFromHex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294',
);

/**
 * This constant is used to indicate that the next element in an `ots` file is _not_ the last one.
 *
 */
export const nonFinal: number = 0xff;

/**
 * Execute the given {@link Op} on the given message, and return the result.
 *
 * Operation execution proceeds according to `op.type`:
 *
 * - If `sha1`: the `SHA1` hash of `msg` is returned.
 * - If `ripemd160`: the `RIPEMD160` hash of `msg` is returned.
 * - If `sha256`: the `SHA256` hash of `msg` is returned.
 * - If `keccak256`: the `KECCAK256` hash of `msg` is returned.
 * - If `append`: `msg` is returned, with `op.operand` tucked at the end.
 * - If `prepend`: `op.operand` is returned, with `msg` tucked at the end.
 * - If `reverse`: `msg` is returned, but reversed byte-to-byte.
 * - If `hexlify`: the ASCII hex representation of `msg`'s content is returned (nb. this will have double the length, as each byte in `msg` will be converted to _two_ hex digits).
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { callOp } from './src/internals';
 *
 * console.log(callOp({ type: 'sha1' }, Uint8Array.of(1, 2, 3)));                                      // Uint8Array(20) [ 112, 55, ..., 207 ]
 * console.log(callOp({ type: 'ripemd160' }, Uint8Array.of(1, 2, 3)));                                 // Uint8Array(20) [ 121, 249, ..., 87 ]
 * console.log(callOp({ type: 'sha256' }, Uint8Array.of(1, 2, 3)));                                    // Uint8Array(32) [ 3, 144, ..., 129 ]
 * console.log(callOp({ type: 'keccak256' }, Uint8Array.of(1, 2, 3)));                                 // Uint8Array(32) [ 241, 136, ..., 57 ]
 * console.log(callOp({ type: 'append', operand: Uint8Array.of(4, 5, 6) }, Uint8Array.of(1, 2, 3)));   // Uint8Array(6) [ 1, 2, 3, 4, 5, 6 ]
 * console.log(callOp({ type: 'prepend', operand: Uint8Array.of(4, 5, 6) }, Uint8Array.of(1, 2, 3)));  // Uint8Array(6) [ 4, 5, 6, 1, 2, 3 ]
 * console.log(callOp({ type: 'reverse' }, Uint8Array.of(1, 2, 3)));                                   // Uint8Array(3) [ 3, 2, 1 ]
 * console.log(callOp({ type: 'hexlify' }, Uint8Array.of(1, 2, 3)));                                   // Uint8Array(6) [ 48, 49, 48, 50, 48, 51 ]
 * ```
 *
 * @param op - The operation to execute.
 * @param msg - The message to execute it on.
 * @returns The resulting message.
 */
export function callOp(op: Op, msg: Uint8Array): Uint8Array {
  switch (op.type) {
    case 'sha1':
      return sha1(msg);
    case 'ripemd160':
      return ripemd160(msg);
    case 'sha256':
      return sha256(msg);
    case 'keccak256':
      return keccak_256(msg);
    case 'append':
      return Uint8Array.of(...msg, ...op.operand);
    case 'prepend':
      return Uint8Array.of(...op.operand, ...msg);
    case 'reverse':
      return uint8ArrayReversed(msg);
    case 'hexlify':
      return textEncoder.encode(uint8ArrayToHex(msg));
  }
}

/**
 * Execute the given sequence of {@link Ops | operations}, in order, on the given message, and return the result.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { callOps } from './src/internals';
 *
 * console.log(callOps([], Uint8Array.of()));  // Uint8Array(0) []
 * console.log(callOps([
 *   { type: 'sha1' },
 *   { type: 'prepend', operand: Uint8Array.of(1, 2, 3) },
 *   { type: 'append', operand: Uint8Array.of(4, 5, 6) },
 * ], Uint8Array.of()));                       // Uint8Array(26) [ 1, 2, 3, 218, 57, ..., 9, 4, 5, 6 ]
 * ```
 *
 * @param ops - The sequence of operations to execute.
 * @param msg - The message to execute them on.
 * @returns The resulting message.
 */
export function callOps(ops: Ops, msg: Uint8Array): Uint8Array {
  return ops.reduce((prevMsg: Uint8Array, op: Op): Uint8Array => callOp(op, prevMsg), msg);
}

/**
 * Compare two {@link Leaf | Leaves}, and return the comparison result.
 *
 * {@link Leaf} comparison works as follows:
 *
 * 1. First, the {@link Leaf | Leaves}' _headers_ (cf. {@link LeafHeader}) are compared, if they're different, their difference is returned as the result.
 * 2. If the headers are equal, we proceed according to the {@link Leaf}'s `type`:
 *     - If `unknown`, the `payload`s are compared lexicographically (cf. {@link uint8ArrayCompare}), and that result returned.
 *     - If {@link LeafHeader.pending}, their `url`s are compared lexicographically, and that result returned.
 *     - If {@link LeafHeader.bitcoin}, {@link LeafHeader.litecoin}, or {@link LeafHeader.ethereum}, their `height`s are compared, and that result returned.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { compareLeaves } from './src/internals';
 *
 * console.log(compareLeaves({ type: 'bitcoin', height: 123 }, { type: 'litecoin', height: 123 })); // -1
 * console.log(compareLeaves({ type: 'litecoin', height: 123 }, { type: 'bitcoin', height: 123 })); //  1
 * console.log(compareLeaves({ type: 'bitcoin', height: 123 }, { type: 'bitcoin', height: 456 }));  // -333
 * console.log(compareLeaves({ type: 'bitcoin', height: 456 }, { type: 'bitcoin', height: 123 }));  //  333
 *
 * console.log(compareLeaves(
 *   { type: 'pending', url: new URL('https://example.com/a') },
 *   { type: 'pending', url: new URL('https://example.com/b') },
 * ));                                                                                              // -1
 * console.log(compareLeaves(
 *   { type: 'pending', url: new URL('https://example.com') },
 *   { type: 'pending', url: new URL('https://example.com') },
 * ));                                                                                              //  0
 * console.log(compareLeaves(
 *   { type: 'pending', url: new URL('https://example.com/b') },
 *   { type: 'pending', url: new URL('https://example.com/a') },
 * ));                                                                                              //  1
 *
 * console.log(compareLeaves(
 *   { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(1, 2, 3) },
 *   { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(4, 5, 6) },
 * ));                                                                                              // -3
 * console.log(compareLeaves(
 *   { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() },
 *   { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() },
 * ));                                                                                              //  0
 * console.log(compareLeaves(
 *   { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(4, 5, 6) },
 *   { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(1, 2, 3) },
 * ));                                                                                              //  3
 * ```
 *
 * @param left - The first leaf to compare.
 * @param right - The second leaf to compare.
 * @returns `0` if both {@link Leaf | Leaves} are equal, a positive number if the `left` one is bigger than the `right` one, or a negative number otherwise.
 */
export function compareLeaves(left: Leaf, right: Leaf): number {
  const headerCompare: number = uint8ArrayCompare(
    'unknown' == left.type ? left.header : uint8ArrayFromHex(LeafHeader[left.type as keyof typeof LeafHeader]),
    'unknown' == right.type ? right.header : uint8ArrayFromHex(LeafHeader[right.type as keyof typeof LeafHeader]),
  );
  if (0 === headerCompare) {
    switch (left.type) {
      case 'pending':
        return uint8ArrayCompare(
          textEncoder.encode(left.url.toString()),
          textEncoder.encode((right as { url: URL }).url.toString()),
        );
      case 'unknown':
        return uint8ArrayCompare(left.payload, (right as { payload: Uint8Array }).payload);
      default:
        return left.height - (right as { height: number }).height;
    }
  }
  return headerCompare;
}

/**
 * Compare two {@link Op}s, and return the comparison result.
 *
 * {@link Op} comparison works as follows:
 * 1. First the {@link Op}'s _tags_ are compared (cf. {@link Tag}), if they're different, their difference is returned as the result.
 * 2. If the tags are equal, we proceed according to the {@link Op}'s `type`:
 *     - If `append` or `prepend`, the `operand`s are compared lexicographically (cf. {@link uint8ArrayCompare}), and that result returned.
 *     - Otherwise, the result from step **1** is returned.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { compareOps } from ''./src/internals';
 *
 * console.log(compareOps({ type: 'sha1' }, { type: 'ripemd160' })); // -1
 * console.log(compareOps({ type: 'sha1' }, { type: 'sha1' }));      //  0
 * console.log(compareOps({ type: 'ripemd160' }, { type: 'sha1' })); //  1
 * console.log(compareOps(
 *   { type: 'append', operand: Uint8Array.of(1, 2, 3) },
 *   { type: 'append', operand: Uint8Array.of(4, 5, 6) },
 * ));                                                               // -3
 * console.log(compareOps(
 *   { type: 'append', operand: Uint8Array.of(1, 2, 3) },
 *   { type: 'append', operand: Uint8Array.of(1, 2, 3) },
 * ));                                                               //  0
 * console.log(compareOps(
 *   { type: 'append', operand: Uint8Array.of(4, 5, 6) },
 *   { type: 'append', operand: Uint8Array.of(1, 2, 3) },
 * ));                                                               //  3
 * ```
 *
 * @param left - The first operation to compare.
 * @param right - The second operation to compare.
 * @returns `0` if both {@link Op}s are equal, a positive number if the `left` one is bigger than the `right` one, or a negative number otherwise.
 */
export function compareOps(left: Op, right: Op): number {
  const tagCompare: number = Tag[left.type] - Tag[right.type];
  if (0 === tagCompare && ('append' === left.type || 'prepend' === left.type)) {
    return uint8ArrayCompare(left.operand, (right as { operand: Uint8Array }).operand);
  }
  return tagCompare;
}

/**
 * Compare two {@link Edge}s, and return the comparison result.
 *
 * {@link Edge} comparison merely entails comparing their corresponding {@link Op}s.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { compareEdges, newTree } from './src/internals';
 *
 * console.log(compareEdges(
 *   [{ type: 'sha1' }, newTree()], [{ type: 'ripemd160' }, newTree()],
 * ));  // -1
 * console.log(compareEdges(
 *   [{ type: 'sha1' }, newTree()], [{ type: 'sha1' }, newTree()],
 * ));  //  0
 * console.log(compareEdges(
 *   [{ type: 'ripemd160' }, newTree()], [{ type: 'sha1' }, newTree()],
 * ));  //  1
 * console.log(compareEdges(
 *   [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()],
 *   [{ type: 'append', operand: Uint8Array.of(4, 5, 6) }, newTree()],
 * ));  // -3
 * console.log(compareEdges(
 *   [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()],
 *   [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()],
 * ));  //  0
 * console.log(compareEdges(
 *   [{ type: 'append', operand: Uint8Array.of(4, 5, 6) }, newTree()],
 *   [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()],
 * ));  //  3
 * ```
 *
 * @param left - The first edge to compare.
 * @param right - The second edge to compare.
 * @returns `0` if both {@link Edge}s are equal, a positive number if the `left` one is bigger than the `right` one, or a negative number otherwise.
 */
export function compareEdges(left: Edge, right: Edge): number {
  const [[leftOp], [rightOp]]: [Edge, Edge] = [left, right];
  return compareOps(leftOp, rightOp);
}

/**
 * Incorporate _all_ {@link Leaf | Leaves} and {@link Edge}s from the `right` {@link Tree} into the `left` {@link Tree}.
 *
 * This function will effectively take all {@link Leaf | Leaves} from the `right` {@link Tree} and add them to the `left` {@link Tree}.
 * Likewise, it will take all {@link Edge}s from the `right` {@link Tree} and add them to the `left` {@link Tree}.
 * This effectively makes the `left` {@link Tree} contain all of the data in the `right` {@link Tree} in addition to its own.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import type { Tree } from './src/types';
 *
 * import { incorporateTreeToTree, EdgeMap, LeafSet } from './src/internals';
 *
 * const left: Tree = { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() };
 * const right: Tree = {
 *   leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }),
 *   edges: new EdgeMap().add(
 *     { type: 'sha1' },
 *     {
 *       leaves: new LeafSet().add({ type: 'pending', url: new URL('https://www.example.com') }),
 *       edges: new EdgeMap(),
 *     },
 *   ),
 * };
 *
 * incorporateTreeToTree(left, right);
 *
 * console.log(left.leaves.values());  // [ { type: 'bitcoin', height: 123 }, { type: 'bitcoin', height: 456 } ]
 * console.log(left.edges.entries());  // [ [ { type: 'sha1' }, { leaves: [LeafSet], edges: [EdgeMap] } ] ]
 * ```
 *
 * @param left - The tree to incorporate data _into_.
 * @param right - The tree to incorporate data _from_.
 * @returns The `left` tree, for chaining.
 */
export function incorporateTreeToTree(left: Tree, right: Tree): Tree {
  left.leaves.incorporate(right.leaves);
  left.edges.incorporate(right.edges);
  return left;
}

/**
 * Incorporate the given {@link Edge} or {@link Leaf} the given {@link Tree}.
 *
 * If the given parameter is indeed an {@link Edge}, this function will add it to the given {@link Tree}'s edges {@link EdgeMap}.
 * If, on the other hand, the given parameter is a {@link Leaf}, this function will add it to the {@link Tree}'s leaves {@link LeafSet}.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import type { Tree } from './src/types';
 *
 * import { incorporateToTree, EdgeMap, LeafSet } from './src/internals';
 *
 * const tree: Tree = { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() };
 *
 * incorporateToTree(tree, { type: 'bitcoin', height: 456 });
 * incorporateToTree(tree, [
 *   { type: 'sha1' },
 *   {
 *     leaves: new LeafSet().add({ type: 'pending', url: new URL('https://www.example.com') }),
 *     edges: new EdgeMap(),
 *   },
 * ]);
 *
 * console.log(tree.leaves.values());  // [ { type: 'bitcoin', height: 123 }, { type: 'bitcoin', height: 456 } ]
 * console.log(tree.edges.entries());  // [ [ { type: 'sha1' }, { leaves: [LeafSet], edges: [EdgeMap] } ] ]
 * ```
 *
 * @param tree - The tree to incorporate the given parameter _into_.
 * @param edgeOrLeaf - The element to incorporate.
 * @returns The `tree`, for chaining.
 */
export function incorporateToTree(tree: Tree, edgeOrLeaf: Edge | Leaf): Tree {
  if (Array.isArray(edgeOrLeaf)) {
    tree.edges.add(...edgeOrLeaf);
  } else {
    tree.leaves.add(edgeOrLeaf);
  }
  return tree;
}

/**
 * A set of {@link Leaf | leaves} which are implicitly deduplicated.
 *
 * A `LeafSet` needs to take two operations into account:
 *
 * - **how to determine if two {@link Leaf | leaves} are equivalent:** takes a {@link Leaf} and return a `string` that represents it unequivocally (ie. two {@link Leaf | leaves} returning the same `string` will be taken to be equal themselves).
 * - **how to combine two equivalent {@link Leaf | leaves}:** {@link Leaf | leaves} are not really combined, if two of them are equivalent, then they're _equal_, and only a single one is kept.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { LeafSet } from './src/internals';
 *
 * const leafSetA: LeafSet = new LeafSet()
 *   .add({ type: 'bitcoin', height: 123 })
 *   .add({ type: 'litecoin', height: 123 })
 *   .add({ type: 'ethereum', height: 123 });
 * const leafSetB: LeafSet = new LeafSet()
 *   .add({ type: 'bitcoin', height: 123 })
 *   .add({ type: 'litecoin', height: 456 })
 *   .add({ type: 'ethereum', height: 456 });
 * const leafSetC: LeafSet = new LeafSet();
 *
 * console.log(leafSetA.size());  // 3
 * console.log(leafSetB.size());  // 3
 * console.log(leafSetC.size());  // 0
 *
 * console.log(leafSetA.values());  // [ { type: 'bitcoin', height: 123 }, { type: 'litecoin', height: 123 }, { type: 'ethereum', height: 123 } ]
 * console.log(leafSetB.values());  // [ { type: 'bitcoin', height: 123 }, { type: 'litecoin', height: 456 }, { type: 'ethereum', height: 456 } ]
 * console.log(leafSetC.values());  // []
 *
 * console.log(leafSetA.remove({ type: 'ethereum', height: 123 }));  // LeafSet { mapping: { ... } }
 * console.log(leafSetB.remove({ type: 'ethereum', height: 456 }));  // LeafSet { mapping: { ... } }
 * console.log(leafSetC.remove({ type: 'ethereum', height: 789 }));  // LeafSet { mapping: {} }
 *
 * console.log(leafSetA.incorporate(leafSetB).size());                        // 3
 * console.log(leafSetB.incorporate(leafSetC).size());                        // 2
 * console.log(leafSetC.incorporate(leafSetB).incorporate(leafSetA).size());  // 3
 * ```
 *
 */
export class LeafSet implements MergeSet<Leaf> {
  /**
   * The {@link LeafSet} is implemented via a {@link !Record} that maps "keys" (derived fom an actual {@link Leaf}) to actual values.
   *
   * This is the main storage mapping used to implement the {@link LeafSet}.
   *
   */
  private readonly mapping: Record<string, Leaf> = {};

  /**
   * The callback that will transform a {@link Leaf} into a `string` (implicitly defining what "equality" between them means).
   *
   * @param leaf - Leaf to get the `string` representation of.
   * @returns The `string` representation of the given {@link Leaf}.
   */
  private toKey(leaf: Leaf): string {
    switch (leaf.type) {
      case 'pending':
        return `${leaf.type}:${leaf.url.toString()}`;
      case 'unknown':
        return `${leaf.type}:${uint8ArrayToHex(leaf.header)}:${uint8ArrayToHex(leaf.payload)}`;
      default:
        return `${leaf.type}:${leaf.height}`;
    }
  }

  /**
   * The callback that will be used to combine two equivalent {@link Leaf | leaves} within the {@link LeafSet}.
   *
   * @param left - First Leaf to combine.
   * @param _right - Second Leaf to combine.
   * @returns The resulting combined {@link Leaf}.
   */
  private combine(left: Leaf, _right: Leaf): Leaf {
    return left;
  }

  /**
   * Perform the addition "heavy-lifting" within a {@link LeafSet}.
   *
   * @param key - The `string` key to use (previously passed through {@link toKey}).
   * @param leaf - The actual {@link Leaf} to add.
   * @returns The {@link LeafSet} instance, for chaining.
   */
  private doAdd(key: string, leaf: Leaf): this {
    this.mapping[key] = key in this.mapping ? this.combine(this.mapping[key]!, leaf) : leaf;
    return this;
  }

  /**
   * Return the number of {@link Leaf | leaves} in the {@link LeafSet}.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { LeafSet } from './src/internals';
   *
   * const leafSet: LeafSet = new LeafSet();
   *
   * console.log(leafSet.size());                                        // 0
   * console.log(leafSet.add({ type: 'bitcoin', height: 123 }).size());  // 1
   * ```
   *
   * @returns The number of leaves in the {@link LeafSet}.
   */
  public size(): number {
    return this.values().length;
  }

  /**
   * Return a list of {@link Leaf | Leaves} stored in a {@link LeafSet}.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { LeafSet } from './src/internals';
   *
   * const leafSet: LeafSet = new LeafSet();
   *
   * console.log(leafSet.values());                                        // []
   * console.log(leafSet.add({ type: 'bitcoin', height: 123 }).values());  // [ { type: 'bitcoin', height: 123 } ]
   * ```
   *
   * @returns The list of leaves in the {@link LeafSet}.
   */
  public values(): Leaf[] {
    return Object.values(this.mapping);
  }

  /**
   * Remove the given {@link Leaf} from the {@link LeafSet}.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { LeafSet } from './src/internals';
   *
   * const leafSet: LeafSet = new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 });
   *
   * console.log(leafSet.size());                                            // 2
   * console.log(leafSet.remove({ type: 'ethereum', height: 123 }).size());  // 2
   * console.log(leafSet.remove({ type: 'bitcoin', height: 123 }).size());   // 1
   * console.log(leafSet.remove({ type: 'litecoin', height: 123 }).size());  // 0
   * ```
   *
   * @param leaf - The Leaf to remove.
   * @returns The original {@link LeafSet} with the given {@link Leaf} removed, for chaining.
   */
  public remove(leaf: Leaf): this {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.mapping[this.toKey(leaf)];
    return this;
  }

  /**
   * Add the given {@link Leaf} to the {@link LeafSet}.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { LeafSet } from './src/internals';
   *
   * const leafSet: LeafSet = new LeafSet();
   *
   * console.log(leafSet.size()); // 0
   * console.log(leafSet
   *   .add({ type: 'bitcoin', height: 123 })
   *   .size(),
   * );                           // 1
   * console.log(leafSet
   *   .add({ type: 'bitcoin', height: 123 })
   *   .add({ type: 'litecoin', height: 123 })
   *   .size(),
   * );                           // 2
   * console.log(leafSet
   *   .add({ type: 'bitcoin', height: 123 })
   *   .add({ type: 'litecoin', height: 123 })
   *   .add({ type: 'bitcoin', height: 123 })
   *   .size(),
   * );                           // 2
   * ```
   *
   * @param leaf - The leaf to add to the {@link LeafSet}.
   * @returns The original {@link LeafSet} with the given {@link Leaf} added, for chaining.
   */
  public add(leaf: Leaf): this {
    return this.doAdd(this.toKey(leaf), leaf);
  }

  /**
   * Add _all_ {@link Leaf | Leaves} of the given {@link LeafSet} to the current one.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { LeafSet } from './src/internals';
   *
   * const leafSetA: LeafSet = new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 });
   * const leafSetB: LeafSet = new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 456 });
   * const leafSetC: LeafSet = new LeafSet();
   *
   * console.log(leafSetA.incorporate(leafSetB).size());                        // 3
   * console.log(leafSetB.incorporate(leafSetC).size());                        // 2
   * console.log(leafSetC.incorporate(leafSetB).incorporate(leafSetA).size());  // 3
   * ```
   *
   * @param other - The {@link LeafSet} to incorporate into this one.
   * @returns The original {@link LeafSet} with the given other {@link LeafSet} incorporated, for chaining.
   */
  public incorporate(other: typeof this): this {
    Object.entries(other.mapping).forEach(([key, value]: [string, Leaf]): void => {
      this.doAdd(key, value);
    });
    return this;
  }
}

/**
 * A mapping from {@link Op}s to {@link Tree}s which is implicitly deduplicated.
 *
 * An `EdgeMap` needs to take two operations into account:
 *
 * - **how to determine if two {@link Op}s are equivalent:** takes an {@link Op} and return a `string` that represents it unequivocally (ie. two {@link Op}s returning the same `string` will be taken to be equal themselves).
 * - **how to combine two equivalent {@link Tree}s:** {@link Tree}s are combined by merging them recursively.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { newTree, EdgeMap } from './src/internals';
 *
 * const edgeMapA: EdgeMap = new EdgeMap()
 *   .add({ type: 'sha1' }, newTree())
 *   .add({ type: 'ripemd160' }, newTree())
 *   .add({ type: 'sha256' }, newTree());
 * const edgeMapB: EdgeMap = new EdgeMap()
 *   .add({ type: 'sha1' }, newTree())
 *   .add({ type: 'ripemd160' }, newTree())
 *   .add({ type: 'sha256' }, newTree());
 * const edgeMapC: EdgeMap = new EdgeMap();
 *
 * console.log(edgeMapA.size());  // 3
 * console.log(edgeMapB.size());  // 3
 * console.log(edgeMapC.size());  // 0
 *
 * console.log(edgeMapA.values());  // [ { edges: EdgeMap { keySet: {}, mapping: {} }, leaves: LeafSet { mapping: {} } }, { edges: EdgeMap { keySet: {}, mapping: {} }, leaves: LeafSet { mapping: {} } }, { edges: EdgeMap { keySet: {}, mapping: {} }, leaves: LeafSet { mapping: {} } } ]
 * console.log(edgeMapB.values());  // [ { edges: EdgeMap { keySet: {}, mapping: {} }, leaves: LeafSet { mapping: {} } }, { edges: EdgeMap { keySet: {}, mapping: {} }, leaves: LeafSet { mapping: {} } }, { edges: EdgeMap { keySet: {}, mapping: {} }, leaves: LeafSet { mapping: {} } } ]
 * console.log(edgeMapC.values());  // []
 *
 * console.log(edgeMapA.remove({ type: 'sha256' }));  // EdgeMap { keySet: { sha1: { type: 'sha1' }, ripemd160: { type: 'ripemd160' } }, mapping: { ... } }
 * console.log(edgeMapB.remove({ type: 'sha256' }));  // EdgeMap { keySet: { sha1: { type: 'sha1' }, ripemd160: { type: 'ripemd160' } }, mapping: { ... } }
 * console.log(edgeMapC.remove({ type: 'sha256' }));  // EdgeMap { keySet: {}, mapping: {} }
 *
 * console.log(edgeMapA.incorporate(edgeMapB).size());                        // 2
 * console.log(edgeMapB.incorporate(edgeMapC).size());                        // 2
 * console.log(edgeMapC.incorporate(edgeMapB).incorporate(edgeMapA).size());  // 2
 * ```
 *
 */
export class EdgeMap implements MergeMap<Op, Tree> {
  /**
   * The {@link EdgeMap} is implemented via a pair of {@link !Record}s; the first one maps "keys" (derived form an actual {@link Op}) to actual {@link Op}s.
   *
   * This is the main {@link Op}-mapping used to implement the {@link EdgeMap}.
   *
   */
  private readonly keySet: Record<string, Op> = {};

  /**
   * The {@link EdgeMap} is implemented via a pair of {@link !Record}s; the second one maps "keys" (derived from an actual {@link Op}) to actual {@link Tree}s.
   *
   * This is the main {@link Tree}-mapping used to implement the {@link EdgeMap}.
   *
   */
  private readonly mapping: Record<string, Tree> = {};

  /**
   * The callback that will transform an {@link Op} into a `string` (implicitly defining what "equality" between keys means).
   *
   * @param op - Op to get the `string` representation of.
   * @returns The `string` representation of the given {@link Op}.
   */
  private toKey(op: Op): string {
    switch (op.type) {
      case 'append':
      case 'prepend':
        return `${op.type}:${uint8ArrayToHex(op.operand)}`;
      default:
        return op.type;
    }
  }

  /**
   * The callback that will be used to combine two equivalent {@link Tree}s within the {@link EdgeMap}.
   *
   * @param left - First Tree to combine.
   * @param right - Second Tree to combine.
   * @returns The resulting combined {@link Tree}.
   */
  private combine(left: Tree, right: Tree): Tree {
    return incorporateTreeToTree(left, right);
  }

  /**
   * Perform the addition "heavy-lifting" within a {@link EdgeMap}.
   *
   * @param op - The {@link Op} to use.
   * @param tree - The {@link Tree} to add.
   * @returns The {@link EdgeMap} instance, for chaining.
   */
  private doAdd(op: Op, tree: Tree): this {
    const sKey: string = this.toKey(op);
    this.keySet[sKey] = op;
    this.mapping[sKey] = sKey in this.mapping ? this.combine(this.mapping[sKey]!, tree) : tree;
    return this;
  }

  /**
   * Return the number of pairs in the {@link EdgeMap}.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { newTree, EdgeMap } from './src/internals';
   *
   * const edgeMap: EdgeMap = new EdgeMap();
   *
   * console.log(edgeMap.size());                                   // 0
   * console.log(edgeMap.add({ type: 'sha1' }, newTree()).size());  // 1
   * ```
   *
   * @returns The number of pairs in the {@link EdgeMap}.
   */
  public size(): number {
    return this.values().length;
  }

  /**
   * Return a list of {@link Op}s stored in a {@link EdgeMap}.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { newTree, EdgeMap } from './src/internals';
   *
   * const edgeMap: EdgeMap = new EdgeMap();
   *
   * console.log(edgeMap.values());                                 // []
   * console.log(edgeMap.add({ type: 'sha1' }, newTree()).keys());  // [ { type: 'sha1' } ]
   * ```
   *
   * @returns The list of {@link Op}s in the {@link EdgeMap}.
   */
  public keys(): Op[] {
    return Object.values(this.keySet);
  }

  /**
   * Return a list of {@link Tree}s stored in a {@link EdgeMap}.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { newTree, EdgeMap } from './src/internals';
   *
   * const edgeMap: EdgeMap = new EdgeMap();
   *
   * console.log(edgeMap.values());                                   // []
   * console.log(edgeMap.add({ type: 'sha1' }, newTree()).values());  // [ { edges: EdgeMap { keySet: {}, mapping: {} }, leaves: LeafSet { mapping: {} } } ]
   * ```
   *
   * @returns The list of {@link Tree}s in the {@link EdgeMap}.
   */
  public values(): Tree[] {
    return Object.values(this.mapping);
  }

  /**
   * Return a list of _entries_ (ie. {@link Op} / {@link Tree} pairs) stored in an {@link EdgeMap}.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { newTree, EdgeMap } from './src/internals';
   *
   * const edgeMap: EdgeMap = new EdgeMap();
   *
   * console.log(edgeMap.values());                                    // []
   * console.log(edgeMap.add({ type: 'sha1' }, newTree()).entries());  // [ [ { type: 'sha1' }, { edges: [EdgeMap], leaves: [LeafSet] } ] ]
   * ```
   *
   * @returns The list of entries in the {@link EdgeMap}.
   */
  public entries(): [Op, Tree][] {
    return this.keys().map((key: Op): [Op, Tree] => [key, this.mapping[this.toKey(key)]!]);
  }

  /**
   * Remove the given {@link Op} from the {@link EdgeMap}.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { newTree, EdgeMap } from './src/internals';
   *
   * const edgeMap: EdgeMap = new EdgeMap().add({ type: 'sha1' }, newTree()).add({ type: 'ripemd160' }, newTree());
   *
   * console.log(edgeMap.size());                                // 2
   * console.log(edgeMap.remove({ type: 'sha256' }).size());     // 2
   * console.log(edgeMap.remove({ type: 'sha1' }).size());       // 1
   * console.log(edgeMap.remove({ type: 'ripemd160' }).size());  // 0
   * ```
   *
   * @param op - The {@link Op} to remove.
   * @returns The original {@link EdgeMap} with the given {@link Op} removed, for chaining.
   */
  public remove(op: Op): this {
    const sKey: string = this.toKey(op);
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.mapping[sKey];
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.keySet[sKey];
    return this;
  }

  /**
   * Add the given {@link Op} / {@link Tree} pair to the {@link EdgeMap}.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { newTree, EdgeMap } from './src/internals';
   *
   * const edgeMap: EdgeMap = new EdgeMap();
   *
   * console.log(edgeMap.size()); // 0
   * console.log(edgeMap
   *   .add({ type: 'sha1' }, newTree())
   *   .size(),
   * );                           // 1
   * console.log(edgeMap
   *   .add({ type: 'sha1' }, newTree())
   *   .add({ type: 'ripemd160' }, newTree())
   *   .size(),
   * );                           // 2
   * console.log(edgeMap
   *   .add({ type: 'sha1' }, newTree())
   *   .add({ type: 'ripemd160' }, newTree())
   *   .add({ type: 'sha1' }, newTree())
   *   .size(),
   * );                           // 2
   * ```
   *
   * @param op - The {@link Op} to add to the {@link EdgeMap}.
   * @param tree - The {@link Tree} to add to the {@link EdgeMap}.
   * @returns The original {@link EdgeMap} with the given {@link Op} / {@link Tree} pair added, for chaining.
   */
  public add(op: Op, tree: Tree): this {
    return this.doAdd(op, tree);
  }

  /**
   * Add _all_ {@link Op} / {@link Tree} pairs of the given {@link EdgeMap} to the current one.
   *
   * @example
   * ```typescript
   * 'use strict';
   *
   * import { newTree, EdgeMap } from './src/internals';
   *
   * const edgeMapA: EdgeMap = new EdgeMap().add({ type: 'sha1' }, newTree()).add({ type: 'ripemd160' }, newTree());
   * const edgeMapB: EdgeMap = new EdgeMap().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree());
   * const edgeMapC: EdgeMap = new EdgeMap();
   *
   * console.log(edgeMapA.incorporate(edgeMapB).size());                        // 3
   * console.log(edgeMapB.incorporate(edgeMapC).size());                        // 2
   * console.log(edgeMapC.incorporate(edgeMapB).incorporate(edgeMapA).size());  // 3
   * ```
   *
   * @param other - The {@link EdgeMap} to incorporate into this one.
   * @returns The original {@link EdgeMap} with the given other {@link EdgeMap} incorporated, for chaining.
   */
  public incorporate(other: typeof this): this {
    other.entries().forEach(([op, tree]: [Op, Tree]): void => {
      this.doAdd(op, tree);
    });
    return this;
  }
}

/**
 * Construct an empty {@link Tree}.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { newTree } from './src/internals';
 *
 * console.log(newTree());  // { edges: EdgeMap { keySet: {}, mapping: {} }, leaves: LeafSet { mapping: {} } }
 * ```
 *
 * @returns The empty tree constructed.
 */
export function newTree(): Tree {
  return { edges: new EdgeMap(), leaves: new LeafSet() };
}

/**
 * Turn single-byte-operand binary {@link Op | Operations} (ie. `append` and `prepend` that append or prepend a single byte value), followed by _two {@link Op | Operations} of the same type_ into two {@link Op | Operations} the have the single-byte-operand pre-computed within them.
 *
 * This is a strange function to have, and it serves a very "niche" case required in order to obtain the minimum possible length for serialized timestamps.
 *
 * The {@link coalesceOperations} function will try to factor out common `operand` suffixes for `append`, and common `operand` prefixes for `prepend` operations happening on sibling edges.
 * That is to say:
 *
 * ```mermaid
 * flowchart TD
 *     A((<i>first</i>))
 *     B((T<sub>1</sub>))
 *     C((T<sub>2</sub>))
 *     D((T<sub>3</sub>))
 *     E1([<code>append:abc</code>])
 *     E2([<code>append:abd</code>])
 *     E3([<code>append:abe</code>])
 *     A --> E1 --> B
 *     A --> E2 --> C
 *     A --> E3 --> D
 * ```
 *
 * Will be transformed to:
 *
 * ```mermaid
 * flowchart TD
 *     A((<i>second</i>))
 *     B((&nbsp;&nbsp;&nbsp;))
 *     C((T<sub>1</sub>))
 *     D((T<sub>2</sub>))
 *     E((T<sub>3</sub>))
 *     E1([<code>append:ab</code>])
 *     E2([<code>append:c</code>])
 *     E3([<code>append:d</code>])
 *     E4([<code>append:e</code>])
 *     A --> E1 --> B
 *     B --> E2 --> C
 *     B --> E3 --> D
 *     B --> E4 --> E
 * ```
 *
 * This is advantageous because the common `ab` part of the operand will only appear once in the serialized output.
 * To see this, consider the size of the first form (where **`NF`** stands for the _non-final marker_):
 *
 * $$
 *   \\begin\{align*\}
 *     s_\\text\{first\} &= \\left| \\text\{\\tt\{NF\}\} \\right| + \\left| \\text\{\\tt\{append abc\}\} \\right| + \\left| \\text\{\\tt\{NF\}\} \\right| + \\left| \\text\{\\tt\{append abd\}\} \\right| + \\left| \\text\{\\tt\{append abe\}\} \\right| + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right| \\\\
 *                       &= 1 + 2 + \\left| \\text\{\\tt\{abc\}\} \\right| + 1 + 2 + \\left| \\text\{\\tt\{abd\}\} \\right| + 2 + \\left| \\text\{\\tt\{abe\}\} \\right| + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right| \\\\
 *                       &= 1 + 2 + 3 + 1 + 2 + 3 + 2 + 3 + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right| \\\\
 *                       &= 17 + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right|
 *   \\end\{align*\}
 * $$
 *
 * And contrast it with the size of the second form:
 *
 * $$
 *   \\begin\{align*\}
 *     s_\\text\{second\} &= \\left| \\text\{\\tt\{append ab\}\} \\right| + \\left( \\left| \\text\{\\tt\{NF\}\} \\right| + \\left| \\text\{\\tt\{append c\}\} \\right| + \\left| \\text\{\\tt\{NF\}\} \\right| + \\left| \\text\{\\tt\{append d\}\} \\right| + \\left| \\text\{\\tt\{append e\}\} \\right| + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right| \\right) \\\\
 *                        &= 2 + \\left| \\text\{\\tt\{ab\}\} \\right| + \\left( 1 + 2 + \\left| \\text\{\\tt\{c\}\} \\right| + 1 + 2 + \\left| \\text\{\\tt\{d\}\} \\right| + 2 + \\left| \\text\{\\tt\{e\}\} \\right| + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right| \\right) \\\\
 *                        &= 2 + 2 + \\left( 1 + 2 + 1 + 1 + 2 + 1 + 2 + 1 + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right| \\right) \\\\
 *                        &= 15 + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right|
 *   \\end\{align*\}
 * $$
 *
 * Note how, if the common operand would have had length 2, these two sizes would have been equal.
 *
 * But what would happen if `ab` above would be just `a`, and we were to have only two siblings?
 * Like so:
 *
 * ```mermaid
 * flowchart TD
 *     A((<i>third</i>))
 *     B((T<sub>1</sub>))
 *     C((T<sub>2</sub>))
 *     E1([<code>append:ac</code>])
 *     E2([<code>append:ad</code>])
 *     A --> E1 --> B
 *     A --> E2 --> C
 * ```
 *
 * This would get transformed to:
 *
 * ```mermaid
 * flowchart TD
 *     A((<i>fourth</i>))
 *     B((&nbsp;&nbsp;&nbsp;))
 *     C((T<sub>1</sub>))
 *     D((T<sub>2</sub>))
 *     E1([<code>append:a</code>])
 *     E2([<code>append:c</code>])
 *     E3([<code>append:d</code>])
 *     A --> E1 --> B
 *     B --> E2 --> C
 *     B --> E3 --> D
 * ```
 *
 * Calculating the new sizes in this case gives:
 *
 * $$
 *   \\begin\{align\*\}
 *     s_\\text\{third\} &= \\left| \\text\{\\tt\{NF\}\} \\right| + \\left| \\text\{\\tt\{append ac\}\} \\right| + \\left| \\text\{\\tt\{append ad\}\} \\right| + \\left| T_1 \\right| + \\left| T_2 \\right| \\\\
 *                       &= 1 + 2 + \\left| \\text\{\\tt\{ac\}\} \\right| + 2 + \\left| \\text\{\\tt\{ad\}\} \\right| + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right| \\\\
 *                       &= 1 + 2 + 2 + 2 + 2 + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right| \\\\
 *                       &= 9 + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right|
 *   \\end\{align\*\}
 * $$
 *
 * And:
 *
 * $$
 *   \\begin\{align\*\}
 *     s_\\text\{fourth\} &= \\left| \\text\{\\tt\{append a\}\} \\right| + \\left( \\left| \\text\{\\tt\{NF\}\} \\right| + \\left| \\text\{\\tt\{append c\}\} \\right| + \\left| \\text\{\\tt\{append d\}\} \\right| + \\left| T_1 \\right| + \\left| T_2 \\right| \\right) \\\\
 *                        &= 2 + \\left| \\text\{\\tt\{a\}\} \\right| + \\left( 1 + 2 + \\left| \\text\{\\tt\{c\}\} \\right| + 2 + \\left| \\text\{\\tt\{d\}\} \\right| + \\left| T_1 \\right| + \\left| T_2 \\right| \\right) \\\\
 *                        &= 2 + 1 + \\left( 1 + 2 + 1 + 2 + 1 + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right| \\right) \\\\
 *                        &= 10 + \\left| T_1 \\right| + \\left| T_2 \\right| + \\left| T_3 \\right|
 *   \\end\{align\*\}
 * $$
 *
 * As can be seen, $s_\\text\{third\} < s_\\text\{fourth\}$, and we've ended up using one more byte by aggressively coalescing.
 * Needless to say, the same would happen if we were to use `prepend` operations instead of `append` ones.
 *
 * What this function does is identify this specific scenario:
 *
 * 1. The current tree node has only a single edge exiting from it.
 * 2. Said edge leads to another tree node with _no_ leaves, and _exactly two_ edges.
 * 3. Said two edges have _the same_ operation associated to them.
 * 4. Both operations of step **3** and that associated to the edge identified in step **1** are _of the same type_, and said type is either `append` or `prepend`.
 * 5. The operation associated to the edge in step **1** consists of a single byte.
 *
 * It the eliminates the edge in step **1** and replaces it with the result of pre-computing the removed operation on the edges of step **2** and attaching the resulting trees there.
 *
 * In other words: it replaces the substructure found in the _fourth_ graph above, with the one found in the _third_ one.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import type { Tree } from './src/types';
 *
 * import { decoalesceOperations, EdgeMap, LeafSet, newTree } from './src/internals';
 *
 * const tree: Tree = {
 *   leaves: new LeafSet(),
 *   edges: new EdgeMap().add(
 *     { type: 'append', operand: Uint8Array.of(1) },
 *     {
 *       leaves: new LeafSet(),
 *       edges: new EdgeMap()
 *         .add({ type: 'append', operand: Uint8Array.of(2, 3) }, newTree())
 *         .add({ type: 'append', operand: Uint8Array.of(4, 5) }, newTree()),
 *     },
 *   ),
 * };
 *
 * console.log(tree.edges.keys());                     // [ { type: 'append', operand: Uint8Array(1) [ 1 ] } ]
 * console.log(tree.edges.values()[0]?.edges.keys());  // [ { type: 'append', operand: Uint8Array(2) [ 2, 3 ] },
 *                                                     //   { type: 'append', operand: Uint8Array(2) [ 4, 5 ] } ]
 *
 * decoalesceOperations(tree);
 *
 * console.log(tree.edges.keys());                     // [ { type: 'append', operand: Uint8Array(3) [ 1, 2, 3 ] },
 *                                                     //   { type: 'append', operand: Uint8Array(3) [ 1, 4, 5 ] } ]
 * ```
 *
 * @param tree - The tree to decoalesce operations from.
 * @returns The processed tree.
 */
export function decoalesceOperations(tree: Tree): Tree {
  tree.edges.values().forEach((subTree: Tree): Tree => decoalesceOperations(subTree));
  if (1 === tree.edges.size()) {
    const [op, subTree]: Edge = tree.edges.entries()[0]!;
    if (0 === subTree.leaves.size() && 2 === subTree.edges.size()) {
      if (
        'prepend' === op.type &&
        1 === op.operand.length &&
        'prepend:prepend' ===
          subTree.edges
            .keys()
            .map((subOp: Op): string => subOp.type)
            .join(':')
      ) {
        const [[subOp1, subSubTree1], [subOp2, subSubTree2]]: [Edge, Edge] = subTree.edges.entries() as [Edge, Edge];
        tree.edges
          .remove(op)
          .add(
            { type: 'prepend', operand: uint8ArrayConcat((subOp1 as { operand: Uint8Array }).operand, op.operand) },
            subSubTree1,
          )
          .add(
            { type: 'prepend', operand: uint8ArrayConcat((subOp2 as { operand: Uint8Array }).operand, op.operand) },
            subSubTree2,
          );
      } else if (
        'append' === op.type &&
        1 === op.operand.length &&
        'append:append' ===
          subTree.edges
            .keys()
            .map((subOp: Op): string => subOp.type)
            .join(':')
      ) {
        const [[subOp1, subSubTree1], [subOp2, subSubTree2]]: [Edge, Edge] = subTree.edges.entries() as [Edge, Edge];
        tree.edges
          .remove(op)
          .add(
            { type: 'append', operand: uint8ArrayConcat(op.operand, (subOp1 as { operand: Uint8Array }).operand) },
            subSubTree1,
          )
          .add(
            { type: 'append', operand: uint8ArrayConcat(op.operand, (subOp2 as { operand: Uint8Array }).operand) },
            subSubTree2,
          );
      }
    }
  }
  return tree;
}

/**
 * Merge equal consecutive binary operations on single-{@link Edge} nodes.
 *
 * This function will turn strings of equal _binary_ operations (ie. `append`s or `prepend`s) into a single such operation with their operands correctly concatenated.
 *
 * By way of example, consider the following tree:
 *
 * ```mermaid
 * flowchart TD
 *     A((&nbsp;&nbsp;&nbsp;))
 *     B((&nbsp;&nbsp;&nbsp;))
 *     C((&nbsp;&nbsp;&nbsp;))
 *     D((&nbsp;&nbsp;&nbsp;))
 *     E((&nbsp;&nbsp;&nbsp;))
 *     E1([<code>prepend:a</code>])
 *     E2([<code>prepend:b</code>])
 *     E3([<code>prepend:c</code>])
 *     E4([<code>prepend:d</code>])
 *     A --> E1 --> B --> E2 --> C --> E3 --> D --> E4 --> E
 * ```
 *
 * This function will merge all these `prepend` operations into:
 *
 * ```mermaid
 * flowchart TD
 *     A((&nbsp;&nbsp;&nbsp;))
 *     B((&nbsp;&nbsp;&nbsp;))
 *     E1([<code>prepend:dcba</code>])
 *     A --> E1 --> B
 * ```
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import type { Tree } from './src/types';
 *
 * import { coalesceOperations, newTree, EdgeMap, LeafSet } from './src/internals';
 *
 * const tree: Tree = {
 *   leaves: new LeafSet(),
 *   edges: new EdgeMap().add(
 *     { type: 'append', operand: Uint8Array.of(1) },
 *     {
 *       leaves: new LeafSet(),
 *       edges: new EdgeMap().add(
 *         { type: 'append', operand: Uint8Array.of(2) },
 *         {
 *           leaves: new LeafSet(),
 *           edges: new EdgeMap().add({ type: 'append', operand: Uint8Array.of(3) }, newTree()),
 *         },
 *       ),
 *     },
 *   ),
 * };
 *
 * console.log(tree.edges.keys());                                        // [ { type: 'append', operand: Uint8Array(1) [ 1 ] } ]
 * console.log(tree.edges.values()[0]?.edges.keys());                     // [ { type: 'append', operand: Uint8Array(1) [ 2 ] } ]
 * console.log(tree.edges.values()[0]?.edges.values()[0]?.edges.keys());  // [ { type: 'append', operand: Uint8Array(1) [ 3 ] } ]
 *
 * coalesceOperations(tree);
 *
 * console.log(tree.edges.keys());  // [ { type: 'append', operand: Uint8Array(3) [ 1, 2, 3 ] } ]
 * ```
 *
 * @param tree - The tree to coalesce operations on.
 * @returns The processed tree.
 */
export function coalesceOperations(tree: Tree): Tree {
  tree.edges.values().forEach(coalesceOperations);
  if (0 !== tree.leaves.size()) {
    return tree;
  }
  tree.edges.entries().forEach(([op, subTree]: Edge): void => {
    if (0 === subTree.leaves.size() && 1 === subTree.edges.size()) {
      const [subOp, subSubTree]: Edge = subTree.edges.entries()[0]!;
      if ('prepend' === op.type && 'prepend' === subOp.type) {
        tree.edges
          .remove(op)
          .add({ type: 'prepend', operand: uint8ArrayConcat(subOp.operand, op.operand) }, subSubTree);
      } else if ('append' === op.type && 'append' === subOp.type) {
        tree.edges.remove(op).add({ type: 'append', operand: uint8ArrayConcat(op.operand, subOp.operand) }, subSubTree);
      }
    }
  });
  return tree;
}

/**
 * Transform a `prepend` operand into a list of `prepend` {@link Ops | operations} where each of them prepends a _single_ byte.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { atomizePrependOp } from './src/internals';
 *
 * console.log(atomizePrependOp(Uint8Array.of(1, 2, 3)));  // [
 *                                                         //   { type: 'prepend', operand: Uint8Array(1) [ 3 ] },
 *                                                         //   { type: 'prepend', operand: Uint8Array(1) [ 2 ] },
 *                                                         //   { type: 'prepend', operand: Uint8Array(1) [ 1 ] }
 *                                                         // ]
 * ```
 *
 * @param prefix - The operand to atomize.
 * @returns The list of `prepend` operations.
 */
export function atomizePrependOp(prefix: Uint8Array): Ops {
  const ops: Ops = [];
  uint8ArrayReversed(prefix).forEach((value: number): void => {
    ops.push({ type: 'prepend', operand: Uint8Array.of(value) });
  });
  return ops;
}

/**
 * Transform an `append` operand into a list of `append` {@link Ops | operations} where each of them appends a _single_ byte.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { atomizeAppendOp } from './src/internals';
 *
 * console.log(atomizeAppendOp(Uint8Array.of(1, 2, 3)));  // [
 *                                                        //   { type: 'append', operand: Uint8Array(1) [ 1 ] },
 *                                                        //   { type: 'append', operand: Uint8Array(1) [ 2 ] },
 *                                                        //   { type: 'append', operand: Uint8Array(1) [ 3 ] }
 *                                                        // ]
 * ```
 *
 * @param suffix - The operand to atomize.
 * @returns The list of `append` operations.
 */
export function atomizeAppendOp(suffix: Uint8Array): Ops {
  const ops: Ops = [];
  suffix.forEach((value: number): void => {
    ops.push({ type: 'append', operand: Uint8Array.of(value) });
  });
  return ops;
}

/**
 * Transform a series of {@link Op | operations} such that consecutive `reverse`, `prepend`, and `append` operations are turned into an equivalent series of operations in a standard order.
 *
 * The normalization process takes blocks of consecutive operations, each of which is either `reverse`, `prepend`, or `append`, and calculates the resulting prefix, suffix, and whether the result should be reversed itself.
 * Upon encountering any other operation type, the result is written in order: first the prefix, then the suffix, and lastly any `reverse` operations required.
 *
 * The individual normalization rules used are:
 *
 * $$
 *   \\begin\{align\*\}
 *     \\text\{reverse\} \\left( \\text\{reverse\} \\left( x \\right) \\right) &\\to x \\\\
 *     \\text\{append\} \\left( \\text\{reverse\} \\left( x \\right), s \\right) &\\to \\text\{reverse\} \\left( \\text\{prepend\} \\left( x, s^\{-1\} \\right) \\right) \\\\
 *     \\text\{prepend\} \\left( \\text\{reverse\} \\left( x \\right), p \\right) &\\to \\text\{reverse\} \\left( \\text\{append\} \\left( x, p^\{-1\} \\right) \\right)
 *   \\end\{align\*\}
 * $$
 *
 * Where $s^\{-1\}$ and $p^\{-1\}$ represents the reversal of the suffix or prefix respectively, and can be precomputed.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { normalizeOps } from './src/internals';
 *
 * console.log(normalizeOps([
 *   { type: 'append', operand: Uint8Array.of(1, 2) },
 *   { type: 'prepend', operand: Uint8Array.of(3, 4) },
 * ]));  // [
 *       //   { type: 'prepend', operand: Uint8Array(1) [ 4 ] },
 *       //   { type: 'prepend', operand: Uint8Array(1) [ 3 ] },
 *       //   { type: 'append', operand: Uint8Array(1) [ 1 ] },
 *       //   { type: 'append', operand: Uint8Array(1) [ 2 ] }
 *       // ]
 * ```
 *
 * @param operations - Operations to normalize.
 * @returns The normalized operations.
 */
export function normalizeOps(operations: Ops): Ops {
  let prefix: Uint8Array = Uint8Array.of();
  let suffix: Uint8Array = Uint8Array.of();
  let reverse: boolean = false;
  let ops: Ops = [];
  for (let i: number = 0; i < operations.length; i++) {
    const thisOp: Op = operations[i]!;
    switch (thisOp.type) {
      case 'reverse':
        [prefix, reverse, suffix] = [uint8ArrayReversed(suffix), !reverse, uint8ArrayReversed(prefix)];
        break;
      case 'append':
        suffix = uint8ArrayConcat(suffix, thisOp.operand);
        break;
      case 'prepend':
        prefix = uint8ArrayConcat(thisOp.operand, prefix);
        break;
      default:
        if (reverse) {
          ops.push({ type: 'reverse' });
          reverse = false;
        }
        if (0 !== prefix.length) {
          ops = ops.concat(atomizePrependOp(prefix));
          prefix = Uint8Array.of();
        }
        if (0 !== suffix.length) {
          ops = ops.concat(atomizeAppendOp(suffix));
          suffix = Uint8Array.of();
        }
        ops.push(thisOp);
    }
  }
  if (reverse) {
    ops.push({ type: 'reverse' });
  }
  if (0 !== prefix.length) {
    ops = ops.concat(atomizePrependOp(prefix));
  }
  if (0 !== suffix.length) {
    ops = ops.concat(atomizeAppendOp(suffix));
  }
  return ops;
}

/**
 * Given a set of {@link Path}s, transform them into a {@link Tree}, by repeatedly incorporating each of them to an empty one.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import type { Path } from './src/internals';
 * import type { Op, Tree } from './src/types';
 * import { pathsToTree } from './src/internals';
 *
 * const path1: Path = { operations: [{ type: 'sha1' }], leaf: { type: 'bitcoin', height: 123 } };
 * const path2: Path = { operations: [{ type: 'sha256' }], leaf: { type: 'bitcoin', height: 456 } };
 *
 * const tree: Tree = pathsToTree([path1, path2]);
 *
 * console.log(tree.edges.keys());  // [ { type: 'sha1' }, { type: 'sha256' } ]
 * tree.edges.entries().forEach(([, subTree]: [Op, Tree]): void => {
 *   console.log(subTree.leaves.values());
 * });                              // [ { type: 'bitcoin', height: 123 } ]
 *                                  // [ { type: 'bitcoin', height: 456 } ]
 * ```
 *
 * @param paths - The paths to transform.
 * @returns The resulting tree.
 */
export function pathsToTree(paths: Paths): Tree {
  return paths
    .map((path: Path): Tree => {
      return path.operations.reduceRight(
        (tree: Tree, op: Op): Tree => {
          const result: Tree = newTree();
          result.edges.add(op, tree);
          return result;
        },
        { leaves: new LeafSet().add(path.leaf), edges: new EdgeMap() },
      );
    })
    .reduce(incorporateTreeToTree, newTree());
}

/**
 * Transform a {@link Tree} into a set of {@link Path}s, by extracting each path from the tree's root to a {@link Leaf}.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import type { Path } from './src/internals';
 * import type { Tree } from './src/types';
 *
 * import { treeToPaths, EdgeMap, LeafSet } from './src/internals';
 *
 * const tree: Tree = {
 *   leaves: new LeafSet(),
 *   edges: new EdgeMap()
 *     .add({ type: 'sha1' }, { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() })
 *     .add({ type: 'sha256' }, { leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }), edges: new EdgeMap() }),
 * };
 *
 * treeToPaths(tree).forEach((path: Path): void => {
 *   console.log(path.operations);
 *   console.log(path.leaf);
 * });  // [ { type: 'sha1' } ]
 *      // { type: 'bitcoin', height: 123 }
 *      // [ { type: 'sha256' } ]
 *      // { type: 'bitcoin', height: 456 }
 * ```
 *
 * @param tree - The tree to transform.
 * @param path - A list of {@link Op | operations} representing the current path from the root to the given tree.
 * @returns The extracted paths.
 */
export function treeToPaths(tree: Tree, path: Ops = []): Paths {
  const result: Paths = [];
  tree.leaves.values().forEach((leaf: Leaf): void => {
    result.push({ operations: path, leaf });
  });
  tree.edges.entries().forEach(([op, subTree]: Edge): void => {
    treeToPaths(subTree, path.concat([op])).forEach((leafPath: Path): void => {
      result.push(leafPath);
    });
  });
  return result;
}

/**
 * Normalize the given {@link Timestamp}, so as to have it have standardized `tree` component.
 *
 * This function will perform the following steps in order:
 *
 * 1. Transform the given {@link Timestamp}'s `tree` component into a set of {@link Path}s (via {@link treeToPaths}).
 * 2. Normalize each of these {@link Path}s individually (via {@link normalizeOps}).
 * 3. Re-build a {@link Tree} from these normalized {@link Path}s (via {@link pathsToTree}).
 * 4. Coalesce these {@link Op | operation}s in this resulting {@link Tree} (via {@link coalesceOperations}).
 * 5. Finally, decoalesce them (via {@link decoalesceOperations}) to deal with edge cases.
 *
 * If the normalization operation would yield an empty {@link Tree}, `undefined` is returned (since "empty" {@link Timestamp}s are not allowed).
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import type { Timestamp } from './src/types';
 *
 * import { normalize, EdgeMap, LeafSet } from './src/internals';
 *
 * const timestamp: Timestamp = normalize({
 *   version: 1,
 *   fileHash: {
 *     algorithm: 'sha1',
 *     value: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *   },
 *   tree: {
 *     leaves: new LeafSet(),
 *     edges: new EdgeMap().add(
 *       { type: 'prepend', operand: Uint8Array.of(1, 2, 3) },
 *       { leaves: new LeafSet(),
 *         edges: new EdgeMap()
 *           .add(
 *             { type: 'reverse' },
 *             { leaves: new LeafSet(),
 *               edges: new EdgeMap().add(
 *                 { type: 'append', operand: Uint8Array.of(7, 8, 9) },
 *                 { edges: new EdgeMap(),
 *                   leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
 *                 },
 *               ),
 *             },
 *           )
 *           .add(
 *             { type: 'prepend', operand: Uint8Array.of(4, 5, 6) },
 *             { edges: new EdgeMap(),
 *               leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }),
 *             },
 *           ),
 *       },
 *     ),
 *   },
 * })!;
 *
 * console.log(timestamp.tree.leaves.values());                                                        // []
 * console.log(timestamp.tree.edges.keys());
 *   // [
 *   //   { type: 'prepend', operand: Uint8Array(3) [ 9, 8, 7 ] },
 *   //   { type: 'prepend', operand: Uint8Array(6) [ 4, 5, 6, 1, 2, 3 ] }
 *   // ]
 * console.log(timestamp.tree.edges.values()[0]?.leaves.values());                                     // []
 * console.log(timestamp.tree.edges.values()[0]?.edges.keys());
 *   // [ { type: 'append', operand: Uint8Array(3) [ 3, 2, 1 ] } ]
 * console.log(timestamp.tree.edges.values()[0]?.edges.values()[0]?.leaves.values());                  // []
 * console.log(timestamp.tree.edges.values()[0]?.edges.values()[0]?.edges.keys());
 *   // [ { type: 'reverse' } ]
 * console.log(timestamp.tree.edges.values()[0]?.edges.values()[0]?.edges.values()[0]?.leaves.values());
 *   // [ { type: 'bitcoin', height: 123 } ]
 * console.log(timestamp.tree.edges.values()[0]?.edges.values()[0]?.edges.values()[0]?.edges.keys());  // []
 * console.log(timestamp.tree.edges.values()[1]?.leaves.values());
 *   // [ { type: 'bitcoin', height: 456 } ]
 * console.log(timestamp.tree.edges.values()[1]?.edges.keys());                                        // []
 * ```
 *
 * @param timestamp - The timestamp to normalize.
 * @returns The normalized timestamp.
 */
export function normalize(timestamp: Timestamp): Timestamp | undefined {
  const tree: Tree = decoalesceOperations(
    coalesceOperations(
      pathsToTree(
        treeToPaths(timestamp.tree).map((path: Path): { operations: Ops; leaf: Leaf } => {
          return { operations: normalizeOps(path.operations), leaf: path.leaf };
        }),
      ),
    ),
  );

  return 0 === tree.leaves.size() + tree.edges.size()
    ? undefined
    : {
        fileHash: timestamp.fileHash,
        version: timestamp.version,
        tree,
      };
}
