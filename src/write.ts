// typescript-opentimestamps: An OpenTimestamps client written in TypeScript.
// Copyright (C) 2024  La Crypta
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

/**
 * This module exposes binary writing functions.
 *
 * @see {@link read! | Read} for information regarding the binary serialization format.
 *
 * @packageDocumentation
 * @module
 */

import type { Edge } from './internals';
import type { FileHash, Leaf, Timestamp, Tree } from './types';

import { compareEdges, compareLeaves, magicHeader, nonFinal, LeafHeader, Tag } from './internals';
import { textEncoder, uint8ArrayConcat, uint8ArrayFromHex } from './utils';

/**
 * Write a multi-byte unsigned integer.
 *
 * Multi-byte unsigned integers (ie. `UINT`s) are written in byte-based little-endian ordering, and use the most-significant-bit to indicate whether more bytes need to be read.
 * Pictorially, if the number to write has the following bit-pattern:
 *
 * ```
 * aaaaaaabbbbbbbcccccccddddddd
 * ```
 *
 * it will be written as (leftmost bytes appear _first_ in the data stream, leftmost bits are more significant):
 *
 * ```
 * 1ddddddd 1ccccccc 1bbbbbbb 0aaaaaaa
 * ```
 *
 * @example
 * ```typescript
 * import { writeUint } from './src/write';
 *
 * console.log(writeUint(0));
 *   // Uint8Array(1) [ 0 ]
 * console.log(writeUint(1));
 *   // Uint8Array(1) [ 1 ]
 * console.log(writeUint(1234));
 *   // Uint8Array(2) [ 210, 9 ]
 * console.log(writeUint(12345678));
 *   // Uint8Array(4) [ 206, 194, 241, 5 ]
 * ```
 *
 * @example
 * ```typescript
 * import { writeUint } from './src/write';
 *
 * console.log(writeUint(-1));
 *   // Error: Expected safe non-negative value
 * console.log(writeUint(NaN));
 *   // Error: Expected safe non-negative value
 * console.log(writeUint(Math.PI));
 *   // Error: Expected safe non-negative value
 * ```
 *
 * @param value - The value to write.
 * @returns The written {@link !Uint8Array}.
 * @throws {@link !Error} when the given value is not a {@link !Number.isSafeInteger | safe integer}.
 */
export function writeUint(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('Expected safe non-negative value');
  }
  const resultParts: Uint8Array[] = [];
  while (0x7f < value) {
    resultParts.push(Uint8Array.of(0x80 | (value & 0x7f)));
    value >>>= 7;
  }
  resultParts.push(Uint8Array.of(value));
  return uint8ArrayConcat(...resultParts);
}

/**
 * Write a variable-length bytes value.
 *
 * Variable-length bytes (ie. `VARBYTE`) are written as two consecutive entities: a `UINT` specifying the number of bytes that follow, and the bytes themselves.
 *
 * > This function internally calls {@link writeUint}.
 *
 * @example
 * ```typescript
 * import { writeBytes } from './src/write';
 *
 * console.log(writeBytes(Uint8Array.of()));
 *   // Uint8Array(1) [ 0 ]
 * console.log(writeBytes(Uint8Array.of(1, 2, 3, 4)));
 *   // Uint8Array(5) [ 4, 1, 2, 3, 4 ]
 * ```
 *
 * @param bytes - The bytes to write.
 * @returns The written {@link !Uint8Array}.
 */
export function writeBytes(bytes: Uint8Array): Uint8Array {
  return uint8ArrayConcat(writeUint(bytes.length), bytes);
}

/**
 * Write a {@link FileHash} value.
 *
 * {@link FileHash} values are written by writing $n + 1$ bytes, where $n$ is the number of bytes the {@link FileHash}'s `algorithm` outputs.
 * The additional byte is written at the beginning and simply constitutes the `algorithm`'s {@link Tag}.
 *
 * @example
 * ```typescript
 * import { writeFileHash } from './src/write';
 *
 * console.log(writeFileHash({
 *   algorithm: 'sha1',
 *   value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                        11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 * }));
 *   // Uint8Array(21) [
 *   //    2,
 *   //    1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *   //   11, 12, 13, 14, 15, 16, 17, 18, 19, 20
 *   // ]
 * console.log(writeFileHash({
 *   algorithm: 'ripemd160',
 *   value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                        11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 * }));
 *   // Uint8Array(21) [
 *   //    3,
 *   //    1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *   //   11, 12, 13, 14, 15, 16, 17, 18, 19, 20
 *   // ]
 * console.log(writeFileHash({
 *   algorithm: 'sha256',
 *   value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,
 *                         9, 10, 11, 12, 13, 14, 15, 16,
 *                        17, 18, 19, 20, 21, 22, 23, 24,
 *                        25, 26, 27, 28, 29, 30, 31, 32),
 * }));
 *   // Uint8Array(33) [
 *   //    8,
 *   //    1,  2,  3,  4,  5,  6,  7,  8,
 *   //    9, 10, 11, 12, 13, 14, 15, 16,
 *   //   17, 18, 19, 20, 21, 22, 23, 24,
 *   //   25, 26, 27, 28, 29, 30, 31, 32
 *   // ]
 * console.log(writeFileHash({
 *   algorithm: 'keccak256',
 *   value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,
 *                         9, 10, 11, 12, 13, 14, 15, 16,
 *                        17, 18, 19, 20, 21, 22, 23, 24,
 *                        25, 26, 27, 28, 29, 30, 31, 32),
 * }));
 *   // Uint8Array(33) [
 *   //   103,
 *   //     1,  2,  3,  4,  5,  6,  7,  8,
 *   //     9, 10, 11, 12, 13, 14, 15, 16,
 *   //    17, 18, 19, 20, 21, 22, 23, 24,
 *   //    25, 26, 27, 28, 29, 30, 31, 32
 *   // ]
 * ```
 *
 * @param fileHash - The {@link FileHash} to write.
 * @returns The written {@link !Uint8Array}.
 */
export function writeFileHash(fileHash: FileHash): Uint8Array {
  return uint8ArrayConcat(Uint8Array.of(Tag[fileHash.algorithm]), fileHash.value);
}

/**
 * Write a {@link Leaf} value.
 *
 * {@link Leaf | Leaves} are written by concatenating (in order) their 8-byte header and their `VARBYTE` `payload`.
 *
 * > This function internally calls {@link writeBytes}.
 * >
 * > This function internally calls {@link writeUint}.
 *
 * @example
 * ```typescript
 * import { writeLeaf } from './src/write';
 *
 * console.log(writeLeaf({ type: 'bitcoin', height: 123 }));
 *   // Uint8Array(11) [ 0, 5, 136, 150, 13, 115, 215, 25, 1, 1, 123 ]
 * console.log(writeLeaf({ type: 'litecoin', height: 123 }));
 *   // Uint8Array(11) [ 0, 6, 134, 154, 13, 115, 215, 27, 69, 1, 123 ]
 * console.log(writeLeaf({ type: 'ethereum', height: 123 }));
 *   // Uint8Array(11) [ 0, 48, 254, 128, 135, 181, 199, 234, 215, 1, 123 ]
 * console.log(writeLeaf({ type: 'pending', url: new URL('https://www.example.com') }));
 *   // Uint8Array(35) [
 *   //     0, 131, 223, 227,  13,  46, 249,  12, 142,  25,  24,
 *   //   104, 116, 116, 112, 115,  58,  47,  47, 119, 119, 119,
 *   //    46, 101, 120,  97, 109, 112, 108, 101,  46,  99, 111,
 *   //   109, 47
 *   // ]
 * console.log(writeLeaf(
 *   {
 *     type: 'unknown',
 *     header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
 *     payload: Uint8Array.of(1, 2, 3),
 *   },
 * ));
 *   // Uint8Array(13) [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 3, 1, 2, 3 ]
 * ```
 *
 * @param leaf - The {@link Leaf} to write.
 * @returns The written {@link !Uint8Array}.
 */
export function writeLeaf(leaf: Leaf): Uint8Array {
  const resultParts: Uint8Array[] = [];
  resultParts.push(Uint8Array.of(Tag.attestation));
  switch (leaf.type) {
    case 'pending':
      resultParts.push(uint8ArrayFromHex(LeafHeader[leaf.type]));
      resultParts.push(writeBytes(writeBytes(textEncoder.encode(leaf.url.toString()))));
      break;
    case 'unknown':
      resultParts.push(leaf.header);
      resultParts.push(writeBytes(leaf.payload));
      break;
    default:
      resultParts.push(uint8ArrayFromHex(LeafHeader[leaf.type]));
      resultParts.push(writeBytes(writeUint(leaf.height)));
  }
  return uint8ArrayConcat(...resultParts);
}

/**
 * Write an {@link Edge} value.
 *
 * {@link Edge | Edges} are written by concatenating the following elements:
 *
 * 1. The {@link Edge}'s operation `type` {@link Tag}.
 * 2. If the {@link Edge}'s operation `type` is binary (ie. `append` or `prepend`), concatenate their `operand` as a `VARBYTE`.
 * 3. Finally, concatenate the {@link Edge}'s successor {@link Tree}.
 *
 * > This function internally calls {@link writeBytes}.
 * >
 * > This function internally calls {@link writeTree}.
 *
 * @example
 * ```typescript
 * import { newTree } from './src/internals';
 * import { writeEdge } from './src/write';
 *
 * console.log(writeEdge([{ type: 'sha1' }, newTree()]));
 *   // Uint8Array(1) [ 2 ]
 * console.log(writeEdge([{ type: 'ripemd160' }, newTree()]));
 *   // Uint8Array(1) [ 3 ]
 * console.log(writeEdge([{ type: 'sha256' }, newTree()]));
 *   // Uint8Array(1) [ 8 ]
 * console.log(writeEdge([{ type: 'keccak256' }, newTree()]));
 *   // Uint8Array(1) [ 103 ]
 * console.log(writeEdge([{ type: 'reverse' }, newTree()]));
 *   // Uint8Array(1) [ 242 ]
 * console.log(writeEdge([{ type: 'hexlify' }, newTree()]));
 *   // Uint8Array(1) [ 243 ]
 * console.log(writeEdge([{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()]));
 *   // Uint8Array(5) [ 240, 3, 1, 2, 3 ]
 * console.log(writeEdge([{ type: 'prepend', operand: Uint8Array.of(1, 2, 3) }, newTree()]));
 *   // Uint8Array(5) [ 241, 3, 1, 2, 3 ]
 * ```
 *
 * @param edge - The {@link Edge} to write.
 * @returns The written {@link !Uint8Array}.
 */
export function writeEdge(edge: Edge): Uint8Array {
  const [op, tree]: Edge = edge;
  const resultParts: Uint8Array[] = [];
  resultParts.push(Uint8Array.of(Tag[op.type]));
  if (op.type === 'append' || op.type === 'prepend') {
    resultParts.push(writeBytes(op.operand));
  }
  resultParts.push(writeTree(tree));
  return uint8ArrayConcat(...resultParts);
}

/**
 * Write a {@link Tree}'s value.
 *
 * A {@link Tree}'s value simply consists of all their "elements".
 * An "element" is either a {@link Leaf} or an {@link Edge}.
 * A {@link Tree}'s elements are listed in order, first its {@link Leaf | Leaves} (sorted via {@link compareLeaves}), then their {@link Edge | Edges} (sorted via {@link compareEdges}).
 * Now, _all but the last_ of these elements are written out like so:
 *
 * 1. Write a single-byte {@link nonFinal} tag.
 * 2. Write the element itself (either via {@link writeLeaf} or {@link writeEdge}, as applicable).
 *
 * Finally, the _last_ element is written itself (either via {@link writeLeaf} or {@link writeEdge}, as applicable).
 *
 * > This function internally calls {@link writeLeaf}.
 * >
 * > This function internally calls {@link writeEdge}.
 *
 * @example
 * ```typescript
 * import { newTree, EdgeMap, LeafSet } from './src/internals';
 * import { writeTree } from './src/write';
 *
 * console.log(writeTree(newTree()));
 *   // Uint8Array(0) []
 * console.log(writeTree(
 *   {
 *     edges: new EdgeMap(),
 *     leaves: new LeafSet()
 *       .add({ type: 'bitcoin', height: 123 }),
 *   },
 * ));
 *   // Uint8Array(11) [ 0, 5, 136, 150, 13, 115, 215, 25, 1, 1, 123 ]
 * console.log(writeTree(
 *   {
 *     edges: new EdgeMap(),
 *     leaves: new LeafSet()
 *       .add({ type: 'bitcoin', height: 123 })
 *       .add({ type: 'litecoin', height: 123 }),
 *   }
 * ));
 *   // Uint8Array(23) [
 *   //   255, 0,   5, 136, 150,  13, 115, 215, 25, 1,   1, 123,
 *   //     0, 6, 134, 154,  13, 115, 215,  27, 69, 1, 123
 *   // ]
 * console.log(writeTree(
 *   {
 *     edges: new EdgeMap()
 *       .add({ type: 'sha1' }, newTree()),
 *     leaves: new LeafSet()
 *       .add({ type: 'bitcoin', height: 123 }),
 *   },
 * ));
 *   // Uint8Array(13) [ 255, 0, 5, 136, 150, 13, 115, 215, 25, 1, 1, 123, 2 ]
 * console.log(writeTree(
 *   {
 *     edges: new EdgeMap()
 *       .add({ type: 'sha1' }, newTree())
 *       .add({ type: 'sha256' }, newTree()),
 *     leaves: new LeafSet(),
 *   },
 * ));
 *   // Uint8Array(3) [ 255, 2, 8 ]
 * ```
 *
 * @param tree - The {@link Tree} to write.
 * @returns The written {@link !Uint8Array}.
 */
export function writeTree(tree: Tree): Uint8Array {
  const leaves: Leaf[] = tree.leaves.values();
  const edges: Edge[] = tree.edges.entries();
  const totalLength: number = leaves.length + edges.length;
  const resultParts: Uint8Array[] = [];
  leaves.sort(compareLeaves);
  edges.sort(compareEdges);
  if (1 < totalLength) {
    for (let i = 0; i < totalLength - 1; i++) {
      resultParts.push(Uint8Array.of(nonFinal));
      if (i < leaves.length) {
        resultParts.push(writeLeaf(leaves[i]!));
      } else {
        resultParts.push(writeEdge(edges[i - leaves.length]!));
      }
    }
  }
  if (0 < edges.length) {
    resultParts.push(writeEdge(edges[edges.length - 1]!));
  } else if (0 < leaves.length) {
    resultParts.push(writeLeaf(leaves[leaves.length - 1]!));
  }
  return uint8ArrayConcat(...resultParts);
}

/**
 * Write a {@link Timestamp}'s value.
 *
 * A {@link Timestamp} is written by concatenating the following parts in order:
 *
 * 1. A {@link magicHeader | "magic header"} to indicate that this is a {@link Timestamp} data stream.
 * 2. The `version` used to write the value.
 * 3. The {@link Timestamp}'s {@link FileHash}.
 * 4. The {@link Timestamp}'s {@link Tree}.
 *
 * > This function internally calls {@link writeUint}.
 * >
 * > This function internally calls {@link writeFileHash}.
 * >
 * > This function internally calls {@link writeTree}.
 *
 * @example
 * ```typescript
 * import { newTree } from './src/internals';
 * import { write } from './src/write';
 *
 * console.log(write(
 *   {
 *     version: 1,
 *     fileHash: {
 *       algorithm: 'sha1',
 *       value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *     },
 *     tree: newTree(),
 *   }),
 * );
 *   // Uint8Array(53) [
 *   //    0,  79, 112, 101, 110,  84, 105, 109, 101, 115, 116,  97, 109,
 *   //  112, 115,   0,   0,  80, 114, 111, 111, 102,   0, 191, 137, 226,
 *   //  232, 132, 232, 146, 148,   1,   2,   1,   2,   3,   4,   5,   6,
 *   //    7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,  19,
 *   //   20
 *   // ]
 * ```
 *
 * @param timestamp - The {@link Timestamp} to write.
 * @returns The written {@link !Uint8Array}.
 */
export function write(timestamp: Timestamp): Uint8Array {
  return uint8ArrayConcat(
    magicHeader,
    writeUint(timestamp.version),
    writeFileHash(timestamp.fileHash),
    writeTree(timestamp.tree),
  );
}
