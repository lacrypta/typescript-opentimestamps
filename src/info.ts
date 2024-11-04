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
 * This module exposes functions related to the human-readable output of {@link types!Timestamp | Timestamps}.
 *
 * @packageDocumentation
 * @module
 */

import type { Edge } from './internals';
import type { FileHash, Leaf, Op, Timestamp, Tree } from './types';

import { callOp, compareEdges, compareLeaves } from './internals';
import { uint8ArrayToHex } from './utils';

/**
 * Indent the given string, line by line, prepending the first line with a marker (ie. `" -> "`).
 *
 * @example
 * ```typescript
 * import { indent } from './src/info';
 *
 * console.log(indent(''));
 *   // ->
 * console.log(indent('something'));
 *   // -> something
 * console.log(indent('something\nelse'));
 *   // -> something
 *   //    else
 * console.log(indent('something\nelse\nentirely'));
 *   // -> something
 *   //    else
 *   //    entirely
 * ```
 *
 * @param text - Text to indent.
 * @returns The indented text.
 */
export function indent(text: string): string {
  const [first, ...rest]: string[] = text.split('\n');
  return [` -> ${first}`].concat(rest.map((line: string): string => `    ${line}`)).join('\n');
}

/**
 * Generate a human-readable string form the given {@link Leaf}.
 *
 * Human readable strings are generated as (possibly _"faux generic"_) function calls, the names of these functions depending on the {@link Leaf}'s `type`:
 *
 * - **`pending`:** simply `pendingVerify`.
 * - **`unknown`:** the _"faux generic"_ `unknownVerify<HEADER_AS_HEX>`.
 * - **`bitcoin`, `litecoin`, or `ethereum`:** simply `bitcoinVerify`, `litecoinVerify`, or `ethereumVerify`.
 *
 * @example
 * ```typescript
 * import { infoLeaf } from './src/info';
 *
 * console.log(infoLeaf({ type: 'bitcoin', height: 123 }));
 *   // bitcoinVerify(msg, 123)
 * console.log(infoLeaf({ type: 'litecoin', height: 456 }));
 *   // litecoinVerify(msg, 456)
 * console.log(infoLeaf({ type: 'ethereum', height: 789 }));
 *   // ethereumVerify(msg, 789)
 * console.log(infoLeaf({
 *   type: 'pending',
 *   url: new URL('https://www.example.com'),
 * }));
 *   // pendingVerify(msg, https://www.example.com/)
 * console.log(infoLeaf({
 *   type: 'unknown',
 *   header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
 *   payload: Uint8Array.of(1, 2, 3),
 * }));
 *   // unknownVerify<0102030405060708>(msg, 010203)
 * ```
 *
 * @param leaf - {@link Leaf} to generate human-readable string for.
 * @returns Human-readable string generated.
 */
export function infoLeaf(leaf: Leaf): string {
  switch (leaf.type) {
    case 'pending':
      return `pendingVerify(msg, ${leaf.url.toString()})`;
    case 'unknown':
      return `unknownVerify<${uint8ArrayToHex(leaf.header)}>(msg, ${uint8ArrayToHex(leaf.payload)})`;
    default:
      return `${leaf.type}Verify(msg, ${leaf.height})`;
  }
}

/**
 * Generate a human-readable string form the given {@link Edge}.
 *
 * Human readable strings are generated as simple function calls, their names being given by the {@link Op | operation}'s `type`.
 *
 * If the optional `msg` parameter is given, it is used to generate verbose output (aligned to the function's `=` sign), showing the result of applying the operation in question to the given {@link !Uint8Array} value.
 *
 * @example
 * ```typescript
 * import { infoEdge } from './src/info';
 * import { EdgeMap, LeafSet } from './src/internals';
 *
 * console.log(infoEdge(
 *   [ { type: 'append', operand: Uint8Array.of(7, 8, 9) },
 *     { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
 *   ],
 *   undefined,
 * ));
 *   // msg = append(msg, 070809)
 *   // bitcoinVerify(msg, 123)
 * console.log(infoEdge(
 *   [ { type: 'append', operand: Uint8Array.of(7, 8, 9) },
 *     { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
 *   ],
 *   Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10),
 * ));
 *   // msg = append(msg, 070809)
 *   //     = 0102030405060708090a070809
 *   // bitcoinVerify(msg, 123)
 * ```
 *
 * @param edge - {@link Edge} to generate human-readable string for.
 * @param msg - Optional message to use as {@link Op | operation} input for verbose output.
 * @returns Human-readable string generated.
 */
export function infoEdge(edge: Edge, msg: Uint8Array | undefined): string {
  const resultParts: string[] = [];
  const [op, tree]: [Op, Tree] = edge;
  const newMsg: Uint8Array | undefined = undefined === msg ? undefined : callOp(op, msg);
  switch (op.type) {
    case 'append':
    case 'prepend':
      resultParts.push(`msg = ${op.type}(msg, ${uint8ArrayToHex(op.operand)})`);
      break;
    default:
      resultParts.push(`msg = ${op.type}(msg)`);
  }
  if (undefined !== newMsg) {
    resultParts.push(`    = ${uint8ArrayToHex(newMsg)}`);
  }
  const treeInfo: string = infoTree(tree, newMsg);
  if ('' !== treeInfo) {
    resultParts.push(treeInfo);
  }
  return resultParts.join('\n');
}

/**
 * Generate a human-readable string form the given {@link Tree}.
 *
 * Human-readable strings are generated as lists of {@link Op | operations} whenever possible, only reverting to {@link indent | indentation} when a given {@link Tree} node has more than one successor (ie. either a {@link Leaf} or an {@link Edge}).
 *
 * If the optional `msg` parameter is given, it is passed to {@link infoEdge} to show verbose output.
 *
 * @example
 * ```typescript
 * import type { Tree } from './src/types';
 *
 * import { infoTree } from './src/info';
 * import { EdgeMap, LeafSet } from './src/internals';
 *
 * const tree: Tree = {
 *   leaves: new LeafSet(),
 *   edges: new EdgeMap().add(
 *     { type: 'prepend', operand: Uint8Array.of(1, 2, 3) },
 *     {
 *       leaves: new LeafSet(),
 *       edges: new EdgeMap()
 *         .add(
 *           { type: 'reverse' },
 *           {
 *             leaves: new LeafSet(),
 *             edges: new EdgeMap().add(
 *               {
 *                 type: 'append',
 *                 operand: Uint8Array.of(7, 8, 9),
 *               },
 *               {
 *                 edges: new EdgeMap(),
 *                 leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
 *               },
 *             ),
 *           },
 *         )
 *         .add(
 *           { type: 'prepend', operand: Uint8Array.of(4, 5, 6) },
 *           { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }) },
 *         ),
 *     },
 *   ),
 * };
 *
 * console.log(infoTree(tree, undefined));
 *   // msg = prepend(msg, 010203)
 *   //  -> msg = reverse(msg)
 *   //     msg = append(msg, 070809)
 *   //     bitcoinVerify(msg, 123)
 *   //  -> msg = prepend(msg, 040506)
 *   //     bitcoinVerify(msg, 456)
 * console.log(infoTree(tree, Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)));
 *   // msg = prepend(msg, 010203)
 *   //     = 0102030102030405060708090a
 *   //  -> msg = reverse(msg)
 *   //         = 0a090807060504030201030201
 *   //     msg = append(msg, 070809)
 *   //         = 0a090807060504030201030201070809
 *   //     bitcoinVerify(msg, 123)
 *   //  -> msg = prepend(msg, 040506)
 *   //         = 0405060102030102030405060708090a
 *   //     bitcoinVerify(msg, 456)
 * ```
 *
 * @param tree - {@link Tree} to generate human-readable string for.
 * @param msg - Optional message to use for verbose output.
 * @returns Human-readable string generated.
 */
export function infoTree(tree: Tree, msg: Uint8Array | undefined): string {
  const leaves: Leaf[] = tree.leaves.values();
  const edges: Edge[] = tree.edges.entries();
  const leavesSize: number = leaves.length;
  const edgesSize: number = edges.length;
  leaves.sort(compareLeaves);
  edges.sort(compareEdges);

  const doIndent: (x: string) => string = 1 < leavesSize + edgesSize ? indent : (x: string): string => x;

  const resultParts: string[] = tree.leaves
    .values()
    .map((leaf: Leaf): string => doIndent(infoLeaf(leaf)))
    .concat(tree.edges.entries().map((edge: Edge): string => doIndent(infoEdge(edge, msg))));
  return resultParts.join('\n');
}

/**
 * Generate a human-readable string form the given {@link FileHash}.
 *
 * Human-readable strings are generated as simple function calls, using the {@link FileHash}'s `algorithm` as name and the `FILE` pseudo-variable.
 *
 * If the `verbose` parameter is true, the {@link FileHash}'s `value` is also shown, (aligned to the function's `=` sign).
 *
 * @example
 * ```typescript
 * import type { FileHash } from './src/types';
 *
 * import { infoFileHash } from './src/info';
 *
 * const fileHash: FileHash = {
 *   algorithm: 'sha1',
 *   value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                        11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 * };
 *
 * console.log(infoFileHash(fileHash, false));
 *   // msg = sha1(FILE)
 * console.log(infoFileHash(fileHash, true));
 *   // msg = sha1(FILE)
 *   //     = 0102030405060708090a0b0c0d0e0f1011121314
 * ```
 *
 * @param fileHash - {@link FileHash} to generate human-readable string for.
 * @param verbose - Whether to include the `value` field in the output or not.
 * @returns Human-readable string generated.
 */
export function infoFileHash(fileHash: FileHash, verbose: boolean): string {
  const resultParts: string[] = [];
  resultParts.push(`msg = ${fileHash.algorithm}(FILE)`);
  if (verbose) {
    resultParts.push(`    = ${uint8ArrayToHex(fileHash.value)}`);
  }
  return resultParts.join('\n');
}

/**
 * Generate a human-readable string form the given {@link Timestamp}.
 *
 * Human-readable strings are generated as a concatenation of:
 *
 * - The {@link Timestamp}'s `version` (as a _"faux comment"_, and only if the `verbose` parameter is true).
 * - The {@link Timestamp}'s `fileHash` as a simple function call.
 * - Function call trees for the main {@link Timestamp} `tree`.
 *
 * @example
 * ```typescript
 * import type { Timestamp } from './src/types';
 *
 * import { info } from './src/info';
 * import { EdgeMap, LeafSet } from './src/internals';
 *
 * const timestamp: Timestamp = {
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
 * };
 *
 * console.log(info(timestamp));
 *   // msg = sha1(FILE)
 *   // msg = prepend(msg, 010203)
 *   //  -> msg = reverse(msg)
 *   //     msg = append(msg, 070809)
 *   //     bitcoinVerify(msg, 123)
 *   //  -> msg = prepend(msg, 040506)
 *   //     bitcoinVerify(msg, 456)
 * console.log(info(timestamp, true));
 *   // # version: 1
 *   // msg = sha1(FILE)
 *   //     = 0102030405060708090a0b0c0d0e0f1011121314
 *   // msg = prepend(msg, 010203)
 *   //     = 0102030102030405060708090a0b0c0d0e0f1011121314
 *   //  -> msg = reverse(msg)
 *   //         = 14131211100f0e0d0c0b0a090807060504030201030201
 *   //     msg = append(msg, 070809)
 *   //         = 14131211100f0e0d0c0b0a090807060504030201030201070809
 *   //     bitcoinVerify(msg, 123)
 *   //  -> msg = prepend(msg, 040506)
 *   //         = 0405060102030102030405060708090a0b0c0d0e0f1011121314
 *   //     bitcoinVerify(msg, 456)
 * ```
 *
 * @param timestamp - {@link Timestamp} to generate human-readable string for.
 * @param verbose - Whether to include the `value` field in the output or not.
 * @returns Human-readable string generated.
 */
export function info(timestamp: Timestamp, verbose: boolean = false): string {
  const resultParts: string[] = [];
  if (verbose) {
    resultParts.push(`# version: ${timestamp.version}`);
  }
  resultParts.push(infoFileHash(timestamp.fileHash, verbose));
  const treeInfo: string = infoTree(timestamp.tree, verbose ? timestamp.fileHash.value : undefined);
  if ('' !== treeInfo) {
    resultParts.push(treeInfo);
  }
  return resultParts.join('\n');
}
