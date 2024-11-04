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
 * This module exposes predicate functions.
 *
 * @packageDocumentation
 * @module
 */

import type { Path, Paths } from './internals';
import type { Timestamp, Leaf } from './types';

import { treeToPaths } from './internals';

/**
 * Determine whether the given {@link Timestamp} can be shrunk on the given chain.
 *
 * In order for a {@link Timestamp} to be shrunk, it needs to have at least one {@link Leaf} on the given chain, and at least one other {@link Leaf}.
 * Shrinking it would remove all but the oldest {@link Leaf} on the given chain.
 *
 * @example
 * ```typescript
 * import { EdgeMap, LeafSet } from './src/internals';
 * import { canShrink } from './src/predicates';
 *
 * console.log(
 *   canShrink(
 *     {
 *       version: 1,
 *       fileHash: {
 *         algorithm: 'sha1',
 *         value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                              11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *       },
 *       tree: {
 *         edges: new EdgeMap(),
 *         leaves: new LeafSet()
 *           .add({ type: 'bitcoin', height: 123 })
 *           .add({ type: 'bitcoin', height: 456 }),
 *       },
 *     },
 *     'bitcoin',
 *   ),
 * );
 *   // true
 * console.log(
 *   canShrink(
 *     {
 *       version: 1,
 *       fileHash: {
 *         algorithm: 'sha1',
 *         value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                              11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *       },
 *       tree: {
 *         edges: new EdgeMap(),
 *         leaves: new LeafSet()
 *           .add({ type: 'bitcoin', height: 123 }),
 *       },
 *     },
 *     'bitcoin',
 *   ),
 * );
 *   // false
 * ```
 *
 * @param timestamp - The {@link Timestamp} being queried.
 * @param chain - The chain in question.
 * @returns `true` if the given {@link Timestamp} can be shrunk on the given chain, `false` otherwise.
 */
export function canShrink(timestamp: Timestamp, chain: 'bitcoin' | 'litecoin' | 'ethereum'): boolean {
  const paths: Paths = treeToPaths(timestamp.tree);
  return 1 < paths.length && paths.some(({ leaf }: Path): boolean => chain === leaf.type);
}

/**
 * Determine whether the given {@link Timestamp} can be upgraded.
 *
 * In order for a {@link Timestamp} to be upgraded, it needs to have at least one `pending` {@link Leaf}.
 *
 * @example
 * ```typescript
 * import { EdgeMap, LeafSet } from './src/internals';
 * import { canUpgrade } from './src/predicates';
 *
 * console.log(
 *   canUpgrade({
 *     version: 1,
 *     fileHash: {
 *       algorithm: 'sha1',
 *       value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *     },
 *     tree: {
 *       edges: new EdgeMap(),
 *       leaves: new LeafSet()
 *         .add({ type: 'bitcoin', height: 123 })
 *         .add({ type: 'pending', url: new URL('https://www.example.com') }),
 *     },
 *   }),
 * );
 *   // true
 * console.log(
 *   canUpgrade({
 *     version: 1,
 *     fileHash: {
 *       algorithm: 'sha1',
 *       value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *     },
 *     tree: {
 *       edges: new EdgeMap(),
 *       leaves: new LeafSet()
 *         .add({ type: 'bitcoin', height: 123 })
 *         .add({ type: 'litecoin', height: 123 }),
 *     },
 *   }),
 * );
 *   // false
 * ```
 *
 * @param timestamp - The {@link Timestamp} in question.
 * @returns `true` if the given {@link Timestamp} can be upgraded, `false` otherwise.
 */
export function canUpgrade(timestamp: Timestamp): boolean {
  return treeToPaths(timestamp.tree).some(({ leaf }: Path): boolean => 'pending' === leaf.type);
}

/**
 * Determine whether the given {@link Timestamp} can be verified.
 *
 * In order for a {@link Timestamp} to be verified, it needs to have at least one non-`pending` {@link Leaf}.
 *
 * @example
 * ```typescript
 * import { EdgeMap, LeafSet } from './src/internals';
 * import { canVerify } from './src/predicates';
 *
 * console.log(
 *   canVerify({
 *     version: 1,
 *     fileHash: {
 *       algorithm: 'sha1',
 *       value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *     },
 *     tree: {
 *       edges: new EdgeMap(),
 *       leaves: new LeafSet()
 *         .add({ type: 'bitcoin', height: 123 })
 *         .add({ type: 'pending', url: new URL('https://www.example.com') }),
 *     },
 *   }),
 * );
 *   // true
 * console.log(
 *   canVerify({
 *     version: 1,
 *     fileHash: {
 *       algorithm: 'sha1',
 *       value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *     },
 *     tree: {
 *       edges: new EdgeMap(),
 *       leaves: new LeafSet()
 *         .add({ type: 'pending', url: new URL('https://www.example.com/1') })
 *         .add({ type: 'pending', url: new URL('https://www.example.com/2') }),
 *     },
 *   }),
 * );
 *   // false
 * ```
 *
 * @param timestamp - The {@link Timestamp} in question.
 * @returns `true` if the given {@link Timestamp} can be verified, `false` otherwise.
 */
export function canVerify(timestamp: Timestamp): boolean {
  return treeToPaths(timestamp.tree).some(({ leaf }: Path): boolean => 'pending' !== leaf.type);
}
