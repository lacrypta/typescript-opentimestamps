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
 * This module exposes the shrinking functions.
 *
 * @packageDocumentation
 * @module
 */

import type { Path, Paths } from './internals';
import type { Leaf, Timestamp } from './types';

import { pathsToTree, treeToPaths } from './internals';

/**
 * Shrink the given {@link Timestamp} on the given chain.
 *
 * Shrinking a {@link Timestamp} consists of eliminating all {@link Paths} other than the one leading to the _oldest_ {@link Leaf} on the given chain.
 * This allows the {@link Timestamp} to be smaller, only keeping the most stringent {@link Leaf | attestation} for the chosen chain.
 *
 * Note that shrinking an already shrunken {@link Timestamp} does nothing.
 *
 * @example
 * ```typescript
 * import type { Timestamp } from './src/types';
 *
 * import { info } from './src/info';
 * import { EdgeMap, LeafSet } from './src/internals';
 * import { shrink } from './src/shrink';
 *
 * const timestamp: Timestamp = {
 *   version: 1,
 *   fileHash: {
 *     algorithm: 'sha1',
 *     value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                          11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *   },
 *   tree: {
 *     edges: new EdgeMap(),
 *     leaves: new LeafSet()
 *       .add({ type: 'bitcoin', height: 123 })
 *       .add({ type: 'bitcoin', height: 456 }),
 *   },
 * };
 *
 * console.log(info(shrink(timestamp, 'bitcoin')));
 *   // msg = sha1(FILE)
 *   // bitcoinVerify(msg, 123)
 * console.log(info(shrink(shrink(timestamp, 'bitcoin'), 'bitcoin')));
 *   // msg = sha1(FILE)
 *   // bitcoinVerify(msg, 123)
 * ```
 *
 * @param timestamp - The {@link Timestamp} to shrink.
 * @param chain - The chain to look into for shrinking.
 * @returns The shrunken {@link Timestamp}.
 */
export function shrink(timestamp: Timestamp, chain: 'bitcoin' | 'litecoin' | 'ethereum'): Timestamp {
  const shrunkenPath: Path | undefined = treeToPaths(timestamp.tree)
    .filter(({ leaf }: { leaf: Leaf }): boolean => chain === leaf.type)
    .reduce((left: Path | undefined, right: Path): Path => {
      if (undefined === left) {
        return right;
      }
      const leftHeight: number = (left.leaf as { height: number }).height;
      const rightHeight: number = (right.leaf as { height: number }).height;
      if (leftHeight <= rightHeight) {
        return left;
      } else {
        return right;
      }
    }, undefined);
  if (undefined === shrunkenPath) {
    return timestamp;
  } else {
    return {
      fileHash: timestamp.fileHash,
      version: timestamp.version,
      tree: pathsToTree([shrunkenPath]),
    };
  }
}
