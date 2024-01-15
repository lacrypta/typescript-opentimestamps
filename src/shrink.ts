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

'use strict';

import type { Leaf, Path, Timestamp } from './types';

import { treeToPaths, pathsToTree, normalizeTimestamp } from './internals';

export function shrinkTimestamp(timestamp: Timestamp, chain: 'bitcoin' | 'litecoin' | 'ethereum'): Timestamp {
  const shrunkenPath: Path | undefined = treeToPaths(timestamp.tree)
    .filter(({ leaf }: { leaf: Leaf }): boolean => chain === leaf.type)
    .reduce((left: Path | undefined, right: Path): Path => {
      if (undefined === left) {
        return right;
      } else if ((left.leaf as { height: number }).height <= (right.leaf as { height: number }).height) {
        return left;
      } else {
        return right;
      }
    }, undefined);
  if (undefined === shrunkenPath) {
    return timestamp;
  } else {
    return normalizeTimestamp({
      fileHash: timestamp.fileHash,
      version: timestamp.version,
      tree: pathsToTree([shrunkenPath]),
    })!;
  }
}
