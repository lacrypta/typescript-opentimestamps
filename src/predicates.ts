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

import { treeToPaths } from './internals';
import { LeafHeader, Path, Paths, Timestamp } from './types';
import { uint8ArrayEquals, uint8ArrayFromHex } from './utils';

export function canShrinkTimestamp(
  timestamp: Timestamp,
  chain: 'bitcoin' | 'litecoin' | 'ethereum' | Uint8Array,
): boolean {
  const chainHeader: Uint8Array = chain instanceof Uint8Array ? chain : uint8ArrayFromHex(LeafHeader[chain]);
  const paths: Paths = treeToPaths(timestamp.tree);
  return (
    paths.some(
      ({ leaf }: Path): boolean =>
        'pending' !== leaf.type &&
        uint8ArrayEquals(chainHeader, 'unknown' === leaf.type ? leaf.header : uint8ArrayFromHex(LeafHeader[leaf.type])),
    ) &&
    paths.some(
      ({ leaf }: Path): boolean =>
        'pending' === leaf.type ||
        !uint8ArrayEquals(
          chainHeader,
          'unknown' === leaf.type ? leaf.header : uint8ArrayFromHex(LeafHeader[leaf.type]),
        ),
    )
  );
}

export function canUpgradeTimestamp(timestamp: Timestamp): boolean {
  return treeToPaths(timestamp.tree).some(({ leaf }: Path): boolean => 'pending' === leaf.type);
}

export function canVerifyTimestamp(timestamp: Timestamp): boolean {
  return treeToPaths(timestamp.tree).some(({ leaf }: Path): boolean => 'pending' !== leaf.type);
}
