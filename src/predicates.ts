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

import type { Path, Paths } from './internals';
import type { Timestamp } from './types';

import { treeToPaths } from './internals';

export function canShrink(timestamp: Timestamp, chain: 'bitcoin' | 'litecoin' | 'ethereum'): boolean {
  const paths: Paths = treeToPaths(timestamp.tree);
  return 1 < paths.length && paths.some(({ leaf }: Path): boolean => chain === leaf.type);
}

export function canUpgrade(timestamp: Timestamp): boolean {
  return treeToPaths(timestamp.tree).some(({ leaf }: Path): boolean => 'pending' === leaf.type);
}

export function canVerify(timestamp: Timestamp): boolean {
  return treeToPaths(timestamp.tree).some(({ leaf }: Path): boolean => 'pending' !== leaf.type);
}
