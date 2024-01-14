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

import type { Leaf, Verifier } from '../types';

import { fetchBody, uint8ArrayEquals, uint8ArrayFromHex } from '../utils';

export const verify: Verifier = async (msg: Uint8Array, leaf: Leaf): Promise<number | undefined> => {
  if ('bitcoin' !== leaf.type) {
    return undefined;
  }
  const block: unknown = JSON.parse(
    new TextDecoder().decode(await fetchBody(new URL(`https://blockchain.info/rawblock/${leaf.height}`))),
  );
  if (!uint8ArrayEquals(msg, uint8ArrayFromHex((block as { mrkl_root: string }).mrkl_root))) {
    throw new Error('Merkle root mismatch');
  }
  return (block as { time: number }).time;
};
