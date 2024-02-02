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

import type { Leaf, Verifier } from '../types';

import {
  fetchBody,
  textDecoder,
  uint8ArrayEquals,
  uint8ArrayFromHex,
  uint8ArrayReversed,
  uint8ArrayToHex,
} from '../utils';

export default (async (msg: Uint8Array, leaf: Leaf): Promise<number | undefined> => {
  if ('bitcoin' !== leaf.type) {
    return undefined;
  }
  const block: unknown = JSON.parse(
    textDecoder.decode(await fetchBody(new URL(`https://blockchain.info/rawblock/${leaf.height}`))),
  );
  if (
    'object' !== typeof block ||
    null === block ||
    !('mrkl_root' in block) ||
    'string' !== typeof block.mrkl_root ||
    !/^[0-9a-f]{64}$/i.test(block.mrkl_root) ||
    !('time' in block) ||
    'number' !== typeof block.time ||
    block.time < 0 ||
    !Number.isSafeInteger(block.time)
  ) {
    throw new Error('Malformed response');
  }
  const expected: Uint8Array = uint8ArrayReversed(msg);
  const found: Uint8Array = uint8ArrayFromHex(block.mrkl_root);
  if (!uint8ArrayEquals(expected, found)) {
    throw new Error(`Merkle root mismatch (expected ${uint8ArrayToHex(expected)} but found ${uint8ArrayToHex(found)})`);
  }
  return block.time;
}) satisfies Verifier;
