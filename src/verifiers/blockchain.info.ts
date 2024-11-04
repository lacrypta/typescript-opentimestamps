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
 * Implementation of a {@link types!Verifier | Verifier} using [Blockchain.info](https://blockchain.info)'s API.
 *
 * @packageDocumentation
 * @module
 */

import type { Leaf, Verifier } from '../types';

import {
  fetchBody,
  textDecoder,
  uint8ArrayEquals,
  uint8ArrayFromHex,
  uint8ArrayReversed,
  uint8ArrayToHex,
} from '../utils';

/**
 * Call [Blockchain.info](https://blockchain.info)'s API to verify the given {@link Leaf}.
 *
 * If the given {@link Leaf} is a `bitcoin` one, call [Blockchain.info](https://blockchain.info)'s API with the given {@link Leaf}'s `height` and verify that the Merkle root corresponds with the given expected one.
 * Otherwise, return `undefined`.
 *
 * @param msg - Message to expect at the block's Merkle root.
 * @param leaf - {@link Leaf} to verify.
 * @return Either the UNIX timestamp corresponding to the block in question, or `undefined` if the given {@link Leaf} is not a `bitcoin` one.
 * @throws {@link !Error} if the API's response is malformed.
 * @throws {@link !Error} if the Merkle root in the block in question does not match the expected Merkle root.
 */
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
