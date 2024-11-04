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
 * This module exposes functions and constants used for submitting hashes to calendars.
 *
 * @packageDocumentation
 * @module
 */

import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

import type { FileHash, Timestamp, Tree } from './types';

import { incorporateTreeToTree, newTree, EdgeMap, LeafSet } from './internals';
import { readTree } from './read';
import { retrievePostBody } from './utils';
import { validateCalendarUrl, validateFileHashValue } from './validation';

/**
 * A list of calendar {@link !URL | URLs} to use by default, in case none are provided.
 *
 * This list consists of:
 *
 * - [Alice (OpenTimestamps)](https://alice.btc.calendar.opentimestamps.org)
 * - [Bob (OpenTimestamps)](https://bob.btc.calendar.opentimestamps.org)
 * - [Finney's Calendar](https://finney.calendar.eternitywall.com)
 * - [Catallaxy's Calendar](https://btc.calendar.catallaxy.com)
 *
 */
export const defaultCalendarUrls: URL[] = [
  new URL('https://alice.btc.calendar.opentimestamps.org'),
  new URL('https://bob.btc.calendar.opentimestamps.org'),
  new URL('https://finney.calendar.eternitywall.com'),
  new URL('https://btc.calendar.catallaxy.com'),
];

/**
 * Submit the given value to the given list of calendars.
 *
 * This function will take an algorithm (one of `sha1`, `ripemd160`, `sha256`, or `keccak256`), and an algorithm value (either a 20- or 32-byte value), and submits said value to each of the given calendars.
 *
 * Prior to submission, a "fudge" value is hashed alongside the given one, to prevent information leakage.
 * This fudge value may be given explicitly, or it may be randomly generated if none given.
 *
 * {@link !Error | Errors} encountered upon submission are not thrown, but rather collected and returned alongside the resulting {@link Timestamp}.
 *
 * > This function internally calls {@link retrievePostBody}.
 * >
 * > This function internally calls {@link validateCalendarUrl}.
 * >
 * > This function internally calls {@link validateFileHashValue}.
 *
 * @example
 * ```typescript
 * import type { Timestamp } from './src/types';
 *
 * import { info } from './src/info';
 * import { submit } from './src/submit';
 *
 * const { timestamp, errors }: { timestamp: Timestamp; errors: Error[] } = await submit(
 *   'sha1',
 *   Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *   Uint8Array.of(1, 2, 3, 12, 23, 123),
 * );
 *
 * console.log(info(timestamp));
 *   // msg = sha1(FILE)
 *   // msg = append(msg, 0102030c177b)
 *   // msg = sha256(msg)
 *   //  -> msg = append(msg, 7bcfb7de87d0394c023b35e16003f936)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, a831953f37b90a9f5ebbcdee7e968622aff0c000c67c9fb8bee3eaf992959693)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, 65cb5387)
 *   //     msg = append(msg, b31df2f301366f3c)
 *   //     pendingVerify(msg, https://alice.btc.calendar.opentimestamps.org/)
 *   //  -> msg = append(msg, b7ed9e86271b179715445d568316d1d5)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, 65cb5387)
 *   //     msg = append(msg, 279f5cc8a3eea096)
 *   //     pendingVerify(msg, https://bob.btc.calendar.opentimestamps.org/)
 *   //  -> msg = append(msg, b852c30e4a6b1420c27d50a7cd40c7d2)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, c80f4d3abef43c6017ce3db34d3b7389a09ab31ae274204e12cd8babb1bafa95)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, 65cb5388)
 *   //     msg = append(msg, ddf860cef5179119)
 *   //     pendingVerify(msg, https://finney.calendar.eternitywall.com/)
 *   //  -> msg = append(msg, e71ef69c247fc026beb260bb38b01545)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, 767bc5417dca9794849f2d67c10480f6c1b715f6dfb0444b9218d36ab55d2d75)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, 65cb5388)
 *   //     msg = append(msg, b1d4d0b7fb122cea)
 *   //     pendingVerify(msg, https://btc.calendar.catallaxy.com/)
 * console.log(errors);
 *   // []
 * ```
 *
 * @param algorithm - The hashing algorithm to use.
 * @param value - The value to hash.
 * @param fudge - The fudging string to add (if not given, use a 16 random bytes).
 * @param calendarUrls - The calendars to submit the hashed value to, if not give, use {@link defaultCalendarUrls}.
 * @returns An object, mapping `timestamp` to the resulting {@link Timestamp}, and `errors` to a list of {@link !Error | Errors} encountered.
 */
export async function submit(
  algorithm: 'sha1' | 'ripemd160' | 'sha256' | 'keccak256',
  value: Uint8Array,
  fudge?: Uint8Array,
  calendarUrls?: URL[],
): Promise<{ timestamp: Timestamp; errors: Error[] }> {
  const fileHash: FileHash = validateFileHashValue(algorithm, value);
  calendarUrls ??= defaultCalendarUrls;
  fudge ??= randomBytes(16);

  calendarUrls.forEach((url: URL): void => void validateCalendarUrl(url.toString()));

  const fudgedValue: Uint8Array = sha256(Uint8Array.of(...value, ...fudge));

  const [stampedTree, stampingErrors]: [Tree, Error[]] = (
    await Promise.all(
      calendarUrls.map(async (url: URL): Promise<Tree | Error> => {
        try {
          const body: Uint8Array = await retrievePostBody(
            new URL(`${url.toString().replace(/\/$/, '')}/digest`),
            fudgedValue,
          );
          const [tree, end]: [Tree, number] = readTree(body, 0);
          if (end !== body.length) {
            throw new Error('Garbage at end of calendar response');
          }
          return tree;
        } catch (e: unknown) {
          return new Error(`Error (${url.toString()}): ${(e as Error).message}`);
        }
      }),
    )
  ).reduce(
    ([tree, errors]: [Tree, Error[]], right: Tree | Error): [Tree, Error[]] => {
      return right instanceof Error ? [tree, errors.concat([right])] : [incorporateTreeToTree(tree, right), errors];
    },
    [newTree(), [] as Error[]],
  );

  const resultTree: Tree = {
    leaves: new LeafSet(),
    edges: new EdgeMap().add({ type: 'sha256' }, stampedTree),
  };

  const fudgedTree: Tree =
    0 === fudge.length
      ? resultTree
      : { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'append', operand: fudge }, resultTree) };

  return {
    timestamp: {
      version: 1,
      fileHash,
      tree: fudgedTree,
    },
    errors: stampingErrors,
  };
}
