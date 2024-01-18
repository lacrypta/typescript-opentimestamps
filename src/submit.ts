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

import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

import type { FileHash, Timestamp, Tree } from './types';

import { incorporateTreeToTree, newEdges, newLeaves, newTree, normalizeTimestamp } from './internals';
import { readTree } from './read';
import { retrievePostBody } from './utils';
import { validateCalendarUrl, validateFileHashValue } from './validation';

export const defaultCalendarUrls: URL[] = [
  new URL('https://alice.btc.calendar.opentimestamps.org'),
  new URL('https://bob.btc.calendar.opentimestamps.org'),
  new URL('https://finney.calendar.eternitywall.com'),
  new URL('https://btc.calendar.catallaxy.com'),
];

export async function submitTimestamp(
  algorithm: string,
  value: Uint8Array,
  fudge?: Uint8Array,
  calendarUrls?: URL[],
): Promise<{ timestamp: Timestamp | undefined; errors: Error[] }> {
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
    leaves: newLeaves(),
    edges: newEdges().add({ type: 'sha256' }, stampedTree),
  };

  const fudgedTree: Tree =
    0 === fudge.length
      ? resultTree
      : { leaves: newLeaves(), edges: newEdges().add({ type: 'append', operand: fudge }, resultTree) };

  return {
    timestamp: normalizeTimestamp({
      version: 1,
      fileHash,
      tree: fudgedTree,
    }),
    errors: stampingErrors,
  };
}
