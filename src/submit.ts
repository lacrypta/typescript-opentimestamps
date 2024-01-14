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
  // new URL('https://a.pool.opentimestamps.org'),
  // new URL('https://b.pool.opentimestamps.org'),
  // new URL('https://a.pool.eternitywall.com'),
  new URL('https://alice.btc.calendar.opentimestamps.org'),
  new URL('https://bob.btc.calendar.opentimestamps.org'),
  // new URL('https://finney.calendar.eternitywall.com'),
  // new URL('https://opentimestamps.org'),
  // new URL('https://ots.btc.catallaxy.com'),
];

export async function submitTimestamp(
  algorithm: string,
  value: Uint8Array,
  fudge: Uint8Array | undefined,
  calendarUrls: URL[] = defaultCalendarUrls,
): Promise<[Timestamp, Error[]]> {
  const fileHash: FileHash = validateFileHashValue(algorithm, value);
  calendarUrls.forEach((url: URL): void => void validateCalendarUrl(url.toString()));

  const fudgeValue: Uint8Array = undefined === fudge ? randomBytes(16) : fudge;
  const fudgedValue: Uint8Array = sha256(Uint8Array.of(...value, ...fudgeValue));

  const [stampedTree, stampingErrors]: [Tree, Error[]] = (
    await Promise.all(
      calendarUrls.map(async (url: URL): Promise<Tree | Error> => {
        const body: Uint8Array | Error = await retrievePostBody(
          new URL(`${url.toString().replace(/\/$/, '')}/digest`),
          fudgedValue,
        );
        if (body instanceof Error) {
          return body;
        }
        const [tree, end]: [Tree, number] = readTree(body, 0);
        if (end !== body.length) {
          return new Error(`Garbage at end of calendar (${url.toString()}) response}`);
        }
        return tree;
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
    0 === fudgeValue.length
      ? resultTree
      : { leaves: newLeaves(), edges: newEdges().add({ type: 'append', operand: fudgeValue }, resultTree) };

  return [
    normalizeTimestamp({
      version: 1,
      fileHash,
      tree: fudgedTree,
    })!,
    stampingErrors,
  ];
}
