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

import type { Path, Paths, Timestamp, Tree } from './types';

import { callOps, normalizeTimestamp, pathsToTree, treeToPaths } from './internals';
import { readTree } from './read';
import { retrieveGetBody, uint8ArrayToHex } from './utils';

export async function upgradeFromCalendar(calendarUrl: URL, msg: Uint8Array): Promise<Tree> {
  const body: Uint8Array = await retrieveGetBody(
    new URL(`${calendarUrl.toString().replace(/\/$/, '')}/timestamp/${uint8ArrayToHex(msg)}`),
  );
  const [upgradedTree, end]: [Tree, number] = readTree(body, 0);
  if (end !== body.length) {
    throw new Error(`Garbage at end of calendar response}`);
  }
  return upgradedTree;
}

export async function upgradeTree(tree: Tree, msg: Uint8Array): Promise<[Tree, Error[]]> {
  const { paths, errors }: { paths: Paths; errors: Error[] } = (
    await Promise.all(
      treeToPaths(tree).map(async ({ operations, leaf }: Path): Promise<Paths | Error> => {
        if ('pending' !== leaf.type) {
          return Promise.resolve([{ operations, leaf }]);
        } else {
          try {
            return upgradeFromCalendar(leaf.url, callOps(operations, msg)).then((upgradedTree: Tree): Paths => {
              return treeToPaths(upgradedTree).map(
                ({ operations: upgradedOperations, leaf: upgradedLeaf }: Path): Path => {
                  return { operations: operations.concat(upgradedOperations), leaf: upgradedLeaf };
                },
              );
            });
          } catch (e: unknown) {
            if (e instanceof Error) {
              return new Error(`Error (${leaf.url.toString()}): ${e.message}`);
            } else {
              return new Error(`Error (${leaf.url.toString()}): Unknown error contacting calendar`);
            }
          }
        }
      }),
    )
  ).reduce(
    (prev: { paths: Paths; errors: Error[] }, current: Error | Paths): { paths: Paths; errors: Error[] } => {
      if (current instanceof Error) {
        return { paths: prev.paths, errors: prev.errors.concat([current]) };
      } else {
        return { paths: prev.paths.concat(current), errors: prev.errors };
      }
    },
    { paths: [], errors: [] },
  );
  return [pathsToTree(paths), errors];
}

export async function upgradeTimestamp(timestamp: Timestamp): Promise<{ timestamp: Timestamp; errors: Error[] }> {
  const [tree, errors]: [Tree, Error[]] = await upgradeTree(timestamp.tree, timestamp.fileHash.value);
  return {
    timestamp: normalizeTimestamp({
      version: timestamp.version,
      fileHash: timestamp.fileHash,
      tree,
    })!,
    errors,
  };
}
