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

import { callOp, incorporateTreeToTree, normalizeTimestamp } from './internals';
import { readTree } from './read';
import { Leaf, Op, Timestamp, Tree } from './types';
import { retrieveGetBody, uint8ArrayToHex } from './utils';

export async function upgradeStep(tree: Tree, msg: Uint8Array): Promise<[Tree, Error[]]> {
  return [
    tree,
    (
      await Promise.all(
        tree.leaves
          .values()
          .map(async (leaf: Leaf): Promise<Error[]> => {
            if ('pending' !== leaf.type) {
              return [];
            }
            try {
              const body: Uint8Array | Error = await retrieveGetBody(
                new URL(`${leaf.url.toString().replace(/\/$/, '')}/timestamp/${uint8ArrayToHex(msg)}`),
              );
              if (body instanceof Error) {
                return [body];
              }
              const [upgradedTree, end]: [Tree, number] = readTree(body, 0);
              if (end !== body.length) {
                return [new Error(`Garbage at end of calendar (${leaf.url.toString()}) response}`)];
              }
              tree.leaves.remove(leaf);
              incorporateTreeToTree(tree, upgradedTree);
              return [];
            } catch (e: unknown) {
              if (e instanceof Error) {
                return [e];
              } else {
                return [new Error('Unknown error')];
              }
            }
          })
          .concat(
            tree.edges.entries().map(async ([op, tree]: [Op, Tree]): Promise<Error[]> => {
              return (await upgradeStep(tree, callOp(op, msg)))[1];
            }),
          ),
      )
    ).reduce<Error[]>((prev: Error[], curr: Error[]) => prev.concat(curr), []),
  ];
}

export async function upgradeTimestamp(timestamp: Timestamp): Promise<[Timestamp, Error[]]> {
  const [tree, errors]: [Tree, Error[]] = await upgradeStep(timestamp.tree, timestamp.fileHash.value);
  return [
    normalizeTimestamp({
      version: timestamp.version,
      fileHash: timestamp.fileHash,
      tree,
    })!,
    errors,
  ];
}
