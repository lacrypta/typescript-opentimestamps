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

import type { Leaf, Op, Timestamp, Tree, Verifier } from './types';

import { callOp, leafPathToTree, leafPathsFromTree, normalizeTimestamp } from './internals';

export function getLeaves(msg: Uint8Array, tree: Tree): { msg: Uint8Array; leaf: Leaf }[] {
  let result: { msg: Uint8Array; leaf: Leaf }[] = [];
  tree.leaves.values().forEach((leaf: Leaf) => {
    result.push({ msg, leaf });
  });
  tree.edges.entries().forEach(([op, tree]: [Op, Tree]) => {
    result = result.concat(getLeaves(callOp(op, msg), tree));
  });
  return result;
}

export async function verifyTimestamp(
  timestamp: Timestamp,
  verifiers: Record<string, Verifier>,
): Promise<{ attestations: Record<number, string[]>; errors: Record<string, Error[]> }> {
  const result: { attestations: Record<number, string[]>; errors: Record<string, Error[]> } = {
    attestations: {},
    errors: {},
  };

  (
    await Promise.all(
      getLeaves(timestamp.fileHash.value, timestamp.tree).map(
        async ({ msg, leaf }: { msg: Uint8Array; leaf: Leaf }): Promise<[string, number | Error | undefined][]> => {
          return await Promise.all(
            Object.entries(verifiers).map(
              async ([name, verifier]: [string, Verifier]): Promise<[string, number | undefined | Error]> => {
                try {
                  return [name, await verifier(msg, leaf)];
                } catch (e: unknown) {
                  if (e instanceof Error) {
                    return [name, e];
                  } else {
                    return [name, new Error('Unknown error in verifier')];
                  }
                }
              },
            ),
          );
        },
      ),
    )
  ).forEach((leafResults: [string, number | Error | undefined][]) => {
    leafResults.forEach(([verifierName, leafResult]: [string, number | Error | undefined]) => {
      if (undefined === leafResult) {
        return;
      } else if (leafResult instanceof Error) {
        if (!(verifierName in result.errors)) {
          result.errors[verifierName] = [];
        }
        result.errors[verifierName]!.push(leafResult);
      } else {
        if (!(leafResult in result.attestations)) {
          result.attestations[leafResult] = [];
        }
        result.attestations[leafResult]!.push(verifierName);
      }
    });
  });

  return result;
}

export function shrinkTimestamp(timestamp: Timestamp, chain: 'bitcoin' | 'litecoin' | 'ethereum'): Timestamp {
  const shrunkenPath: { operations: Op[]; leaf: Leaf } | undefined = leafPathsFromTree(timestamp.tree, [])
    .filter(({ leaf }: { leaf: Leaf }): boolean => chain === leaf.type)
    .reduce(
      (
        left: { operations: Op[]; leaf: Leaf } | undefined,
        right: { operations: Op[]; leaf: Leaf },
      ): { operations: Op[]; leaf: Leaf } => {
        if (undefined === left) {
          return right;
        } else if ((left.leaf as { height: number }).height <= (right.leaf as { height: number }).height) {
          return left;
        } else {
          return right;
        }
      },
      undefined,
    );
  if (undefined === shrunkenPath) {
    return timestamp;
  } else {
    return normalizeTimestamp({
      fileHash: timestamp.fileHash,
      version: timestamp.version,
      tree: leafPathToTree(shrunkenPath),
    })!;
  }
}
