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

import type { Leaf, Path, Timestamp, Verifier } from './types';

import { treeToPaths, pathsToTree, normalizeTimestamp, callOps } from './internals';

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
      treeToPaths(timestamp.tree)
        .map(({ operations, leaf }: Path): Promise<[string, number | Error | undefined]>[] => {
          const msg: Uint8Array = callOps(operations, timestamp.fileHash.value);
          return Object.entries(verifiers).map(
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
          );
        })
        .reduce(
          (
            prev: Promise<[string, number | Error | undefined]>[],
            curr: Promise<[string, number | Error | undefined]>[],
          ): Promise<[string, number | Error | undefined]>[] => {
            return prev.concat(curr);
          },
          [],
        ),
    )
  ).forEach(([verifierName, leafResult]: [string, number | undefined | Error]) => {
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

  return result;
}

export function shrinkTimestamp(timestamp: Timestamp, chain: 'bitcoin' | 'litecoin' | 'ethereum'): Timestamp {
  const shrunkenPath: Path | undefined = treeToPaths(timestamp.tree)
    .filter(({ leaf }: { leaf: Leaf }): boolean => chain === leaf.type)
    .reduce((left: Path | undefined, right: Path): Path => {
      if (undefined === left) {
        return right;
      } else if ((left.leaf as { height: number }).height <= (right.leaf as { height: number }).height) {
        return left;
      } else {
        return right;
      }
    }, undefined);
  if (undefined === shrunkenPath) {
    return timestamp;
  } else {
    return normalizeTimestamp({
      fileHash: timestamp.fileHash,
      version: timestamp.version,
      tree: pathsToTree([shrunkenPath]),
    })!;
  }
}
