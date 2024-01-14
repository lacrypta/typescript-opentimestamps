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

import { callOp } from './internals';
import type { Leaf, LeafVerifier, LeafVerifiers, Op, Timestamp, Tree } from './types';

export function getLeaves(msg: Uint8Array, tree: Tree): { leaf: Leaf; msg: Uint8Array }[] {
  let result: { leaf: Leaf; msg: Uint8Array }[] = [];
  tree.leaves.values().forEach((leaf: Leaf) => {
    result.push({ leaf, msg });
  });
  tree.edges.entries().forEach(([op, tree]: [Op, Tree]) => {
    result = result.concat(getLeaves(callOp(op, msg), tree));
  });
  return result;
}

export function getAllLeaves(timestamp: Timestamp): { leaf: Leaf; msg: Uint8Array }[] {
  return getLeaves(timestamp.fileHash.value, timestamp.tree);
}

export async function verifyLeaf(
  leaf: Leaf,
  msg: Uint8Array,
  verifiers: LeafVerifiers,
): Promise<Record<string, boolean>> {
  if (leaf.type !== 'bitcoin' && leaf.type !== 'litecoin' && leaf.type !== 'ethereum') {
    return {};
  }
  return Object.fromEntries(
    await Promise.all(
      Object.entries(verifiers[leaf.type] ?? {}).map(
        async ([key, verifier]: [string, LeafVerifier]): Promise<[string, boolean]> => {
          return [key, await verifier(msg, leaf.height)];
        },
      ),
    ),
  );
}
