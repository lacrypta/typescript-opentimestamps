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

import type { Edge, Leaf, Op, Timestamp, Tree } from '../src/types';

import { MergeMap, MergeSet, uint8ArrayToHex } from '../src/utils';

export const opToString: (op: Op) => string = (op: Op): string => {
  switch (op.type) {
    case 'append':
    case 'prepend':
      return `${op.type}:${uint8ArrayToHex(op.operand)}`;
    default:
      return op.type;
  }
};

export const edgeToString: (edge: Edge) => string = (edge: Edge): string => {
  const [op, tree]: Edge = edge;
  return `${opToString(op)}=>{${treeToString(tree)}}`;
};

export const leafToString: (leaf: Leaf) => string = (leaf: Leaf): string => {
  switch (leaf.type) {
    case 'pending':
      return `${leaf.type}:${leaf.url.toString()}`;
    case 'unknown':
      return `${leaf.type}:${uint8ArrayToHex(leaf.header)}:${uint8ArrayToHex(leaf.payload)}`;
    default:
      return `${leaf.type}:${leaf.height}`;
  }
};

export const leafOrEdgeToString: (leafOrEdge: Leaf | Edge) => string = (leafOrEdge: Leaf | Edge): string => {
  if (Array.isArray(leafOrEdge)) {
    return edgeToString(leafOrEdge);
  } else {
    return leafToString(leafOrEdge);
  }
};

export const mergeSetToString: (ms: MergeSet<Leaf>) => string = (ms: MergeSet<Leaf>): string => {
  return ms.values().map(leafToString).join(',');
};

export const mergeMapToString: (mm: MergeMap<Op, Tree>) => string = (mm: MergeMap<Op, Tree>): string => {
  return mm
    .entries()
    .map(([op, subTree]: [Op, Tree]) => {
      return `${opToString(op)}=>{${treeToString(subTree)}}`;
    })
    .join(',');
};

export const treeToString: (tree: Tree) => string = (tree: Tree): string => {
  return `[${mergeSetToString(tree.leaves)}](${mergeMapToString(tree.edges)})`;
};

export const timestampToString: (timestamp: Timestamp) => string = (timestamp: Timestamp): string => {
  return `<${[timestamp.version.toString(), timestamp.fileHash.algorithm, uint8ArrayToHex(timestamp.fileHash.value), treeToString(timestamp.tree)].join(':')}>`;
};