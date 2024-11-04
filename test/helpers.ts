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

import type { Edge, EdgeMap, LeafSet } from '../src/internals';
import type { Leaf, Op, Timestamp, Tree } from '../src/types';

import { uint8ArrayToHex } from '../src/utils';

export function opToString(op: Op): string {
  switch (op.type) {
    case 'append':
    case 'prepend':
      return `${op.type}:${uint8ArrayToHex(op.operand)}`;
    default:
      return op.type;
  }
}

export function edgeToString(edge: Edge): string {
  const [op, tree]: Edge = edge;
  return `${opToString(op)}=>{${treeToString(tree)}}`;
}

export function leafToString(leaf: Leaf): string {
  switch (leaf.type) {
    case 'pending':
      return `${leaf.type}:${leaf.url.toString()}`;
    case 'unknown':
      return `${leaf.type}:${uint8ArrayToHex(leaf.header)}:${uint8ArrayToHex(leaf.payload)}`;
    default:
      return `${leaf.type}:${leaf.height}`;
  }
}

export function leafOrEdgeToString(leafOrEdge: Leaf | Edge): string {
  if (Array.isArray(leafOrEdge)) {
    return edgeToString(leafOrEdge);
  } else {
    return leafToString(leafOrEdge);
  }
}

export function leafSetToString(leafSet: LeafSet): string {
  return leafSet.values().map(leafToString).join(',');
}

export function edgeMapToString(edgeMap: EdgeMap): string {
  return edgeMap
    .entries()
    .map(([op, subTree]: [Op, Tree]): string => {
      return `${opToString(op)}=>{${treeToString(subTree)}}`;
    })
    .join(',');
}

export function treeToString(tree: Tree): string {
  return `[${leafSetToString(tree.leaves as LeafSet)}](${edgeMapToString(tree.edges as EdgeMap)})`;
}

export function timestampToString(timestamp: Timestamp): string {
  return `<${[timestamp.version.toString(), timestamp.fileHash.algorithm, uint8ArrayToHex(timestamp.fileHash.value), treeToString(timestamp.tree)].join(':')}>`;
}
