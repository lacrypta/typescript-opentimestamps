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

import type { Edge, FileHash, Leaf, Op, Timestamp, Tree } from './types';

import { callOp, compareEdges, compareLeaves } from './internals';
import { uint8ArrayToHex } from './utils';

export function indent(text: string): string {
  const [first, ...rest]: string[] = text.split('\n');
  return [` -> ${first}`].concat(rest.map((line: string): string => `    ${line}`)).join('\n');
}

export function infoLeaf(leaf: Leaf): string {
  switch (leaf.type) {
    case 'pending':
      return `pendingVerify(msg, ${leaf.url.toString()})`;
    case 'unknown':
      return `unknownVerify<${uint8ArrayToHex(leaf.header)}>(msg, ${uint8ArrayToHex(leaf.payload)})`;
    default:
      return `${leaf.type}Verify(msg, ${leaf.height})`;
  }
}

export function infoEdge(edge: Edge, msg: Uint8Array | undefined): string {
  const resultParts: string[] = [];
  const [op, tree]: [Op, Tree] = edge;
  const newMsg: Uint8Array | undefined = undefined === msg ? undefined : callOp(op, msg);
  switch (op.type) {
    case 'append':
    case 'prepend':
      resultParts.push(`msg = ${op.type}(msg, ${uint8ArrayToHex(op.operand)})`);
      break;
    default:
      resultParts.push(`msg = ${op.type}(msg)`);
  }
  if (undefined !== newMsg) {
    resultParts.push(`    = ${uint8ArrayToHex(newMsg)}`);
  }
  const treeInfo: string = infoTree(tree, newMsg);
  if ('' !== treeInfo) {
    resultParts.push(treeInfo);
  }
  return resultParts.join('\n');
}

export function infoTree(tree: Tree, msg: Uint8Array | undefined): string {
  const leaves: Leaf[] = tree.leaves.values();
  const edges: Edge[] = tree.edges.entries();
  const leavesSize: number = leaves.length;
  const edgesSize: number = edges.length;
  leaves.sort(compareLeaves);
  edges.sort(compareEdges);

  const doIndent: (x: string) => string = 1 < leavesSize + edgesSize ? indent : (x: string): string => x;

  const resultParts: string[] = tree.leaves
    .values()
    .map((leaf: Leaf): string => doIndent(infoLeaf(leaf)))
    .concat(tree.edges.entries().map((edge: Edge): string => doIndent(infoEdge(edge, msg))));
  return resultParts.join('\n');
}

export function infoFileHash(fileHash: FileHash, verbose: boolean): string {
  const resultParts: string[] = [];
  resultParts.push(`msg = ${fileHash.algorithm}(FILE)`);
  if (verbose) {
    resultParts.push(`    = ${uint8ArrayToHex(fileHash.value)}`);
  }
  return resultParts.join('\n');
}

export function infoTimestamp(timestamp: Timestamp, verbose: boolean = false): string {
  const resultParts: string[] = [];
  if (verbose) {
    resultParts.push(`# version: ${timestamp.version}`);
  }
  resultParts.push(infoFileHash(timestamp.fileHash, verbose));
  const treeInfo: string = infoTree(timestamp.tree, verbose ? timestamp.fileHash.value : undefined);
  if ('' !== treeInfo) {
    resultParts.push(treeInfo);
  }
  return resultParts.join('\n');
}
