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

import { callOp } from './internals';
import { uint8ArrayToHex } from './utils';

export function indent(text: string): string {
  const [first, ...rest]: string[] = text.split('\n');
  return [` -> ${first}`].concat(rest.map((line: string): string => `    ${line}`)).join('\n');
}

export function infoEdge(op: Op, tree: Tree, msg: Uint8Array, verbose: boolean): string {
  const resultParts: string[] = [];
  const newMsg: Uint8Array = callOp(op, msg);
  switch (op.type) {
    case 'append':
    case 'prepend':
      resultParts.push(`msg = ${op.type}(msg, ${uint8ArrayToHex(op.operand)})`);
      break;
    default:
      resultParts.push(`msg = ${op.type}(msg)`);
  }
  if (verbose) {
    resultParts.push(`    = ${uint8ArrayToHex(newMsg)}`);
  }
  resultParts.push(infoTree(tree, newMsg, verbose));
  return resultParts.join('\n');
}

export function infoLeaf(leaf: Leaf): string {
  switch (leaf.type) {
    case 'pending':
      return `pending(msg, ${leaf.url.toString()})`;
    case 'unknown':
      return `unknown<${uint8ArrayToHex(leaf.header)}>(msg, ${uint8ArrayToHex(leaf.payload)})`;
    default:
      return `${leaf.type}Verify(msg, ${leaf.height})`;
  }
}

export function infoTree(tree: Tree, msg: Uint8Array, verbose: boolean): string {
  const leavesSize: number = tree.leaves.size();
  const edgesSize: number = tree.edges.size();

  const doIndent: (x: string) => string = 1 < leavesSize + edgesSize ? indent : (x: string) => x;

  const resultParts: string[] = tree.leaves
    .values()
    .map((leaf: Leaf): string => doIndent(infoLeaf(leaf)))
    .concat(tree.edges.entries().map(([op, tree]: Edge): string => doIndent(infoEdge(op, tree, msg, verbose))));
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
  resultParts.push(infoFileHash(timestamp.fileHash, verbose));
  resultParts.push(indent(infoTree(timestamp.tree, timestamp.fileHash.value, verbose)));
  return resultParts.join('\n');
}
