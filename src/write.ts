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
import { LeafHeader, RLeafHeader, Tag, magicHeader, nonFinal } from './types';
import { uint8ArrayCompare, uint8ArrayConcat, uint8ArrayFromHex } from './utils';

export function writeUint(value: number): Uint8Array {
  if (value < 0) {
    throw new Error('Expected non-negative value');
  }
  const resultParts: Uint8Array[] = [];
  while (0x7f < value) {
    resultParts.push(Uint8Array.of(0x80 | (value & 0x7f)));
    value >>= 7;
  }
  resultParts.push(Uint8Array.of(value));
  return uint8ArrayConcat(resultParts);
}

export function writeBytes(bytes: Uint8Array): Uint8Array {
  return uint8ArrayConcat([writeUint(bytes.length), bytes]);
}

export function writeFileHash(fileHash: FileHash): Uint8Array {
  return uint8ArrayConcat([Uint8Array.of(Tag[fileHash.algorithm]), fileHash.value]);
}

export function compareLeaves(left: Leaf, right: Leaf): number {
  const headerCompare: number = uint8ArrayCompare(
    'unknown' == left.type ? left.header : uint8ArrayFromHex(RLeafHeader[left.type as keyof typeof RLeafHeader]),
    'unknown' == right.type ? right.header : uint8ArrayFromHex(RLeafHeader[right.type as keyof typeof RLeafHeader]),
  );
  if (0 === headerCompare) {
    switch (left.type) {
      case 'pending':
        return uint8ArrayCompare(
          new TextEncoder().encode(left.url.toString()),
          new TextEncoder().encode((right as { url: URL }).url.toString()),
        );
      case 'unknown':
        return uint8ArrayCompare(left.payload, (right as { payload: Uint8Array }).payload);
      default:
        return left.height - (right as { height: number }).height;
    }
  }
  return headerCompare;
}

export function compareOps(left: Op, right: Op): number {
  const tagCompare: number = Tag[left.type] - Tag[right.type];
  if (0 === tagCompare && ('append' === left.type || 'prepend' === left.type)) {
    return uint8ArrayCompare(left.operand, (right as { operand: Uint8Array }).operand);
  }
  return tagCompare;
}

export function compareEdges(left: Edge, right: Edge): number {
  const [[leftOp], [rightOp]]: [Edge, Edge] = [left, right];
  return compareOps(leftOp, rightOp);
}

export function writeLeaf(leaf: Leaf): Uint8Array {
  const resultParts: Uint8Array[] = [];
  resultParts.push(Uint8Array.of(Tag.attestation));
  switch (leaf.type) {
    case 'pending':
      resultParts.push(uint8ArrayFromHex(LeafHeader[leaf.type]));
      resultParts.push(writeBytes(writeBytes(new TextEncoder().encode(leaf.url.toString()))));
      break;
    case 'unknown':
      resultParts.push(leaf.header);
      resultParts.push(writeBytes(leaf.payload));
      break;
    default:
      resultParts.push(uint8ArrayFromHex(LeafHeader[leaf.type]));
      resultParts.push(writeBytes(writeUint(leaf.height)));
  }
  return uint8ArrayConcat(resultParts);
}

export function writeEdge(edge: Edge): Uint8Array {
  const [op, tree]: [Op, Tree] = edge;
  const resultParts: Uint8Array[] = [];
  resultParts.push(Uint8Array.of(Tag[op.type]));
  if (op.type === 'append' || op.type === 'prepend') {
    resultParts.push(writeBytes(op.operand));
  }
  resultParts.push(writeTree(tree));
  return uint8ArrayConcat(resultParts);
}

export function writeTree(tree: Tree): Uint8Array {
  const leaves: Leaf[] = tree.leaves.values().toSorted(compareLeaves);
  const edges: Edge[] = tree.edges.entries().toSorted(compareEdges);
  const totalLength: number = leaves.length + edges.length;
  const resultParts: Uint8Array[] = [];
  if (1 < totalLength) {
    for (let i = 0; i < totalLength - 1; i++) {
      resultParts.push(Uint8Array.of(nonFinal));
      if (i < leaves.length) {
        resultParts.push(writeLeaf(leaves[i]!));
      } else {
        resultParts.push(writeEdge(edges[i - leaves.length]!));
      }
    }
  }
  if (0 < edges.length) {
    resultParts.push(writeEdge(edges[edges.length - 1]!));
  } else if (0 < leaves.length) {
    resultParts.push(writeLeaf(leaves[leaves.length - 1]!));
  }
  return uint8ArrayConcat(resultParts);
}

export function writeTimestamp(timestamp: Timestamp): Uint8Array {
  return uint8ArrayConcat([
    magicHeader,
    writeUint(timestamp.version),
    writeFileHash(timestamp.fileHash),
    writeTree(timestamp.tree),
  ]);
}
