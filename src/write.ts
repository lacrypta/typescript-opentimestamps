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

import type { Edge, FileHash, Leaf, Timestamp, Tree } from './types';

import { compareEdges, compareLeaves } from './internals';
import { LeafHeader, Tag, magicHeader, nonFinal } from './types';
import { textEncoder, uint8ArrayConcat, uint8ArrayFromHex } from './utils';

export function writeUint(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('Expected safe non-negative value');
  }
  const resultParts: Uint8Array[] = [];
  while (0x7f < value) {
    resultParts.push(Uint8Array.of(0x80 | (value & 0x7f)));
    value >>>= 7;
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

export function writeLeaf(leaf: Leaf): Uint8Array {
  const resultParts: Uint8Array[] = [];
  resultParts.push(Uint8Array.of(Tag.attestation));
  switch (leaf.type) {
    case 'pending':
      resultParts.push(uint8ArrayFromHex(LeafHeader[leaf.type]));
      resultParts.push(writeBytes(writeBytes(textEncoder.encode(leaf.url.toString()))));
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
  const [op, tree]: Edge = edge;
  const resultParts: Uint8Array[] = [];
  resultParts.push(Uint8Array.of(Tag[op.type]));
  if (op.type === 'append' || op.type === 'prepend') {
    resultParts.push(writeBytes(op.operand));
  }
  resultParts.push(writeTree(tree));
  return uint8ArrayConcat(resultParts);
}

export function writeTree(tree: Tree): Uint8Array {
  const leaves: Leaf[] = tree.leaves.values();
  const edges: Edge[] = tree.edges.entries();
  const totalLength: number = leaves.length + edges.length;
  const resultParts: Uint8Array[] = [];
  leaves.sort(compareLeaves);
  edges.sort(compareEdges);
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
