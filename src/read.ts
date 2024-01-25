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

import { incorporateToTree, newTree, normalizeTimestamp } from './internals';
import { Tag, magicHeader, nonFinal } from './types';
import { textDecoder, uint8ArrayEquals, uint8ArrayToHex } from './utils';
import { validateCalendarUrl } from './validation';

export function getBytes(length: number, data: Uint8Array, index: number): [Uint8Array, number] {
  if (data.length < index + length) {
    throw new Error(`Unexpected EOF reading bytes at position ${index}`);
  }
  return [data.slice(index, index + length), index + length];
}

export function getByte(data: Uint8Array, index: number): [number, number] {
  const [[result], idx]: [Uint8Array, number] = getBytes(1, data, index);
  return [result!, idx];
}

export function readUint(data: Uint8Array, index: number): [number, number] {
  let result: number = 0;
  let displacement: number = 0;
  let [current, idx]: [number, number] = getByte(data, index);
  while (current & 0x80) {
    result += (0x7f & current) << (7 * displacement++);
    [current, idx] = getByte(data, idx);
  }
  return [result + (current << (7 * displacement)), idx];
}

export function readBytes(data: Uint8Array, index: number): [Uint8Array, number] {
  const [length, idx]: [number, number] = readUint(data, index);
  const [result, idx2]: [Uint8Array, number] = getBytes(length, data, idx);
  return [result, idx2];
}

export function readUrl(data: Uint8Array, index: number): [URL, number] {
  const [url, idx]: [Uint8Array, number] = readBytes(data, index);
  return [new URL(validateCalendarUrl(textDecoder.decode(url))), idx];
}

export function readLiteral(data: Uint8Array, index: number, literal: Uint8Array): [Uint8Array, number] {
  const [found, idx]: [Uint8Array, number] = getBytes(literal.length, data, index);
  if (!uint8ArrayEquals(found, literal)) {
    throw new Error(
      `Literal mismatch (expected ${uint8ArrayToHex(literal)} but found ${uint8ArrayToHex(found)}) at position ${index}`,
    );
  }
  return [found, idx];
}

export function readDoneLeafPayload(payload: Uint8Array): number {
  const [height, length]: [number, number] = readUint(payload, 0);
  if (payload.length !== length) {
    throw new Error('Garbage at end of attestation payload');
  }
  return height;
}

export function readPendingLeafPayload(payload: Uint8Array): URL {
  const [url, length]: [URL, number] = readUrl(payload, 0);
  if (payload.length !== length) {
    throw new Error('Garbage at end of Pending attestation payload');
  }
  return url;
}

export function readLeaf(data: Uint8Array, index: number): [Leaf, number] {
  const [header, idx]: [Uint8Array, number] = getBytes(8, data, index);
  const [payload, idx2]: [Uint8Array, number] = readBytes(data, idx);
  const sHeader: string = uint8ArrayToHex(header);
  switch (sHeader) {
    case '0588960d73d71901':
      return [{ type: 'bitcoin', height: readDoneLeafPayload(payload) }, idx2];
    case '06869a0d73d71b45':
      return [{ type: 'litecoin', height: readDoneLeafPayload(payload) }, idx2];
    case '30fe8087b5c7ead7':
      return [{ type: 'ethereum', height: readDoneLeafPayload(payload) }, idx2];
    case '83dfe30d2ef90c8e':
      return [{ type: 'pending', url: readPendingLeafPayload(payload) }, idx2];
    default:
      return [{ type: 'unknown', header, payload }, idx2];
  }
}

export function readEdgeOrLeaf(data: Uint8Array, index: number): [Edge | Leaf, number] {
  const [tag, idx]: [number, number] = getByte(data, index);
  switch (tag) {
    case 0x00:
      return readLeaf(data, idx);
    case 0x02:
    case 0x03:
    case 0x08:
    case 0x67:
    case 0xf2:
    case 0xf3: {
      const [tree, idx2]: [Tree, number] = readTree(data, idx);
      return [
        [{ type: Tag[tag] as 'sha1' | 'ripemd160' | 'sha256' | 'keccak256' | 'reverse' | 'hexlify' }, tree],
        idx2,
      ];
    }
    case 0xf0:
    case 0xf1: {
      const [operand, idx2]: [Uint8Array, number] = readBytes(data, idx);
      const [tree, idx3]: [Tree, number] = readTree(data, idx2);
      return [[{ type: Tag[tag] as 'append' | 'prepend', operand }, tree], idx3];
    }
    default:
      throw new Error(`Unknown operation ${uint8ArrayToHex(Uint8Array.of(tag))} at position ${index}`);
  }
}

export function readTree(data: Uint8Array, index: number): [Tree, number] {
  const result: Tree = newTree();
  let idx: number = index;
  while (nonFinal === data[idx]) {
    const [edgeOrLeaf, idx2]: [Edge | Leaf, number] = readEdgeOrLeaf(data, idx + 1);
    incorporateToTree(result, edgeOrLeaf);
    idx = idx2;
  }
  const [edgeOrLeaf, idx2]: [Edge | Leaf, number] = readEdgeOrLeaf(data, idx);
  incorporateToTree(result, edgeOrLeaf);
  return [result, idx2];
}

export function readFileHash(data: Uint8Array, index: number): [FileHash, number] {
  const [tag, idx]: [number, number] = getByte(data, index);
  switch (tag) {
    case 0x02:
    case 0x03: {
      const [value, idx2]: [Uint8Array, number] = getBytes(20, data, idx);
      return [{ algorithm: Tag[tag] as 'sha1' | 'ripemd160', value }, idx2];
    }
    case 0x08:
    case 0x67: {
      const [value, idx2]: [Uint8Array, number] = getBytes(32, data, idx);
      return [{ algorithm: Tag[tag] as 'sha256' | 'keccak256', value }, idx2];
    }
    default:
      throw new Error(`Unknown hashing algorithm ${uint8ArrayToHex(Uint8Array.of(tag))} at position ${index}`);
  }
}

export function readVersion(data: Uint8Array, index: number): [number, number] {
  const [version, idx]: [number, number] = readUint(data, index);
  if (1 !== version) {
    throw new Error(`Unrecognized version (expected 1 but found ${version}) at position ${index}`);
  }
  return [version, idx];
}

export function readTimestamp(data: Uint8Array): Timestamp {
  const idx: number = readLiteral(data, 0, magicHeader)[1];
  const [version, idx2]: [number, number] = readVersion(data, idx);
  const [fileHash, idx3]: [FileHash, number] = readFileHash(data, idx2);
  const [tree, idx4]: [Tree, number] = readTree(data, idx3);

  if (data.length !== idx4) {
    throw new Error('Garbage at EOF');
  }

  return normalizeTimestamp({ version, fileHash, tree })!;
}
