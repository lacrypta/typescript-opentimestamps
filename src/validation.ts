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

import type { FileHash, Leaf, Op, Timestamp, Tree } from './types';

import { MergeMap, MergeSet } from './utils';

export function validateNonNullObject(obj: unknown): object {
  if ('object' !== typeof obj || null === obj) {
    throw new Error('Expected non-null object');
  }
  return obj;
}

export function validateUint8Array(array: unknown): Uint8Array {
  const obj: object = validateNonNullObject(array);
  if (obj.constructor !== Uint8Array) {
    throw new Error('Expected Uint8Array');
  }
  return array as Uint8Array;
}

export function validateURL(url: unknown): URL {
  const obj: object = validateNonNullObject(url);
  if (obj.constructor !== URL) {
    throw new Error('Expected URL');
  }
  return url as URL;
}

export function validateCalendarUrl(url: unknown): string {
  if ('string' !== typeof url) {
    throw new Error('Expected string');
  }
  if (!/^https:\/\/[a-zA-Z0-9_.-]+(:[0-9]+)?(\/[a-zA-Z0-9_.:-]+)*\/?$/.test(url)) {
    throw new Error('Invalid URL');
  }
  return url;
}

export function validateNonNegativeInteger(num: unknown): number {
  if ('number' !== typeof num) {
    throw new Error('Expected number');
  }
  if (!Number.isSafeInteger(num)) {
    throw new Error('Expected safe-integer');
  }
  if (num < 0) {
    throw new Error('Expected non-negative integer');
  }
  return num;
}

export function validateOneOfStrings(value: string, options: string[]): string {
  if (!options.includes(value)) {
    throw new Error(`Expected one of [${options.join(', ')}]`);
  }
  return value;
}

export function validateObjectHasTypeKey(obj: object): { type: string } {
  if (!('type' in obj)) {
    throw new Error('Expected key .type');
  }
  if ('string' !== typeof obj.type) {
    throw new Error('Expected string');
  }
  return obj as { type: string };
}

export function validateObjectHasHeightKey(obj: object): { height: number } {
  if (!('height' in obj)) {
    throw new Error('Expected key .height');
  }
  validateNonNegativeInteger(obj.height);
  return obj as { height: number };
}

export function validateObjectHasUrlKey(obj: object): { url: URL } {
  if (!('url' in obj)) {
    throw new Error('Expected key .url');
  }
  validateURL(obj.url);
  return obj as { url: URL };
}

export function validateObjectHasHeaderKey(obj: object): { header: Uint8Array } {
  if (!('header' in obj)) {
    throw new Error('Expected key .header');
  }
  validateUint8Array(obj.header);
  if (8 !== (obj.header as Uint8Array).length) {
    throw new Error('Expected 8 byte header');
  }
  return obj as { header: Uint8Array };
}

export function validateObjectHasPayloadKey(obj: object): { payload: Uint8Array } {
  if (!('payload' in obj)) {
    throw new Error('Expected key .payload');
  }
  validateUint8Array(obj.payload);
  return obj as { payload: Uint8Array };
}

export function validateObjectHasOperandKey(obj: object): { operand: Uint8Array } {
  if (!('operand' in obj)) {
    throw new Error('Expected key .operand');
  }
  validateUint8Array(obj.operand);
  return obj as { operand: Uint8Array };
}

export function validateObjectHasLeavesKey(obj: object): { leaves: MergeSet<Leaf> } {
  if (!('leaves' in obj)) {
    throw new Error('Expected key .leaves');
  }
  const leaves: object = validateNonNullObject(obj.leaves);
  if (leaves.constructor !== MergeSet) {
    throw new Error('Expected MergeSet');
  }
  (leaves as MergeSet<unknown>).values().forEach(validateLeaf);

  return obj as { leaves: MergeSet<Leaf> };
}

export function validateObjectHasEdgesKey(obj: object): { edges: MergeMap<Op, Tree> } {
  if (!('edges' in obj)) {
    throw new Error('Expected key .edges');
  }
  const edges: object = validateNonNullObject(obj.edges);
  if (edges.constructor !== MergeMap) {
    throw new Error('Expected MergeMap');
  }
  (edges as MergeMap<unknown, unknown>).keys().forEach(validateOp);
  (edges as MergeMap<unknown, unknown>).values().forEach(validateTree);

  return obj as { edges: MergeMap<Op, Tree> };
}

export function validateObjectHasAlgorithmKey(obj: object): { algorithm: string } {
  if (!('algorithm' in obj)) {
    throw new Error('Expected key .algorithm');
  }
  if ('string' !== typeof obj.algorithm) {
    throw new Error('Expected string');
  }
  validateOneOfStrings(obj.algorithm, ['sha1', 'ripemd160', 'sha256', 'keccak256']);

  return obj as { algorithm: string };
}

export function validateObjectHasValueKey(obj: object): { value: Uint8Array } {
  if (!('value' in obj)) {
    throw new Error('Expected key .value');
  }
  validateUint8Array(obj.value);

  return obj as { value: Uint8Array };
}

export function validateLeaf(leaf: unknown): Leaf {
  const obj: { type: string } = validateObjectHasTypeKey(validateNonNullObject(leaf));

  switch (validateOneOfStrings(obj.type, ['bitcoin', 'litecoin', 'ethereum', 'pending', 'unknown'])) {
    case 'bitcoin':
      validateObjectHasHeightKey(obj);
      return leaf as { type: 'bitcoin'; height: number };
    case 'litecoin':
      validateObjectHasHeightKey(obj);
      return leaf as { type: 'litecoin'; height: number };
    case 'ethereum':
      validateObjectHasHeightKey(obj);
      return leaf as { type: 'ethereum'; height: number };
    case 'pending':
      validateObjectHasUrlKey(obj);
      return leaf as { type: 'pending'; url: URL };
    case 'unknown':
      validateObjectHasHeaderKey(obj);
      validateObjectHasPayloadKey(obj);
      return leaf as { type: 'unknown'; header: Uint8Array; payload: Uint8Array };
  }

  /* istanbul ignore next */
  return undefined as never;
}

export function validateOp(op: unknown): Op {
  const obj: { type: string } = validateObjectHasTypeKey(validateNonNullObject(op));

  switch (
    validateOneOfStrings(obj.type, [
      'sha1',
      'ripemd160',
      'sha256',
      'keccak256',
      'reverse',
      'hexlify',
      'append',
      'prepend',
    ])
  ) {
    case 'sha1':
      return op as { type: 'sha1' };
    case 'ripemd160':
      return op as { type: 'ripemd160' };
    case 'sha256':
      return op as { type: 'sha256' };
    case 'keccak256':
      return op as { type: 'keccak256' };
    case 'reverse':
      return op as { type: 'reverse' };
    case 'hexlify':
      return op as { type: 'hexlify' };
    case 'append':
      validateObjectHasOperandKey(obj);
      return op as { type: 'append'; operand: Uint8Array };
    case 'prepend':
      validateObjectHasOperandKey(obj);
      return op as { type: 'prepend'; operand: Uint8Array };
  }

  /* istanbul ignore next */
  return undefined as never;
}

export function validateTree(tree: unknown): Tree {
  const obj: object = validateNonNullObject(tree);

  validateObjectHasLeavesKey(obj);
  validateObjectHasEdgesKey(obj);

  return tree as Tree;
}

export function validateFileHashValue(algorithm: string, value: Uint8Array): FileHash {
  switch (validateOneOfStrings(algorithm, ['sha1', 'ripemd160', 'sha256', 'keccak256'])) {
    case 'sha1':
    case 'ripemd160':
      if (20 !== value.length) {
        throw new Error('Expected 20 byte hash');
      }
      break;
    case 'sha256':
    case 'keccak256':
      if (32 !== value.length) {
        throw new Error('Expected 32 byte hash');
      }
      break;
  }
  return { algorithm, value } as FileHash;
}

export function validateFileHash(fileHash: unknown): FileHash {
  const obj: object = validateNonNullObject(fileHash);
  validateFileHashValue(validateObjectHasAlgorithmKey(obj).algorithm, validateObjectHasValueKey(obj).value);
  return fileHash as FileHash;
}

export function validateVersion(version: unknown): number {
  validateNonNegativeInteger(version);
  if (1 !== version) {
    throw new Error('Expected .version to be 1');
  }

  return version;
}

export function validateTimestamp(timestamp: unknown): Timestamp {
  const obj: object = validateNonNullObject(timestamp);

  if (!('version' in obj)) {
    throw new Error('Expected key .version');
  }
  if (!('fileHash' in obj)) {
    throw new Error('Expected key .fileHash');
  }
  if (!('tree' in obj)) {
    throw new Error('Expected key .tree');
  }

  validateVersion(obj.version);
  validateFileHash(obj.fileHash);
  validateTree(obj.tree);

  return timestamp as Timestamp;
}

export function isTimestamp(timestamp: unknown): timestamp is Timestamp {
  try {
    validateTimestamp(timestamp);
    return true;
  } catch {
    return false;
  }
}

export function assertTimestamp(timestamp: unknown): asserts timestamp is Timestamp {
  void validateTimestamp(timestamp);
}
