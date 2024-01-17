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

import type { Edge, FileHash, Leaf, Timestamp, Tree } from '../src/types';

import { newEdges, newLeaves } from '../src/internals';
import {
  getByte,
  getBytes,
  readBytes,
  readDoneLeafPayload,
  readEdgeOrLeaf,
  readFileHash,
  readLeaf,
  readLiteral,
  readPendingLeafPayload,
  readTimestamp,
  readTree,
  readUint,
  readUrl,
  readVersion,
} from '../src/read';
import { uint8ArrayFromHex } from '../src/utils';

import { leafOrEdgeToString, timestampToString, treeToString } from './helpers';

describe('Read', () => {
  describe('getBytes()', () => {
    it.each([
      {
        length: 0,
        data: Uint8Array.of(),
        index: 0,
        expected: [Uint8Array.of(), 0] as [Uint8Array, number],
        error: null,
        name: 'should return empty for empty length and data',
      },
      {
        length: 1,
        data: Uint8Array.of(),
        index: 0,
        expected: null,
        error: new Error('Unexpected EOF reading bytes at position 0'),
        name: 'should fail when reading past EOF',
      },
      {
        length: 0,
        data: Uint8Array.of(),
        index: 1,
        expected: null,
        error: new Error('Unexpected EOF reading bytes at position 1'),
        name: 'should fail when reading past EOF (again)',
      },
      {
        length: 2,
        data: Uint8Array.of(1, 2, 3, 4),
        index: 0,
        expected: [Uint8Array.of(1, 2), 2] as [Uint8Array, number],
        error: null,
        name: 'should return bytes',
      },
      {
        length: 2,
        data: Uint8Array.of(1, 2, 3, 4),
        index: 2,
        expected: [Uint8Array.of(3, 4), 4] as [Uint8Array, number],
        error: null,
        name: 'should return bytes (again)',
      },
    ])(
      '$name',
      ({
        length,
        data,
        index,
        expected,
        error,
      }:
        | { length: number; data: Uint8Array; index: number; expected: [Uint8Array, number]; error: null }
        | { length: number; data: Uint8Array; index: number; expected: null; error: Error }) => {
        if (null === error) {
          expect(getBytes(length, data, index)).toStrictEqual(expected);
        } else {
          expect(() => getBytes(length, data, index)).toThrow(error);
        }
      },
    );
  });

  describe('getByte()', () => {
    it.each([
      {
        data: Uint8Array.of(),
        index: 0,
        expected: null,
        error: new Error('Unexpected EOF reading bytes at position 0'),
        name: 'should fail when reading past EOF',
      },
      {
        data: Uint8Array.of(),
        index: 1,
        expected: null,
        error: new Error('Unexpected EOF reading bytes at position 1'),
        name: 'should fail when reading past EOF (again)',
      },
      {
        data: Uint8Array.of(1, 2, 3, 4),
        index: 0,
        expected: [1, 1] as [number, number],
        error: null,
        name: 'should return byte',
      },
      {
        data: Uint8Array.of(1, 2, 3, 4),
        index: 1,
        expected: [2, 2] as [number, number],
        error: null,
        name: 'should return byte (again)',
      },
      {
        data: Uint8Array.of(1, 2, 3, 4),
        index: 2,
        expected: [3, 3] as [number, number],
        error: null,
        name: 'should return byte (again, again)',
      },
      {
        data: Uint8Array.of(1, 2, 3, 4),
        index: 3,
        expected: [4, 4] as [number, number],
        error: null,
        name: 'should return byte (again, again, again)',
      },
    ])(
      '$name',
      ({
        data,
        index,
        expected,
        error,
      }:
        | { data: Uint8Array; index: number; expected: [number, number]; error: null }
        | { data: Uint8Array; index: number; expected: null; error: Error }) => {
        if (null === error) {
          expect(getByte(data, index)).toStrictEqual(expected);
        } else {
          expect(() => getByte(data, index)).toThrow(error);
        }
      },
    );
  });

  describe('readUint()', () => {
    it.each([
      {
        data: Uint8Array.of(0),
        expected: [0, 1] as [number, number],
        error: null,
        name: 'should read single byte UINT',
      },
      {
        data: Uint8Array.of(0x80, 0x01),
        expected: [128, 2] as [number, number],
        error: null,
        name: 'should read two-byte UINT',
      },
      {
        data: Uint8Array.of(0x80),
        expected: null,
        error: new Error('Unexpected EOF reading bytes at position 1'),
        name: 'should fail when reading past EOF',
      },
    ])(
      '$name',
      ({
        data,
        expected,
        error,
      }:
        | { data: Uint8Array; expected: [number, number]; error: null }
        | { data: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          expect(readUint(data, 0)).toStrictEqual(expected);
        } else {
          expect(() => readUint(data, 0)).toThrow(error);
        }
      },
    );
  });

  describe('readBytes()', () => {
    it.each([
      {
        data: Uint8Array.of(0),
        expected: [Uint8Array.of(), 1] as [Uint8Array, number],
        error: null,
        name: 'should read empty BYTES',
      },
      {
        data: Uint8Array.of(1, 123),
        expected: [Uint8Array.of(123), 2] as [Uint8Array, number],
        error: null,
        name: 'should read single-byte BYTES',
      },
      {
        data: Uint8Array.of(2, 123, 123),
        expected: [Uint8Array.of(123, 123), 3] as [Uint8Array, number],
        error: null,
        name: 'should read two-byte BYTES',
      },
      {
        data: Uint8Array.of(2, 123),
        expected: null,
        error: new Error('Unexpected EOF reading bytes at position 1'),
        name: 'should fail when reading past EOF',
      },
    ])(
      '$name',
      ({
        data,
        expected,
        error,
      }:
        | { data: Uint8Array; expected: [Uint8Array, number]; error: null }
        | { data: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          expect(readBytes(data, 0)).toStrictEqual(expected);
        } else {
          expect(() => readBytes(data, 0)).toThrow(error);
        }
      },
    );
  });

  describe('readUrl()', () => {
    it.each([
      {
        data: Uint8Array.of(23, ...new TextEncoder().encode('https://www.example.com')),
        expected: [new URL('https://www.example.com'), 24] as [URL, number],
        error: null,
        name: 'should read URL',
      },
      {
        data: Uint8Array.of(22, ...new TextEncoder().encode('http://www.example.com')),
        expected: null,
        error: new Error('Invalid URL'),
        name: 'should fail for non-https URL',
      },
    ])(
      '$name',
      ({
        data,
        expected,
        error,
      }:
        | { data: Uint8Array; expected: [URL, number]; error: null }
        | { data: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          expect(readUrl(data, 0)).toStrictEqual(expected);
        } else {
          expect(() => readUrl(data, 0)).toThrow(error);
        }
      },
    );
  });

  describe('readLiteral()', () => {
    it.each([
      {
        data: Uint8Array.of(1, 2, 3),
        literal: Uint8Array.of(4, 5, 6),
        expected: null,
        error: new Error('Literal mismatch (expected 040506 but found 010203) at position 0'),
        name: 'should fail for mismatched literal',
      },
      {
        data: Uint8Array.of(1, 2, 3),
        literal: Uint8Array.of(1, 2, 3),
        expected: [Uint8Array.of(1, 2, 3), 3] as [Uint8Array, number],
        error: null,
        name: 'should pass for matched literal',
      },
    ])(
      '$name',
      ({
        data,
        literal,
        expected,
        error,
      }:
        | { data: Uint8Array; literal: Uint8Array; expected: [Uint8Array, number]; error: null }
        | { data: Uint8Array; literal: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          expect(readLiteral(data, 0, literal)).toStrictEqual(expected);
        } else {
          expect(() => readLiteral(data, 0, literal)).toThrow(error);
        }
      },
    );
  });

  describe('readDoneLeafPayload()', () => {
    it.each([
      {
        payload: Uint8Array.of(1, 2),
        expected: null,
        error: new Error('Garbage at end of attestation payload'),
        name: 'should fail when containing garbage at end',
      },
      {
        payload: Uint8Array.of(123),
        expected: 123,
        error: null,
        name: 'should pass for height payload',
      },
    ])(
      '$name',
      ({
        payload,
        expected,
        error,
      }:
        | { payload: Uint8Array; expected: number; error: null }
        | { payload: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          expect(readDoneLeafPayload(payload)).toStrictEqual(expected);
        } else {
          expect(() => readDoneLeafPayload(payload)).toThrow(error);
        }
      },
    );
  });

  describe('readPendingLeafPayload()', () => {
    it.each([
      {
        payload: Uint8Array.of(23, ...new TextEncoder().encode('https://www.example.com'), 1, 2, 3),
        expected: null,
        error: new Error('Garbage at end of Pending attestation payload'),
        name: 'should fail when containing garbage at end',
      },
      {
        payload: Uint8Array.of(23, ...new TextEncoder().encode('https://www.example.com')),
        expected: new URL('https://www.example.com'),
        error: null,
        name: 'should pass for height payload',
      },
    ])(
      '$name',
      ({
        payload,
        expected,
        error,
      }:
        | { payload: Uint8Array; expected: URL; error: null }
        | { payload: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          expect(readPendingLeafPayload(payload)).toStrictEqual(expected);
        } else {
          expect(() => readPendingLeafPayload(payload)).toThrow(error);
        }
      },
    );
  });

  describe('readLeaf()', () => {
    it.each([
      {
        data: Uint8Array.of(...uint8ArrayFromHex('0588960d73d71901'), 1, 123),
        expected: [{ type: 'bitcoin', height: 123 }, 10] as [Leaf, number],
        name: 'should read bitcoin leaf',
      },
      {
        data: Uint8Array.of(...uint8ArrayFromHex('06869a0d73d71b45'), 1, 123),
        expected: [{ type: 'litecoin', height: 123 }, 10] as [Leaf, number],
        name: 'should read litecoin leaf',
      },
      {
        data: Uint8Array.of(...uint8ArrayFromHex('30fe8087b5c7ead7'), 1, 123),
        expected: [{ type: 'ethereum', height: 123 }, 10] as [Leaf, number],
        name: 'should read ethereum leaf',
      },
      {
        data: Uint8Array.of(
          ...uint8ArrayFromHex('83dfe30d2ef90c8e'),
          24,
          23,
          ...new TextEncoder().encode('https://www.example.com'),
        ),
        expected: [{ type: 'pending', url: new URL('https://www.example.com') }, 33] as [Leaf, number],
        name: 'should read pending leaf',
      },
      {
        data: Uint8Array.of(...uint8ArrayFromHex('1122334455667788'), 10, ...uint8ArrayFromHex('ffeeddccbbaa99887766')),
        expected: [
          {
            type: 'unknown',
            header: uint8ArrayFromHex('1122334455667788'),
            payload: uint8ArrayFromHex('ffeeddccbbaa99887766'),
          },
          19,
        ] as [Leaf, number],
        name: 'should read unknown leaf',
      },
    ])('$name', ({ data, expected }: { data: Uint8Array; expected: [Leaf, number] }) => {
      expect(readLeaf(data, 0)).toStrictEqual(expected);
    });
  });

  describe('readEdgeOrLeaf()', () => {
    it.each([
      {
        data: Uint8Array.of(0x77),
        expected: null,
        error: new Error('Unknown operation 77 at position 0'),
        name: 'should fail for unknown operation',
      },
      {
        data: Uint8Array.of(0x00, ...uint8ArrayFromHex('0588960d73d71901'), 1, 123),
        expected: [{ type: 'bitcoin', height: 123 }, 11] as [Leaf, number],
        error: null,
        name: 'should read bitcoin leaf',
      },
      {
        data: Uint8Array.of(0x02, 0x00, ...uint8ArrayFromHex('0588960d73d71901'), 1, 123),
        expected: [
          [{ type: 'sha1' }, { edges: newEdges(), leaves: newLeaves().add({ type: 'bitcoin', height: 123 }) }],
          12,
        ] as [Edge, number],
        error: null,
        name: 'should read unary edge',
      },
      {
        data: Uint8Array.of(0xf0, 3, 1, 2, 3, 0x00, ...uint8ArrayFromHex('0588960d73d71901'), 1, 123),
        expected: [
          [
            { type: 'append', operand: Uint8Array.of(1, 2, 3) },
            { edges: newEdges(), leaves: newLeaves().add({ type: 'bitcoin', height: 123 }) },
          ],
          16,
        ] as [Edge, number],
        error: null,
        name: 'should read binary edge',
      },
    ])(
      '$name',
      ({
        data,
        expected,
        error,
      }:
        | { data: Uint8Array; expected: [Edge | Leaf, number]; error: null }
        | { data: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          const [expectedResult, expectedIdx]: [Edge | Leaf, number] = expected;
          const [result, idx]: [Edge | Leaf, number] = readEdgeOrLeaf(data, 0);
          expect(leafOrEdgeToString(result)).toStrictEqual(leafOrEdgeToString(expectedResult));
          expect(idx).toStrictEqual(expectedIdx);
        } else {
          expect(() => readEdgeOrLeaf(data, 0)).toThrow(error);
        }
      },
    );
  });

  describe('readTree()', () => {
    it.each([
      {
        data: Uint8Array.of(0x00, ...uint8ArrayFromHex('0588960d73d71901'), 1, 123),
        expected: [{ edges: newEdges(), leaves: newLeaves().add({ type: 'bitcoin', height: 123 }) }, 11] as [
          Tree,
          number,
        ],
        error: null,
        name: 'should read simple tree',
      },
      {
        data: Uint8Array.of(
          0xff,
          0x00,
          ...uint8ArrayFromHex('0588960d73d71901'),
          1,
          123,
          0x00,
          ...uint8ArrayFromHex('06869a0d73d71b45'),
          1,
          123,
        ),
        expected: [
          {
            edges: newEdges(),
            leaves: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
          },
          23,
        ] as [Tree, number],
        error: null,
        name: 'should read tree with two leaves',
      },
    ])(
      '$name',
      ({
        data,
        expected,
        error,
      }:
        | { data: Uint8Array; expected: [Tree, number]; error: null }
        | { data: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          const [expectedResult, expectedIdx]: [Tree, number] = expected;
          const [result, idx]: [Tree, number] = readTree(data, 0);
          expect(treeToString(result)).toStrictEqual(treeToString(expectedResult));
          expect(idx).toStrictEqual(expectedIdx);
        } else {
          expect(() => readTree(data, 0)).toThrow(error);
        }
      },
    );
  });

  describe('readFileHash()', () => {
    it.each([
      {
        data: Uint8Array.of(0x77),
        expected: null,
        error: new Error('Unknown hashing algorithm 77 at position 0'),
        name: 'should fail for unknown hashing algorithm',
      },
      {
        data: Uint8Array.of(0x02, ...uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233')),
        expected: [{ algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') }, 21] as [
          FileHash,
          number,
        ],
        error: null,
        name: 'should read sha1 fileHash',
      },
      {
        data: Uint8Array.of(0x03, ...uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233')),
        expected: [
          { algorithm: 'ripemd160', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          21,
        ] as [FileHash, number],
        error: null,
        name: 'should read ripemd160 fileHash',
      },
      {
        data: Uint8Array.of(
          0x08,
          ...uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'),
        ),
        expected: [
          {
            algorithm: 'sha256',
            value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'),
          },
          33,
        ] as [FileHash, number],
        error: null,
        name: 'should read sha256 fileHash',
      },
      {
        data: Uint8Array.of(
          0x67,
          ...uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'),
        ),
        expected: [
          {
            algorithm: 'keccak256',
            value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'),
          },
          33,
        ] as [FileHash, number],
        error: null,
        name: 'should read keccak256 fileHash',
      },
    ])(
      '$name',
      ({
        data,
        expected,
        error,
      }:
        | { data: Uint8Array; expected: [FileHash, number]; error: null }
        | { data: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          expect(readFileHash(data, 0)).toStrictEqual(expected);
        } else {
          expect(() => readFileHash(data, 0)).toThrow(error);
        }
      },
    );
  });

  describe('readVersion()', () => {
    it.each([
      {
        data: Uint8Array.of(2),
        expected: null,
        error: new Error('Unrecognized version (expected 1 but found 2) at position 0'),
        name: 'should fail for unknown version',
      },
      {
        data: Uint8Array.of(1),
        expected: [1, 1] as [number, number],
        error: null,
        name: 'should return version 1 data',
      },
    ])(
      '$name',
      ({
        data,
        expected,
        error,
      }:
        | { data: Uint8Array; expected: [number, number]; error: null }
        | { data: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          expect(readVersion(data, 0)).toStrictEqual(expected);
        } else {
          expect(() => readVersion(data, 0)).toThrow(error);
        }
      },
    );
  });

  describe('readTimestamp()', () => {
    it.each([
      {
        data: Uint8Array.of(
          ...uint8ArrayFromHex('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294'),
          1,
          0x02,
          ...uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
          0x00,
          ...uint8ArrayFromHex('0588960d73d71901'),
          1,
          123,
        ),
        expected: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: { edges: newEdges(), leaves: newLeaves().add({ type: 'bitcoin', height: 123 }) },
        } as Timestamp,
        error: null,
        name: 'should read simple tree timestamp',
      },
      {
        data: Uint8Array.of(
          ...uint8ArrayFromHex('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294'),
          1,
          0x02,
          ...uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
          0x00,
          ...uint8ArrayFromHex('0588960d73d71901'),
          1,
          123,
          4,
          5,
          6,
          7,
          8,
          9,
        ),
        expected: null,
        error: new Error('Garbage at EOF'),
        name: 'should fail if garbage found at EOF',
      },
    ])(
      '$name',
      ({
        data,
        expected,
        error,
      }:
        | { data: Uint8Array; expected: Timestamp; error: null }
        | { data: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          expect(timestampToString(readTimestamp(data))).toStrictEqual(timestampToString(expected));
        } else {
          expect(() => readTimestamp(data)).toThrow(error);
        }
      },
    );
  });
});
