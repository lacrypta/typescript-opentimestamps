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

import type { Edge, FileHash, Leaf, Op, Timestamp, Tree } from '../src/types';

import { newEdges, newLeaves, newTree } from '../src/internals';
import { uint8ArrayFromHex } from '../src/utils';
import {
  compareEdges,
  compareLeaves,
  compareOps,
  writeBytes,
  writeEdge,
  writeFileHash,
  writeLeaf,
  writeTimestamp,
  writeTree,
  writeUint,
} from '../src/write';

describe('Write', () => {
  describe('writeUint()', () => {
    it.each([
      {
        input: -1,
        expected: null,
        error: new Error('Expected safe non-negative value'),
        name: 'should fail for negative numbers',
      },
      {
        // eslint-disable-next-line @typescript-eslint/no-loss-of-precision
        input: 12345678901234567890,
        expected: null,
        error: new Error('Expected safe non-negative value'),
        name: 'should fail for non-safe numbers',
      },
      {
        input: 0b0000000,
        expected: Uint8Array.of(0b0000000),
        error: null,
        name: 'should write single-byte value',
      },
      {
        input: 0b1000010,
        expected: Uint8Array.of(0b1000010),
        error: null,
        name: 'should write single-byte value (again)',
      },
      {
        input: 0b0000001_1111111,
        expected: Uint8Array.of(0b11111111, 0b00000001),
        error: null,
        name: 'should write multi-byte value',
      },
      {
        input: 0b0000011_1111110_1000010,
        expected: Uint8Array.of(0b11000010, 0b11111110, 0b00000011),
        error: null,
        name: 'should write multi-byte value (again)',
      },
    ])(
      '$name',
      ({
        input,
        expected,
        error,
      }: { input: number; expected: Uint8Array; error: null } | { input: number; expected: null; error: Error }) => {
        if (null === error) {
          expect(writeUint(input)).toStrictEqual(expected);
        } else {
          expect(() => writeUint(input)).toThrow(error);
        }
      },
    );
  });

  describe('writeBytes()', () => {
    it.each([
      {
        input: Uint8Array.of(),
        expected: Uint8Array.of(0),
        name: 'should write empty bytes',
      },
      {
        input: new TextEncoder().encode('something'),
        expected: Uint8Array.of('something'.length, ...new TextEncoder().encode('something')),
        name: 'should write empty bytes',
      },
    ])('$name', ({ input, expected }: { input: Uint8Array; expected: Uint8Array }) => {
      expect(writeBytes(input)).toStrictEqual(expected);
    });
  });

  describe('writeFileHash()', () => {
    it.each([
      {
        input: { algorithm: 'sha1', value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef01234567') } as FileHash,
        expected: uint8ArrayFromHex('02' + '0123456789abcdef0123456789abcdef01234567'),
        name: 'should write sha1 fileHash',
      },
      {
        input: {
          algorithm: 'ripemd160',
          value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef01234567'),
        } as FileHash,
        expected: uint8ArrayFromHex('03' + '0123456789abcdef0123456789abcdef01234567'),
        name: 'should write ripemd160 fileHash',
      },
      {
        input: {
          algorithm: 'sha256',
          value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
        } as FileHash,
        expected: uint8ArrayFromHex('08' + '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
        name: 'should write sha256 fileHash',
      },
      {
        input: {
          algorithm: 'keccak256',
          value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
        } as FileHash,
        expected: uint8ArrayFromHex('67' + '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
        name: 'should write keccak256 fileHash',
      },
    ])('$name', ({ input, expected }: { input: FileHash; expected: Uint8Array }) => {
      expect(writeFileHash(input)).toStrictEqual(expected);
    });
  });

  describe('compareLeaves()', () => {
    it.each([
      {
        left: { type: 'bitcoin', height: 123 } as Leaf,
        right: { type: 'litecoin', height: 123 } as Leaf,
        expected: -1,
        name: 'should order according to different headers',
      },
      {
        left: { type: 'litecoin', height: 123 } as Leaf,
        right: { type: 'bitcoin', height: 123 } as Leaf,
        expected: 1,
        name: 'should order according to different headers (reversed)',
      },
      {
        left: { type: 'bitcoin', height: 456 } as Leaf,
        right: { type: 'bitcoin', height: 123 } as Leaf,
        expected: 333,
        name: 'should order bitcoin according to height',
      },
      {
        left: { type: 'bitcoin', height: 123 } as Leaf,
        right: { type: 'bitcoin', height: 123 } as Leaf,
        expected: 0,
        name: 'should order bitcoin according to height (equal)',
      },
      {
        left: { type: 'bitcoin', height: 123 } as Leaf,
        right: { type: 'bitcoin', height: 456 } as Leaf,
        expected: -333,
        name: 'should order bitcoin according to height (reversed)',
      },
      {
        left: { type: 'litecoin', height: 456 } as Leaf,
        right: { type: 'litecoin', height: 123 } as Leaf,
        expected: 333,
        name: 'should order litecoin according to height',
      },
      {
        left: { type: 'litecoin', height: 123 } as Leaf,
        right: { type: 'litecoin', height: 123 } as Leaf,
        expected: 0,
        name: 'should order litecoin according to height (equal)',
      },
      {
        left: { type: 'litecoin', height: 123 } as Leaf,
        right: { type: 'litecoin', height: 456 } as Leaf,
        expected: -333,
        name: 'should order litecoin according to height (reversed)',
      },
      {
        left: { type: 'ethereum', height: 456 } as Leaf,
        right: { type: 'ethereum', height: 123 } as Leaf,
        expected: 333,
        name: 'should order ethereum according to height',
      },
      {
        left: { type: 'ethereum', height: 123 } as Leaf,
        right: { type: 'ethereum', height: 123 } as Leaf,
        expected: 0,
        name: 'should order ethereum according to height (equal)',
      },
      {
        left: { type: 'ethereum', height: 123 } as Leaf,
        right: { type: 'ethereum', height: 456 } as Leaf,
        expected: -333,
        name: 'should order ethereum according to height (reversed)',
      },
      {
        left: { type: 'pending', url: new URL('http://www.example/a') } as Leaf,
        right: { type: 'pending', url: new URL('http://www.example/b') } as Leaf,
        expected: -1,
        name: 'should order pending according to url',
      },
      {
        left: { type: 'pending', url: new URL('http://www.example') } as Leaf,
        right: { type: 'pending', url: new URL('http://www.example') } as Leaf,
        expected: 0,
        name: 'should order pending according to url (equal)',
      },
      {
        left: { type: 'pending', url: new URL('http://www.example/b') } as Leaf,
        right: { type: 'pending', url: new URL('http://www.example/a') } as Leaf,
        expected: 1,
        name: 'should order pending according to url (reversed)',
      },
      {
        left: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(1) } as Leaf,
        right: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(2) } as Leaf,
        expected: -1,
        name: 'should order unknown according to payload',
      },
      {
        left: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() } as Leaf,
        right: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() } as Leaf,
        expected: 0,
        name: 'should order unknown according to payload (equal)',
      },
      {
        left: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(2) } as Leaf,
        right: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(1) } as Leaf,
        expected: 1,
        name: 'should order unknown according to payload (reversed)',
      },
    ])('$name', ({ left, right, expected }: { left: Leaf; right: Leaf; expected: number }) => {
      expect(compareLeaves(left, right)).toStrictEqual(expected);
    });
  });

  describe('compareOps()', () => {
    it.each([
      {
        left: { type: 'sha1' } as Op,
        right: { type: 'sha256' } as Op,
        expected: -6,
        name: 'should order according to different tags',
      },
      {
        left: { type: 'sha1' } as Op,
        right: { type: 'sha1' } as Op,
        expected: 0,
        name: 'should order according to different tags (equal)',
      },
      {
        left: { type: 'sha256' } as Op,
        right: { type: 'sha1' } as Op,
        expected: 6,
        name: 'should order according to different tags (reversed)',
      },
      {
        left: { type: 'append', operand: Uint8Array.of(1, 2, 3) } as Op,
        right: { type: 'append', operand: Uint8Array.of(4, 5, 6) } as Op,
        expected: -3,
        name: 'should order binary according to operand',
      },
      {
        left: { type: 'prepend', operand: Uint8Array.of(1, 2, 3) } as Op,
        right: { type: 'prepend', operand: Uint8Array.of(1, 2, 3) } as Op,
        expected: 0,
        name: 'should order binary according to operand (equal)',
      },
      {
        left: { type: 'append', operand: Uint8Array.of(4, 5, 6) } as Op,
        right: { type: 'append', operand: Uint8Array.of(1, 2, 3) } as Op,
        expected: 3,
        name: 'should order binary according to operand (reversed)',
      },
    ])('$name', ({ left, right, expected }: { left: Op; right: Op; expected: number }) => {
      expect(compareOps(left, right)).toStrictEqual(expected);
    });
  });

  describe('compareEdges()', () => {
    it.each([
      {
        left: [{ type: 'sha1' }, newTree()] as Edge,
        right: [{ type: 'sha256' }, newTree()] as Edge,
        expected: -6,
        name: 'should order according to different tags',
      },
      {
        left: [{ type: 'sha1' }, newTree()] as Edge,
        right: [{ type: 'sha1' }, newTree()] as Edge,
        expected: 0,
        name: 'should order according to different tags (equal)',
      },
      {
        left: [{ type: 'sha256' }, newTree()] as Edge,
        right: [{ type: 'sha1' }, newTree()] as Edge,
        expected: 6,
        name: 'should order according to different tags (reversed)',
      },
      {
        left: [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        right: [{ type: 'append', operand: Uint8Array.of(4, 5, 6) }, newTree()] as Edge,
        expected: -3,
        name: 'should order binary according to operand',
      },
      {
        left: [{ type: 'prepend', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        right: [{ type: 'prepend', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        expected: 0,
        name: 'should order binary according to operand (equal)',
      },
      {
        left: [{ type: 'append', operand: Uint8Array.of(4, 5, 6) }, newTree()] as Edge,
        right: [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        expected: 3,
        name: 'should order binary according to operand (reversed)',
      },
    ])('$name', ({ left, right, expected }: { left: Edge; right: Edge; expected: number }) => {
      expect(compareEdges(left, right)).toStrictEqual(expected);
    });
  });

  describe('writeLeaf()', () => {
    it.each([
      {
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        expected: uint8ArrayFromHex('000588960d73d71901017b'),
        name: 'should write bitcoin leaf',
      },
      {
        leaf: { type: 'litecoin', height: 123 } as Leaf,
        expected: uint8ArrayFromHex('0006869a0d73d71b45017b'),
        name: 'should write litecoin leaf',
      },
      {
        leaf: { type: 'ethereum', height: 123 } as Leaf,
        expected: uint8ArrayFromHex('0030fe8087b5c7ead7017b'),
        name: 'should write ethereum leaf',
      },
      {
        leaf: { type: 'pending', url: new URL('http://www.example.com') } as Leaf,
        expected: uint8ArrayFromHex('0083dfe30d2ef90c8e1817687474703a2f2f7777772e6578616d706c652e636f6d2f'),
        name: 'should write pending leaf',
      },
      {
        leaf: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(9, 0) } as Leaf,
        expected: uint8ArrayFromHex('000102030405060708020900'),
        name: 'should write unknown leaf',
      },
    ])('$name', ({ leaf, expected }: { leaf: Leaf; expected: Uint8Array }) => {
      expect(writeLeaf(leaf)).toStrictEqual(expected);
    });
  });

  describe('writeEdge()', () => {
    it.each([
      {
        edge: [{ type: 'sha1' }, newTree()] as Edge,
        expected: uint8ArrayFromHex('02'),
        name: 'should write sha1 edge',
      },
      {
        edge: [{ type: 'ripemd160' }, newTree()] as Edge,
        expected: uint8ArrayFromHex('03'),
        name: 'should write ripemd160 edge',
      },
      {
        edge: [{ type: 'sha256' }, newTree()] as Edge,
        expected: uint8ArrayFromHex('08'),
        name: 'should write sha256 edge',
      },
      {
        edge: [{ type: 'keccak256' }, newTree()] as Edge,
        expected: uint8ArrayFromHex('67'),
        name: 'should write keccak256 edge',
      },
      {
        edge: [{ type: 'reverse' }, newTree()] as Edge,
        expected: uint8ArrayFromHex('f2'),
        name: 'should write reverse edge',
      },
      {
        edge: [{ type: 'hexlify' }, newTree()] as Edge,
        expected: uint8ArrayFromHex('f3'),
        name: 'should write hexlify edge',
      },
      {
        edge: [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        expected: uint8ArrayFromHex('f003010203'),
        name: 'should write append edge',
      },
      {
        edge: [{ type: 'prepend', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        expected: uint8ArrayFromHex('f103010203'),
        name: 'should write prepend edge',
      },
    ])('$name', ({ edge, expected }: { edge: Edge; expected: Uint8Array }) => {
      expect(writeEdge(edge)).toStrictEqual(expected);
    });
  });

  describe('writeTree()', () => {
    it.each([
      {
        tree: newTree(),
        expected: uint8ArrayFromHex(''),
        name: 'should write empty tree',
      },
      {
        tree: { leaves: newLeaves().add({ type: 'bitcoin', height: 123 }), edges: newEdges() },
        expected: uint8ArrayFromHex('000588960d73d71901017b'),
        name: 'should write tree with single leaf',
      },
      {
        tree: {
          leaves: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
          edges: newEdges(),
        },
        expected: uint8ArrayFromHex('ff000588960d73d71901017b0006869a0d73d71b45017b'),
        name: 'should write tree with two leaves',
      },
      {
        tree: { leaves: newLeaves(), edges: newEdges().add({ type: 'sha1' }, newTree()) },
        expected: uint8ArrayFromHex('02'),
        name: 'should write tree with single edge',
      },
      {
        tree: {
          leaves: newLeaves(),
          edges: newEdges().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
        },
        expected: uint8ArrayFromHex('ff0208'),
        name: 'should write tree with two edges',
      },
      {
        tree: {
          leaves: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
          edges: newEdges().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
        },
        expected: uint8ArrayFromHex('ff000588960d73d71901017bff0006869a0d73d71b45017bff0208'),
        name: 'should write tree with edges and leaves',
      },
    ])('$name', ({ tree, expected }: { tree: Tree; expected: Uint8Array }) => {
      expect(writeTree(tree)).toStrictEqual(expected);
    });
  });

  describe('writeTimestamp()', () => {
    it.each([
      {
        timestamp: {
          version: 1,
          fileHash: {
            algorithm: 'sha256',
            value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
          },
          tree: newTree(),
        } as Timestamp,
        expected: uint8ArrayFromHex(
          '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294' +
            '01' +
            '08' +
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        ),
        name: 'should write empty timestamp',
      },
      {
        timestamp: {
          version: 1,
          fileHash: {
            algorithm: 'sha256',
            value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
          },
          tree: {
            leaves: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
            edges: newEdges().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
          },
        } as Timestamp,
        expected: uint8ArrayFromHex(
          '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294' +
            '01' +
            '08' +
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' +
            'ff000588960d73d71901017bff0006869a0d73d71b45017bff0208',
        ),
        name: 'should write non-empty timestamp',
      },
    ])('$name', ({ timestamp, expected }: { timestamp: Timestamp; expected: Uint8Array }) => {
      expect(writeTimestamp(timestamp)).toStrictEqual(expected);
    });
  });
});