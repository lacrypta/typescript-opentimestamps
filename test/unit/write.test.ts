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

import type { Edge } from '../../src/internals';
import type { FileHash, Leaf, Timestamp, Tree } from '../../src/types';

import { newTree, EdgeMap, LeafSet } from '../../src/internals';
import { uint8ArrayFromHex } from '../../src/utils';
import { write, writeBytes, writeEdge, writeFileHash, writeLeaf, writeTree, writeUint } from '../../src/write';

const textEncoder: TextEncoder = new TextEncoder();

describe('Write', (): void => {
  describe('writeUint()', (): void => {
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
      }:
        | { input: number; expected: Uint8Array; error: null }
        | { input: number; expected: null; error: Error }): void => {
        if (null === error) {
          expect(writeUint(input)).toStrictEqual(expected);
        } else {
          expect((): void => {
            writeUint(input);
          }).toThrow(error);
        }
      },
    );
  });

  describe('writeBytes()', (): void => {
    it.each([
      {
        input: Uint8Array.of(),
        expected: Uint8Array.of(0),
        name: 'should write empty bytes',
      },
      {
        input: textEncoder.encode('something'),
        expected: Uint8Array.of('something'.length, ...textEncoder.encode('something')),
        name: 'should write empty bytes',
      },
    ])('$name', ({ input, expected }: { input: Uint8Array; expected: Uint8Array }): void => {
      expect(writeBytes(input)).toStrictEqual(expected);
    });
  });

  describe('writeFileHash()', (): void => {
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
    ])('$name', ({ input, expected }: { input: FileHash; expected: Uint8Array }): void => {
      expect(writeFileHash(input)).toStrictEqual(expected);
    });
  });

  describe('writeLeaf()', (): void => {
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
    ])('$name', ({ leaf, expected }: { leaf: Leaf; expected: Uint8Array }): void => {
      expect(writeLeaf(leaf)).toStrictEqual(expected);
    });
  });

  describe('writeEdge()', (): void => {
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
    ])('$name', ({ edge, expected }: { edge: Edge; expected: Uint8Array }): void => {
      expect(writeEdge(edge)).toStrictEqual(expected);
    });
  });

  describe('writeTree()', (): void => {
    it.each([
      {
        tree: newTree(),
        expected: uint8ArrayFromHex(''),
        name: 'should write empty tree',
      },
      {
        tree: { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
        expected: uint8ArrayFromHex('000588960d73d71901017b'),
        name: 'should write tree with single leaf',
      },
      {
        tree: {
          leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
          edges: new EdgeMap(),
        },
        expected: uint8ArrayFromHex('ff000588960d73d71901017b0006869a0d73d71b45017b'),
        name: 'should write tree with two leaves',
      },
      {
        tree: { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'sha1' }, newTree()) },
        expected: uint8ArrayFromHex('02'),
        name: 'should write tree with single edge',
      },
      {
        tree: {
          leaves: new LeafSet(),
          edges: new EdgeMap().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
        },
        expected: uint8ArrayFromHex('ff0208'),
        name: 'should write tree with two edges',
      },
      {
        tree: {
          leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
          edges: new EdgeMap().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
        },
        expected: uint8ArrayFromHex('ff000588960d73d71901017bff0006869a0d73d71b45017bff0208'),
        name: 'should write tree with edges and leaves',
      },
    ])('$name', ({ tree, expected }: { tree: Tree; expected: Uint8Array }): void => {
      expect(writeTree(tree)).toStrictEqual(expected);
    });
  });

  describe('write()', (): void => {
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
            leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
            edges: new EdgeMap().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
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
    ])('$name', ({ timestamp, expected }: { timestamp: Timestamp; expected: Uint8Array }): void => {
      expect(write(timestamp)).toStrictEqual(expected);
    });
  });
});
