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

import { indent, info, infoEdge, infoFileHash, infoLeaf, infoTree } from '../../src/info';
import { newTree, EdgeMap, LeafSet } from '../../src/internals';
import { uint8ArrayFromHex } from '../../src/utils';

describe('Info', (): void => {
  describe('indent()', (): void => {
    it.each([
      {
        input: '',
        expected: ' -> ',
        name: 'should indent empty string',
      },
      {
        input: 'something',
        expected: ' -> something',
        name: 'should indent non-empty string',
      },
      {
        input: 'something\nelse\nentirely',
        expected: ' -> something\n    else\n    entirely',
        name: 'should indent multiline string',
      },
    ])('$name', ({ input, expected }: { input: string; expected: string }): void => {
      expect(indent(input)).toStrictEqual(expected);
    });
  });

  describe('infoLeaf()', (): void => {
    it.each([
      {
        leaf: { type: 'pending', url: new URL('http://www.example.com') } as Leaf,
        expected: 'pendingVerify(msg, http://www.example.com/)',
        name: 'should show pending leaf',
      },
      {
        leaf: {
          type: 'unknown',
          header: uint8ArrayFromHex('0123456789abcdef'),
          payload: uint8ArrayFromHex('0123456789abcdef0123456789abcdef'),
        } as Leaf,
        expected: 'unknownVerify<0123456789abcdef>(msg, 0123456789abcdef0123456789abcdef)',
        name: 'should show unknown leaf',
      },
      {
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        expected: 'bitcoinVerify(msg, 123)',
        name: 'show bitcoin leaf',
      },
      {
        leaf: { type: 'litecoin', height: 123 } as Leaf,
        expected: 'litecoinVerify(msg, 123)',
        name: 'show litecoin leaf',
      },
      {
        leaf: { type: 'ethereum', height: 123 } as Leaf,
        expected: 'ethereumVerify(msg, 123)',
        name: 'show ethereum leaf',
      },
    ])('$name', ({ leaf, expected }: { leaf: Leaf; expected: string }): void => {
      expect(infoLeaf(leaf)).toStrictEqual(expected);
    });
  });

  describe('infoEdge()', (): void => {
    it.each([
      {
        edge: [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        msg: undefined,
        expected: 'msg = append(msg, 010203)',
        name: 'should show binary operation',
      },
      {
        edge: [{ type: 'prepend', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        msg: Uint8Array.of(4, 5, 6),
        expected: 'msg = prepend(msg, 010203)\n    = 010203040506',
        name: 'should show binary operation (verbose)',
      },
      {
        edge: [{ type: 'sha1' }, newTree()] as Edge,
        msg: undefined,
        expected: 'msg = sha1(msg)',
        name: 'should show unary operation',
      },
      {
        edge: [{ type: 'reverse' }, newTree()] as Edge,
        msg: Uint8Array.of(4, 5, 6),
        expected: 'msg = reverse(msg)\n    = 060504',
        name: 'should show unary operation (verbose)',
      },
      {
        edge: [
          { type: 'sha1' },
          { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'sha256' }, newTree()) },
        ] as Edge,
        msg: undefined,
        expected: 'msg = sha1(msg)\nmsg = sha256(msg)',
        name: 'should show subtree',
      },
      {
        edge: [
          { type: 'reverse' },
          { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'reverse' }, newTree()) },
        ] as Edge,
        msg: Uint8Array.of(4, 5, 6),
        expected: 'msg = reverse(msg)\n    = 060504\nmsg = reverse(msg)\n    = 040506',
        name: 'should show subtree (verbose)',
      },
    ])('$name', ({ edge, msg, expected }: { edge: Edge; msg: Uint8Array | undefined; expected: string }): void => {
      expect(infoEdge(edge, msg)).toStrictEqual(expected);
    });
  });

  describe('infoTree()', (): void => {
    it.each([
      {
        tree: newTree(),
        msg: undefined,
        expected: '',
        name: 'should show empty tree',
      },
      {
        tree: { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
        msg: undefined,
        expected: 'bitcoinVerify(msg, 123)',
        name: 'should show tree with single leaf',
      },
      {
        tree: {
          edges: new EdgeMap(),
          leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 456 }),
        },
        msg: undefined,
        expected: ' -> bitcoinVerify(msg, 123)\n -> bitcoinVerify(msg, 456)',
        name: 'should show tree with two leaves',
      },
      {
        tree: { edges: new EdgeMap().add({ type: 'sha1' }, newTree()), leaves: new LeafSet() },
        msg: undefined,
        expected: 'msg = sha1(msg)',
        name: 'should show tree with single edge',
      },
      {
        tree: {
          edges: new EdgeMap().add({ type: 'sha1' }, newTree()).add({ type: 'reverse' }, newTree()),
          leaves: new LeafSet(),
        },
        msg: undefined,
        expected: ' -> msg = sha1(msg)\n -> msg = reverse(msg)',
        name: 'should show tree with two edges',
      },
      {
        tree: {
          edges: new EdgeMap().add(
            { type: 'sha1' },
            { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }) },
          ),
          leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
        },
        msg: undefined,
        expected: ' -> bitcoinVerify(msg, 123)\n -> msg = sha1(msg)\n    bitcoinVerify(msg, 456)',
        name: 'should show tree with leaves and edges',
      },
      {
        tree: { edges: new EdgeMap().add({ type: 'sha1' }, newTree()), leaves: new LeafSet() },
        msg: Uint8Array.of(1, 2, 3),
        expected: 'msg = sha1(msg)\n    = 7037807198c22a7d2b0807371d763779a84fdfcf',
        name: 'should show tree with single edge (verbose)',
      },
      {
        tree: {
          edges: new EdgeMap().add({ type: 'sha1' }, newTree()).add({ type: 'reverse' }, newTree()),
          leaves: new LeafSet(),
        },
        msg: Uint8Array.of(1, 2, 3),
        expected:
          ' -> msg = sha1(msg)\n        = 7037807198c22a7d2b0807371d763779a84fdfcf\n -> msg = reverse(msg)\n        = 030201',
        name: 'should show tree with two edges (verbose)',
      },
      {
        tree: {
          edges: new EdgeMap().add(
            { type: 'sha1' },
            { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }) },
          ),
          leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
        },
        msg: Uint8Array.of(1, 2, 3),
        expected:
          ' -> bitcoinVerify(msg, 123)\n -> msg = sha1(msg)\n        = 7037807198c22a7d2b0807371d763779a84fdfcf\n    bitcoinVerify(msg, 456)',
        name: 'should show tree with leaves and edges (verbose)',
      },
    ])('$name', ({ tree, msg, expected }: { tree: Tree; msg: Uint8Array | undefined; expected: string }): void => {
      expect(infoTree(tree, msg)).toStrictEqual(expected);
    });
  });

  describe('infoFileHash()', (): void => {
    it.each([
      {
        fileHash: {
          algorithm: 'sha1',
          value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef01234567'),
        } as FileHash,
        verbose: false,
        expected: 'msg = sha1(FILE)',
        name: 'should show fileHash',
      },
      {
        fileHash: {
          algorithm: 'sha256',
          value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
        } as FileHash,
        verbose: true,
        expected: 'msg = sha256(FILE)\n    = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        name: 'should show fileHash (verbose)',
      },
    ])('$name', ({ fileHash, verbose, expected }: { fileHash: FileHash; verbose: boolean; expected: string }): void => {
      expect(infoFileHash(fileHash, verbose)).toStrictEqual(expected);
    });
  });

  describe('info()', (): void => {
    it.each([
      {
        timestamp: {
          version: 1,
          fileHash: {
            algorithm: 'sha1',
            value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef01234567'),
          },
          tree: newTree(),
        } as Timestamp,
        verbose: false,
        expected: 'msg = sha1(FILE)',
        name: 'should show empty timestamp',
      },
      {
        timestamp: {
          version: 1,
          fileHash: {
            algorithm: 'sha1',
            value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef01234567'),
          },
          tree: newTree(),
        } as Timestamp,
        verbose: true,
        expected: '# version: 1\nmsg = sha1(FILE)\n    = 0123456789abcdef0123456789abcdef01234567',
        name: 'should show empty timestamp (verbose)',
      },
      {
        timestamp: {
          version: 1,
          fileHash: {
            algorithm: 'sha1',
            value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef01234567'),
          },
          tree: {
            edges: new EdgeMap().add(
              { type: 'sha1' },
              { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }) },
            ),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          },
        } as Timestamp,
        verbose: false,
        expected: 'msg = sha1(FILE)\n -> bitcoinVerify(msg, 123)\n -> msg = sha1(msg)\n    bitcoinVerify(msg, 456)',
        name: 'should show non-empty timestamp',
      },
      {
        timestamp: {
          version: 1,
          fileHash: {
            algorithm: 'sha1',
            value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef01234567'),
          },
          tree: {
            edges: new EdgeMap().add(
              { type: 'sha1' },
              { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }) },
            ),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          },
        } as Timestamp,
        verbose: true,
        expected:
          '# version: 1\nmsg = sha1(FILE)\n    = 0123456789abcdef0123456789abcdef01234567\n -> bitcoinVerify(msg, 123)\n -> msg = sha1(msg)\n        = ef473bbc24024ac1d66b318ac96bb31a95fd9a7d\n    bitcoinVerify(msg, 456)',
        name: 'should show non-empty timestamp (verbose)',
      },
    ])(
      '$name',
      ({ timestamp, verbose, expected }: { timestamp: Timestamp; verbose: boolean; expected: string }): void => {
        expect(info(timestamp, verbose)).toStrictEqual(expected);
      },
    );

    test('should default to non-verbose', (): void => {
      expect(
        info({
          version: 1,
          fileHash: {
            algorithm: 'sha1',
            value: uint8ArrayFromHex('0123456789abcdef0123456789abcdef01234567'),
          },
          tree: newTree(),
        }),
      ).toStrictEqual('msg = sha1(FILE)');
    });
  });
});
