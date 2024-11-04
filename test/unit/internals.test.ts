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

import type { Edge, Ops, Paths } from '../../src/internals';
import type { Leaf, Op, Tree } from '../../src/types';

import {
  callOp,
  callOps,
  compareEdges,
  compareLeaves,
  compareOps,
  incorporateToTree,
  incorporateTreeToTree,
  magicHeader,
  newTree,
  nonFinal,
  pathsToTree,
  treeToPaths,
  EdgeMap,
  LeafHeader,
  LeafSet,
  Tag,
} from '../../src/internals';
import { uint8ArrayToHex } from '../../src/utils';

import { treeToString } from '../helpers';

describe('Internals', (): void => {
  describe('Tag', (): void => {
    it.each([
      {
        element: 'attestation',
        expected: 0x00,
        name: 'should have correct attestation value',
      },
      {
        element: 'sha1',
        expected: 0x02,
        name: 'should have correct sha1 value',
      },
      {
        element: 'ripemd160',
        expected: 0x03,
        name: 'should have correct ripemd160 value',
      },
      {
        element: 'sha256',
        expected: 0x08,
        name: 'should have correct sha256 value',
      },
      {
        element: 'keccak256',
        expected: 0x67,
        name: 'should have correct keccak256 value',
      },
      {
        element: 'append',
        expected: 0xf0,
        name: 'should have correct append value',
      },
      {
        element: 'prepend',
        expected: 0xf1,
        name: 'should have correct prepend value',
      },
      {
        element: 'reverse',
        expected: 0xf2,
        name: 'should have correct reverse value',
      },
      {
        element: 'hexlify',
        expected: 0xf3,
        name: 'should have correct hexlify value',
      },
    ])('$name', ({ element, expected }: { element: string; expected: number }): void => {
      expect(Tag[element as keyof typeof Tag]).toStrictEqual(expected);
    });
  });

  describe('LeafHeader', (): void => {
    it.each([
      {
        element: 'bitcoin',
        expected: '0588960d73d71901',
        name: 'should have correct bitcoin value',
      },
      {
        element: 'litecoin',
        expected: '06869a0d73d71b45',
        name: 'should have correct litecoin value',
      },
      {
        element: 'ethereum',
        expected: '30fe8087b5c7ead7',
        name: 'should have correct ethereum value',
      },
      {
        element: 'pending',
        expected: '83dfe30d2ef90c8e',
        name: 'should have correct pending value',
      },
    ])('$name', ({ element, expected }: { element: string; expected: string }): void => {
      expect(LeafHeader[element as keyof typeof LeafHeader]).toStrictEqual(expected);
    });
  });

  describe('magicHeader', (): void => {
    test('should have correct value', (): void => {
      expect(uint8ArrayToHex(magicHeader)).toStrictEqual(
        '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294',
      );
    });
  });

  describe('nonFinal', (): void => {
    test('should have correct value', (): void => {
      expect(nonFinal).toStrictEqual(255);
    });
  });

  describe('callOp()', (): void => {
    it.each([
      {
        op: { type: 'sha1' } as Op,
        expected: '5d211bad8f4ee70e16c7d343a838fc344a1ed961',
        name: 'should correctly apply sha1 operation',
      },
      {
        op: { type: 'ripemd160' } as Op,
        expected: 'c11a22b375a791275cede257f7f0a0e8d8ef2424',
        name: 'should correctly apply ripemd160 operation',
      },
      {
        op: { type: 'sha256' } as Op,
        expected: '7192385c3c0605de55bb9476ce1d90748190ecb32a8eed7f5207b30cf6a1fe89',
        name: 'should correctly apply sha256 operation',
      },
      {
        op: { type: 'keccak256' } as Op,
        expected: '13a08e3cd39a1bc7bf9103f63f83273cced2beada9f723945176d6b983c65bd2',
        name: 'should correctly apply keccak256 operation',
      },
      {
        op: { type: 'append', operand: Uint8Array.of(7, 8, 9) } as Op,
        expected: '010203040506070809',
        name: 'should correctly apply append operation',
      },
      {
        op: { type: 'prepend', operand: Uint8Array.of(7, 8, 9) } as Op,
        expected: '070809010203040506',
        name: 'should correctly apply prepend operation',
      },
      {
        op: { type: 'reverse' } as Op,
        expected: '060504030201',
        name: 'should correctly apply reverse operation',
      },
      {
        op: { type: 'hexlify' } as Op,
        expected: '303130323033303430353036',
        name: 'should correctly apply hexlify operation',
      },
    ])('$name', ({ op, expected }: { op: Op; expected: string }): void => {
      expect(uint8ArrayToHex(callOp(op, Uint8Array.of(1, 2, 3, 4, 5, 6)))).toStrictEqual(expected);
    });
  });

  describe('callOps()', (): void => {
    it.each([
      {
        ops: [{ type: 'sha1' }, { type: 'sha1' }] as Ops,
        expected: 'a4b57f71771bf97396883832d94359d86acb6079',
        name: 'should correctly apply sha1, sha1 operations',
      },
      {
        ops: [{ type: 'sha1' }, { type: 'ripemd160' }] as Ops,
        expected: 'a954421e4426975c7c5798980a05a4527468ad13',
        name: 'should correctly apply sha1, ripemd160 operations',
      },
      {
        ops: [{ type: 'sha1' }, { type: 'sha256' }] as Ops,
        expected: '0bd3970606c05cf09b4ba3db76291f8ad9d26d02f487a62df1ad8f11622952a2',
        name: 'should correctly apply sha1, sha256 operations',
      },
      {
        ops: [{ type: 'sha1' }, { type: 'keccak256' }] as Ops,
        expected: 'ec573ac000e11ff98de8807466b09143dade900f6aaac4ee4f1648c3753b7051',
        name: 'should correctly apply sha1, keccak256 operations',
      },
      {
        ops: [{ type: 'sha1' }, { type: 'append', operand: Uint8Array.of(7, 8, 9) }] as Ops,
        expected: '5d211bad8f4ee70e16c7d343a838fc344a1ed961070809',
        name: 'should correctly apply sha1, append operations',
      },
      {
        ops: [{ type: 'sha1' }, { type: 'prepend', operand: Uint8Array.of(7, 8, 9) }] as Ops,
        expected: '0708095d211bad8f4ee70e16c7d343a838fc344a1ed961',
        name: 'should correctly apply sha1, prepend operations',
      },
      {
        ops: [{ type: 'sha1' }, { type: 'reverse' }] as Ops,
        expected: '61d91e4a34fc38a843d3c7160ee74e8fad1b215d',
        name: 'should correctly apply sha1, reverse operations',
      },
      {
        ops: [{ type: 'sha1' }, { type: 'hexlify' }] as Ops,
        expected: '35643231316261643866346565373065313663376433343361383338666333343461316564393631',
        name: 'should correctly apply sha1, hexlify operations',
      },
    ])('$name', ({ ops, expected }: { ops: Ops; expected: string }): void => {
      expect(uint8ArrayToHex(callOps(ops, Uint8Array.of(1, 2, 3, 4, 5, 6)))).toStrictEqual(expected);
    });
  });

  describe('compareLeaves()', (): void => {
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
    ])('$name', ({ left, right, expected }: { left: Leaf; right: Leaf; expected: number }): void => {
      expect(compareLeaves(left, right)).toStrictEqual(expected);
    });
  });

  describe('compareOps()', (): void => {
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
    ])('$name', ({ left, right, expected }: { left: Op; right: Op; expected: number }): void => {
      expect(compareOps(left, right)).toStrictEqual(expected);
    });
  });

  describe('compareEdges()', (): void => {
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
    ])('$name', ({ left, right, expected }: { left: Edge; right: Edge; expected: number }): void => {
      expect(compareEdges(left, right)).toStrictEqual(expected);
    });
  });

  describe('incorporateTreeToTree()', (): void => {
    it.each([
      {
        left: newTree(),
        right: newTree(),
        expected: newTree(),
        name: 'should incorporate empty trees into empty tree',
      },
      {
        left: newTree(),
        right: {
          leaves: new LeafSet().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: new EdgeMap(),
        },
        expected: {
          leaves: new LeafSet().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: new EdgeMap(),
        },
        name: 'should incorporate leaves into empty tree',
      },
      {
        left: {
          leaves: new LeafSet().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: new EdgeMap(),
        },
        right: newTree(),
        expected: {
          leaves: new LeafSet().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: new EdgeMap(),
        },
        name: 'should incorporate empty tree into leaves',
      },
      {
        left: newTree(),
        right: { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'sha1' }, newTree()) },
        expected: { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'sha1' }, newTree()) },
        name: 'should incorporate edges into empty tree',
      },
      {
        left: { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'sha1' }, newTree()) },
        right: newTree(),
        expected: { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'sha1' }, newTree()) },
        name: 'should incorporate empty tree into edges',
      },
      {
        left: { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'sha1' }, newTree()) },
        right: {
          leaves: new LeafSet().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: new EdgeMap(),
        },
        expected: {
          leaves: new LeafSet().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: new EdgeMap().add({ type: 'sha1' }, newTree()),
        },
        name: 'should incorporate leaves into edges',
      },
      {
        left: {
          leaves: new LeafSet().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: new EdgeMap(),
        },
        right: { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'sha1' }, newTree()) },
        expected: {
          leaves: new LeafSet().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: new EdgeMap().add({ type: 'sha1' }, newTree()),
        },
        name: 'should incorporate edges into leaves',
      },
    ])('$name', ({ left, right, expected }: { left: Tree; right: Tree; expected: Tree }): void => {
      expect(treeToString(incorporateTreeToTree(left, right))).toStrictEqual(treeToString(expected));
    });
  });

  describe('incorporateToTree()', (): void => {
    it.each([
      {
        left: newTree(),
        right: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() } as Leaf,
        expected: {
          leaves: new LeafSet().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: new EdgeMap(),
        },
        name: 'should incorporate leaves into empty tree',
      },
      {
        left: newTree(),
        right: [{ type: 'sha1' }, newTree()] as Edge,
        expected: { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'sha1' }, newTree()) },
        name: 'should incorporate edges into empty tree',
      },
    ])('$name', ({ left, right, expected }: { left: Tree; right: Edge | Leaf; expected: Tree }): void => {
      expect(treeToString(incorporateToTree(left, right))).toStrictEqual(treeToString(expected));
    });
  });

  describe('LeafSet', (): void => {
    describe('size()', (): void => {
      it.each([
        {
          leafSet: new LeafSet(),
          expected: 0,
          name: 'should return 0 for empty LeafSet',
        },
        {
          leafSet: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          expected: 1,
          name: 'should return 1 for singleton LeafSet',
        },
        {
          leafSet: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 123 }),
          expected: 1,
          name: 'should return 1 for singleton LeafSet (again)',
        },
      ])('$name', ({ leafSet, expected }: { leafSet: LeafSet; expected: number }): void => {
        expect(leafSet.size()).toEqual(expected);
      });
    });

    describe('values()', (): void => {
      it.each([
        {
          leafSet: new LeafSet(),
          expected: [] as Leaf[],
          name: 'should return empty for empty LeafSet',
        },
        {
          leafSet: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          expected: [{ type: 'bitcoin', height: 123 }] as Leaf[],
          name: 'should return singleton for singleton LeafSet',
        },
        {
          leafSet: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 123 }),
          expected: [{ type: 'bitcoin', height: 123 }] as Leaf[],
          name: 'should return singleton for singleton LeafSet (again)',
        },
        {
          leafSet: new LeafSet()
            .add({ type: 'bitcoin', height: 123 })
            .add({ type: 'bitcoin', height: 123 })
            .add({ type: 'litecoin', height: 123 }),
          expected: [
            { type: 'bitcoin', height: 123 },
            { type: 'litecoin', height: 123 },
          ] as Leaf[],
          name: 'should return non-singleton for non-singleton LeafSet',
        },
      ])('$name', ({ leafSet, expected }: { leafSet: LeafSet; expected: Leaf[] }): void => {
        expect(leafSet.values()).toEqual(expected);
      });
    });

    describe('remove()', (): void => {
      it.each([
        {
          leafSet: new LeafSet(),
          item: { type: 'bitcoin', height: 123 } as Leaf,
          expected: new LeafSet(),
          name: 'should not alter empty LeafSet',
        },
        {
          leafSet: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          item: { type: 'bitcoin', height: 123 } as Leaf,
          expected: new LeafSet(),
          name: 'should return empty LeafSet when removing last element',
        },
        {
          leafSet: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
          item: { type: 'bitcoin', height: 123 } as Leaf,
          expected: new LeafSet().add({ type: 'litecoin', height: 123 }),
          name: 'should remove non-combined element',
        },
        {
          leafSet: new LeafSet()
            .add({ type: 'bitcoin', height: 123 })
            .add({ type: 'litecoin', height: 123 })
            .add({ type: 'bitcoin', height: 123 }),
          item: { type: 'bitcoin', height: 123 } as Leaf,
          expected: new LeafSet().add({ type: 'litecoin', height: 123 }),
          name: 'should remove combined element',
        },
      ])('$name', ({ leafSet, item, expected }: { leafSet: LeafSet; item: Leaf; expected: LeafSet }): void => {
        expect(leafSet.remove(item)).toEqual(expected);
      });
    });

    describe('add()', (): void => {
      it.each([
        {
          leafSet: new LeafSet(),
          item: { type: 'bitcoin', height: 123 } as Leaf,
          expected: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          name: 'should add single item',
        },
        {
          leafSet: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          item: { type: 'bitcoin', height: 123 } as Leaf,
          expected: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 123 }),
          name: 'should add item and combine it',
        },
        {
          leafSet: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
          item: { type: 'bitcoin', height: 123 } as Leaf,
          expected: new LeafSet()
            .add({ type: 'litecoin', height: 123 })
            .add({ type: 'bitcoin', height: 123 })
            .add({ type: 'bitcoin', height: 123 }),
          name: 'should add item and combine it regardless of order',
        },
      ])('$name', ({ leafSet, item, expected }: { leafSet: LeafSet; item: Leaf; expected: LeafSet }): void => {
        expect(leafSet.add(item)).toEqual(expected);
      });
    });

    describe('incorporate()', (): void => {
      it.each([
        {
          leafSet: new LeafSet(),
          other: new LeafSet(),
          expected: new LeafSet(),
          name: 'should return empty LeafSet when combining empty LeafSets',
        },
        {
          leafSet: new LeafSet(),
          other: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          expected: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          name: 'should ignore empty LeafSet left',
        },
        {
          leafSet: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          other: new LeafSet(),
          expected: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          name: 'should ignore empty LeafSet right',
        },
        {
          leafSet: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          other: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          expected: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 123 }),
          name: 'should return combined LeafSet when incorporating no new elements',
        },
      ])('$name', ({ leafSet, other, expected }: { leafSet: LeafSet; other: LeafSet; expected: LeafSet }): void => {
        expect(leafSet.incorporate(other)).toEqual(expected);
      });
    });
  });

  describe('EdgeMap', (): void => {
    describe('size()', (): void => {
      it.each([
        {
          edgeMap: new EdgeMap(),
          expected: 0,
          name: 'should return 0 for empty EdgeMap',
        },
        {
          edgeMap: new EdgeMap().add(
            { type: 'sha1' },
            {
              leaves: new LeafSet().add({ type: 'pending', url: new URL('http://example.com') }),
              edges: new EdgeMap(),
            },
          ),
          expected: 1,
          name: 'should return 1 for singleton EdgeMap',
        },
        {
          edgeMap: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            ),
          expected: 1,
          name: 'should return 1 for singleton EdgeMap (again)',
        },
      ])('$name', ({ edgeMap, expected }: { edgeMap: EdgeMap; expected: number }): void => {
        expect(edgeMap.size()).toEqual(expected);
      });
    });

    describe('keys()', (): void => {
      it.each([
        {
          edgeMap: new EdgeMap(),
          expected: [] as Op[],
          name: 'should return empty for empty EdgeMap',
        },
        {
          edgeMap: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          expected: [{ type: 'sha1' }] as Op[],
          name: 'should return singleton for singleton EdgeMap',
        },
        {
          edgeMap: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            ),
          expected: [{ type: 'sha1' }] as Op[],
          name: 'should return singleton for singleton EdgeMap (again)',
        },
        {
          edgeMap: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'ripemd160' },
              { leaves: new LeafSet().add({ type: 'ethereum', height: 123 }), edges: new EdgeMap() },
            ),
          expected: [{ type: 'sha1' }, { type: 'ripemd160' }] as Op[],
          name: 'should return non-singleton for non-singleton EdgeMap',
        },
      ])('$name', ({ edgeMap, expected }: { edgeMap: EdgeMap; expected: Op[] }): void => {
        expect(edgeMap.keys()).toEqual(expected);
      });
    });

    describe('values()', (): void => {
      it.each([
        {
          edgeMap: new EdgeMap(),
          expected: [] as Tree[],
          name: 'should return empty for empty EdgeMap',
        },
        {
          edgeMap: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          expected: [{ leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() }],
          name: 'should return singleton for singleton EdgeMap',
        },
        {
          edgeMap: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            ),
          expected: [
            {
              leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
              edges: new EdgeMap(),
            },
          ] as Tree[],
          name: 'should return singleton for singleton EdgeMap (again)',
        },
        {
          edgeMap: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'ripemd160' },
              { leaves: new LeafSet().add({ type: 'ethereum', height: 123 }), edges: new EdgeMap() },
            ),
          expected: [
            {
              leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
              edges: new EdgeMap(),
            },
            { leaves: new LeafSet().add({ type: 'ethereum', height: 123 }), edges: new EdgeMap() },
          ] as Tree[],
          name: 'should return non-singleton for non-singleton EdgeMap',
        },
      ])('$name', ({ edgeMap, expected }: { edgeMap: EdgeMap; expected: Tree[] }): void => {
        expect(edgeMap.values()).toEqual(expected);
      });
    });

    describe('entries()', (): void => {
      it.each([
        {
          edgeMap: new EdgeMap(),
          expected: [] as [Op, Tree][],
          name: 'should return empty for empty EdgeMap',
        },
        {
          edgeMap: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          expected: [
            [{ type: 'sha1' }, { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() }],
          ] as [Op, Tree][],
          name: 'should return singleton for singleton EdgeMap',
        },
        {
          edgeMap: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            ),
          expected: [
            [
              { type: 'sha1' },
              {
                leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
                edges: new EdgeMap(),
              },
            ],
          ] as [Op, Tree][],
          name: 'should return singleton for singleton EdgeMap (again)',
        },
        {
          edgeMap: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'ripemd160' },
              { leaves: new LeafSet().add({ type: 'ethereum', height: 123 }), edges: new EdgeMap() },
            ),
          expected: [
            [
              { type: 'sha1' },
              {
                leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
                edges: new EdgeMap(),
              },
            ],
            [
              { type: 'ripemd160' },
              { leaves: new LeafSet().add({ type: 'ethereum', height: 123 }), edges: new EdgeMap() },
            ],
          ] as [Op, Tree][],
          name: 'should return non-singleton for non-singleton EdgeMap',
        },
        {
          edgeMap: new EdgeMap().add({ type: 'prepend', operand: Uint8Array.of(1, 2, 3) }, newTree()),
          expected: [[{ type: 'prepend', operand: Uint8Array.of(1, 2, 3) }, newTree()]] as [Op, Tree][],
          name: 'should return prepend operation operations',
        },
        {
          edgeMap: new EdgeMap().add({ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()),
          expected: [[{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()]] as [Op, Tree][],
          name: 'should return append operation operations',
        },
      ])('$name', ({ edgeMap, expected }: { edgeMap: EdgeMap; expected: [Op, Tree][] }): void => {
        expect(edgeMap.entries()).toEqual(expected);
      });
    });

    describe('remove()', (): void => {
      it.each([
        {
          edgeMap: new EdgeMap(),
          item: { type: 'sha1' } as Op,
          expected: new EdgeMap(),
          name: 'should not alter empty EdgeMap',
        },
        {
          edgeMap: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          item: { type: 'sha1' } as Op,
          expected: new EdgeMap(),
          name: 'should return empty EdgeMap when removing last element',
        },
        {
          edgeMap: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'ripemd160' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            ),
          item: { type: 'sha1' } as Op,
          expected: new EdgeMap().add(
            { type: 'ripemd160' },
            { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
          ),
          name: 'should remove non-combined element',
        },
        {
          edgeMap: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'ripemd160' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'ethereum', height: 123 }), edges: new EdgeMap() },
            ),
          item: { type: 'sha1' } as Op,
          expected: new EdgeMap().add(
            { type: 'ripemd160' },
            { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
          ),
          name: 'should remove combined element',
        },
      ])('$name', ({ edgeMap, item, expected }: { edgeMap: EdgeMap; item: Op; expected: EdgeMap }): void => {
        expect(edgeMap.remove(item)).toEqual(expected);
      });
    });

    describe('add()', (): void => {
      it.each([
        {
          edgeMap: new EdgeMap(),
          key: { type: 'sha1' } as Op,
          value: { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          expected: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          name: 'should add single item',
        },
        {
          edgeMap: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          key: { type: 'sha1' } as Op,
          value: { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
          expected: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            ),
          name: 'should add item and combine it',
        },
        {
          edgeMap: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'ripemd160' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            ),
          key: { type: 'sha1' } as Op,
          value: { leaves: new LeafSet().add({ type: 'ethereum', height: 123 }), edges: new EdgeMap() },
          expected: new EdgeMap()
            .add(
              { type: 'ripemd160' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'ethereum', height: 123 }), edges: new EdgeMap() },
            ),
          name: 'should add item and combine it regardless of order',
        },
      ])(
        '$name',
        ({ edgeMap, key, value, expected }: { edgeMap: EdgeMap; key: Op; value: Tree; expected: EdgeMap }): void => {
          expect(edgeMap.add(key, value)).toEqual(expected);
        },
      );
    });

    describe('incorporate()', (): void => {
      it.each([
        {
          edgeMap: new EdgeMap(),
          other: new EdgeMap(),
          expected: new EdgeMap(),
          name: 'should return empty EdgeMap when combining empty MergeMaps',
        },
        {
          edgeMap: new EdgeMap(),
          other: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          expected: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          name: 'should ignore empty EdgeMap left',
        },
        {
          edgeMap: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          other: new EdgeMap(),
          expected: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          name: 'should ignore empty EdgeMap right',
        },
        {
          edgeMap: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          ),
          other: new EdgeMap().add(
            { type: 'sha1' },
            { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
          ),
          expected: new EdgeMap()
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
            )
            .add(
              { type: 'sha1' },
              { leaves: new LeafSet().add({ type: 'litecoin', height: 123 }), edges: new EdgeMap() },
            ),
          name: 'should return combined EdgeMap when incorporating no new elements',
        },
      ])('$name', ({ edgeMap, other, expected }: { edgeMap: EdgeMap; other: EdgeMap; expected: EdgeMap }): void => {
        expect(edgeMap.incorporate(other)).toEqual(expected);
      });
    });
  });

  describe('newTree()', (): void => {
    test('should build empty tree', (): void => {
      expect(treeToString(newTree())).toStrictEqual('[]()');
    });
  });

  describe('pathsToTree()', (): void => {
    it.each([
      {
        paths: [],
        expected: newTree(),
        name: 'should return empty tree for empty paths',
      },
      {
        paths: [{ operations: [], leaf: { type: 'bitcoin', height: 123 } }] as Paths,
        expected: { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
        name: 'should return simple tree for simple path',
      },
      {
        paths: [{ operations: [{ type: 'sha1' }], leaf: { type: 'bitcoin', height: 123 } }] as Paths,
        expected: {
          edges: new EdgeMap().add(
            { type: 'sha1' },
            { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
          ),
          leaves: new LeafSet(),
        },
        name: 'should return singleton tree for singleton path',
      },
      {
        paths: [
          { operations: [{ type: 'sha1' }], leaf: { type: 'bitcoin', height: 123 } },
          { operations: [{ type: 'sha1' }], leaf: { type: 'bitcoin', height: 456 } },
        ] as Paths,
        expected: {
          edges: new EdgeMap().add(
            { type: 'sha1' },
            {
              edges: new EdgeMap(),
              leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 456 }),
            },
          ),
          leaves: new LeafSet(),
        },
        name: 'should return singleton tree with double leaves for double paths',
      },
      {
        paths: [
          { operations: [{ type: 'sha1' }], leaf: { type: 'bitcoin', height: 123 } },
          { operations: [{ type: 'sha256' }], leaf: { type: 'bitcoin', height: 456 } },
        ] as Paths,
        expected: {
          edges: new EdgeMap()
            .add(
              { type: 'sha1' },
              { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
            )
            .add(
              { type: 'sha256' },
              { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }) },
            ),
          leaves: new LeafSet(),
        },
        name: 'should return complex tree for complex paths',
      },
    ])('$name', ({ paths, expected }: { paths: Paths; expected: Tree }): void => {
      expect(treeToString(pathsToTree(paths))).toStrictEqual(treeToString(expected));
    });
  });

  describe('treeToPaths()', (): void => {
    it.each([
      {
        tree: newTree(),
        expected: [],
        name: 'should return empty paths for empty tree',
      },
      {
        tree: { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
        expected: [{ operations: [], leaf: { type: 'bitcoin', height: 123 } }] as Paths,
        name: 'should return simple path for simple tree',
      },
      {
        tree: {
          edges: new EdgeMap().add({ type: 'sha1' }, { edges: new EdgeMap(), leaves: new LeafSet() }),
          leaves: new LeafSet(),
        },
        expected: [],
        name: 'should return empty paths for barren tree',
      },
      {
        tree: {
          edges: new EdgeMap().add(
            { type: 'sha1' },
            { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
          ),
          leaves: new LeafSet(),
        },
        expected: [{ operations: [{ type: 'sha1' }], leaf: { type: 'bitcoin', height: 123 } }] as Paths,
        name: 'should return singleton path for singleton tree',
      },
      {
        tree: {
          edges: new EdgeMap().add(
            { type: 'sha1' },
            {
              edges: new EdgeMap(),
              leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 456 }),
            },
          ),
          leaves: new LeafSet(),
        },
        expected: [
          { operations: [{ type: 'sha1' }], leaf: { type: 'bitcoin', height: 123 } },
          { operations: [{ type: 'sha1' }], leaf: { type: 'bitcoin', height: 456 } },
        ] as Paths,
        name: 'should return singleton tree with double leaves for double paths',
      },
      {
        tree: {
          edges: new EdgeMap()
            .add(
              { type: 'sha1' },
              { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
            )
            .add(
              { type: 'sha256' },
              { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }) },
            ),
          leaves: new LeafSet(),
        },
        expected: [
          { operations: [{ type: 'sha1' }], leaf: { type: 'bitcoin', height: 123 } },
          { operations: [{ type: 'sha256' }], leaf: { type: 'bitcoin', height: 456 } },
        ] as Paths,
        name: 'should return complex paths for complex tree',
      },
    ])('$name', ({ tree, expected }: { tree: Tree; expected: Paths }): void => {
      expect(treeToPaths(tree)).toStrictEqual(expected);
    });
  });
});
