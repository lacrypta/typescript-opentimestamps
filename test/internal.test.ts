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

import type { Edge, Leaf, Op, Ops, Tree } from '../src/types';

import {
  callOp,
  callOps,
  incorporateToTree,
  incorporateTreeToTree,
  newEdges,
  newLeaves,
  newTree,
} from '../src/internals';
import { MergeMap, MergeSet, uint8ArrayToHex } from '../src/utils';

const opToString: (op: Op) => string = (op: Op): string => {
  switch (op.type) {
    case 'append':
    case 'prepend':
      return `${op.type}:${uint8ArrayToHex(op.operand)}`;
    default:
      return op.type;
  }
};

const leafToString: (leaf: Leaf) => string = (leaf: Leaf): string => {
  switch (leaf.type) {
    case 'pending':
      return `${leaf.type}:${leaf.url.toString()}`;
    case 'unknown':
      return `${leaf.type}:${uint8ArrayToHex(leaf.header)}:${uint8ArrayToHex(leaf.payload)}`;
    default:
      return `${leaf.type}:${leaf.height}`;
  }
};

const mergeSetToString: (ms: MergeSet<Leaf>) => string = (ms: MergeSet<Leaf>): string => {
  return ms.values().map(leafToString).join(',');
};

const mergeMapToString: (mm: MergeMap<Op, Tree>) => string = (mm: MergeMap<Op, Tree>): string => {
  return mm
    .entries()
    .map(([op, subTree]: [Op, Tree]) => {
      return opToString(op) + '=>{' + treeToString(subTree) + '}';
    })
    .join(',');
};

const treeToString: (tree: Tree) => string = (tree: Tree): string => {
  return '[' + mergeSetToString(tree.leaves) + '](' + mergeMapToString(tree.edges) + ')';
};

describe('Utils', () => {
  describe('callOp()', () => {
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
    ])('$name', ({ op, expected }: { op: Op; expected: string }) => {
      expect(uint8ArrayToHex(callOp(op, Uint8Array.of(1, 2, 3, 4, 5, 6)))).toStrictEqual(expected);
    });
  });

  describe('callOps()', () => {
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
    ])('$name', ({ ops, expected }: { ops: Ops; expected: string }) => {
      expect(uint8ArrayToHex(callOps(ops, Uint8Array.of(1, 2, 3, 4, 5, 6)))).toStrictEqual(expected);
    });
  });

  describe('incorporateTreeToTree()', () => {
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
          leaves: newLeaves().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: newEdges(),
        },
        expected: {
          leaves: newLeaves().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: newEdges(),
        },
        name: 'should incorporate leaves into empty tree',
      },
      {
        left: {
          leaves: newLeaves().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: newEdges(),
        },
        right: newTree(),
        expected: {
          leaves: newLeaves().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: newEdges(),
        },
        name: 'should incorporate empty tree into leaves',
      },
      {
        left: newTree(),
        right: { leaves: newLeaves(), edges: newEdges().add({ type: 'sha1' }, newTree()) },
        expected: { leaves: newLeaves(), edges: newEdges().add({ type: 'sha1' }, newTree()) },
        name: 'should incorporate edges into empty tree',
      },
      {
        left: { leaves: newLeaves(), edges: newEdges().add({ type: 'sha1' }, newTree()) },
        right: newTree(),
        expected: { leaves: newLeaves(), edges: newEdges().add({ type: 'sha1' }, newTree()) },
        name: 'should incorporate empty tree into edges',
      },
      {
        left: { leaves: newLeaves(), edges: newEdges().add({ type: 'sha1' }, newTree()) },
        right: {
          leaves: newLeaves().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: newEdges(),
        },
        expected: {
          leaves: newLeaves().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: newEdges().add({ type: 'sha1' }, newTree()),
        },
        name: 'should incorporate leaves into edges',
      },
      {
        left: {
          leaves: newLeaves().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: newEdges(),
        },
        right: { leaves: newLeaves(), edges: newEdges().add({ type: 'sha1' }, newTree()) },
        expected: {
          leaves: newLeaves().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: newEdges().add({ type: 'sha1' }, newTree()),
        },
        name: 'should incorporate edges into leaves',
      },
    ])('$name', ({ left, right, expected }: { left: Tree; right: Tree; expected: Tree }) => {
      expect(treeToString(incorporateTreeToTree(left, right))).toStrictEqual(treeToString(expected));
    });
  });

  describe('incorporateToTree()', () => {
    it.each([
      {
        left: newTree(),
        right: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() } as Leaf,
        expected: {
          leaves: newLeaves().add({
            type: 'unknown',
            header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
            payload: Uint8Array.of(),
          }),
          edges: newEdges(),
        },
        name: 'should incorporate leaves into empty tree',
      },
      {
        left: newTree(),
        right: [{ type: 'sha1' }, newTree()] as Edge,
        expected: { leaves: newLeaves(), edges: newEdges().add({ type: 'sha1' }, newTree()) },
        name: 'should incorporate edges into empty tree',
      },
    ])('$name', ({ left, right, expected }: { left: Tree; right: Edge | Leaf; expected: Tree }) => {
      expect(treeToString(incorporateToTree(left, right))).toStrictEqual(treeToString(expected));
    });
  });

  describe('newEdges()', () => {
    it.each([
      {
        edges: [] as Edge[],
        expected: newEdges(),
        name: 'should build empty edges',
      },
      {
        edges: [[{ type: 'sha1' }, newTree()]] as Edge[],
        expected: newEdges().add({ type: 'sha1' }, newTree()),
        name: 'should add simple operation',
      },
      {
        edges: [
          [{ type: 'sha1' }, newTree()],
          [{ type: 'sha256' }, newTree()],
        ] as Edge[],
        expected: newEdges().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
        name: 'should add two operations',
      },
      {
        edges: [
          [{ type: 'sha1' }, newTree()],
          [{ type: 'sha1' }, newTree()],
        ] as Edge[],
        expected: newEdges().add({ type: 'sha1' }, newTree()),
        name: 'should add the same operation twice',
      },
      {
        edges: [
          [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()],
          [{ type: 'append', operand: Uint8Array.of(4, 5, 6) }, newTree()],
        ] as Edge[],
        expected: newEdges()
          .add({ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree())
          .add({ type: 'append', operand: Uint8Array.of(4, 5, 6) }, newTree()),
        name: 'should discriminate by operand',
      },
      {
        edges: [
          [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()],
          [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()],
        ] as Edge[],
        expected: newEdges().add({ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()),
        name: 'should not discriminate by same operand',
      },
    ])('$name', ({ edges, expected }: { edges: Edge[]; expected: MergeMap<Op, Tree> }) => {
      expect(
        mergeMapToString(
          edges.reduce((prev: MergeMap<Op, Tree>, edge: Edge): MergeMap<Op, Tree> => prev.add(...edge), newEdges()),
        ),
      ).toStrictEqual(mergeMapToString(expected));
    });
  });

  describe('newLeaves()', () => {
    it.each([
      {
        leaves: [] as Leaf[],
        expected: newLeaves(),
        name: 'should build empty leaves',
      },
      {
        leaves: [{ type: 'bitcoin', height: 123 }] as Leaf[],
        expected: newLeaves().add({ type: 'bitcoin', height: 123 }),
        name: 'should add simple leaf',
      },
      {
        leaves: [
          { type: 'bitcoin', height: 123 },
          { type: 'litecoin', height: 456 },
        ] as Leaf[],
        expected: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 456 }),
        name: 'should add two leaves',
      },
      {
        leaves: [
          { type: 'bitcoin', height: 123 },
          { type: 'bitcoin', height: 123 },
        ] as Leaf[],
        expected: newLeaves().add({ type: 'bitcoin', height: 123 }),
        name: 'should add the same leaf twice',
      },
      {
        leaves: [
          { type: 'pending', url: new URL('http://www.example.com/a') },
          { type: 'pending', url: new URL('http://www.example.com/b') },
        ] as Leaf[],
        expected: newLeaves()
          .add({ type: 'pending', url: new URL('http://www.example.com/a') })
          .add({ type: 'pending', url: new URL('http://www.example.com/b') }),
        name: 'should discriminate by pending URL',
      },
      {
        leaves: [
          { type: 'pending', url: new URL('http://www.example.com/a') },
          { type: 'pending', url: new URL('http://www.example.com/a') },
        ] as Leaf[],
        expected: newLeaves().add({ type: 'pending', url: new URL('http://www.example.com/a') }),
        name: 'should not discriminate by same pending URL',
      },
      {
        leaves: [
          { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() },
          { type: 'unknown', header: Uint8Array.of(2, 3, 4, 5, 6, 7, 8, 9), payload: Uint8Array.of() },
        ] as Leaf[],
        expected: newLeaves()
          .add({ type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() })
          .add({ type: 'unknown', header: Uint8Array.of(2, 3, 4, 5, 6, 7, 8, 9), payload: Uint8Array.of() }),
        name: 'should discriminate by unknown header',
      },
      {
        leaves: [
          { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() },
          { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() },
        ] as Leaf[],
        expected: newLeaves().add({
          type: 'unknown',
          header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
          payload: Uint8Array.of(),
        }),
        name: 'should not discriminate by same unknown header',
      },
      {
        leaves: [
          { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(1, 2, 3) },
          { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(4, 5, 6) },
        ] as Leaf[],
        expected: newLeaves()
          .add({ type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(1, 2, 3) })
          .add({ type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(4, 5, 6) }),
        name: 'should discriminate by unknown payload',
      },
      {
        leaves: [
          { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(1, 2, 3) },
          { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(1, 2, 3) },
        ] as Leaf[],
        expected: newLeaves().add({
          type: 'unknown',
          header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
          payload: Uint8Array.of(1, 2, 3),
        }),
        name: 'should not discriminate by same unknown payload',
      },
      {
        leaves: [
          { type: 'bitcoin', height: 123 },
          { type: 'bitcoin', height: 456 },
        ] as Leaf[],
        expected: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 456 }),
        name: 'should discriminate by bitcoin height',
      },
      {
        leaves: [
          { type: 'bitcoin', height: 123 },
          { type: 'bitcoin', height: 123 },
        ] as Leaf[],
        expected: newLeaves().add({ type: 'bitcoin', height: 123 }),
        name: 'should not discriminate by same bitcoin height',
      },
      {
        leaves: [
          { type: 'litecoin', height: 123 },
          { type: 'litecoin', height: 456 },
        ] as Leaf[],
        expected: newLeaves().add({ type: 'litecoin', height: 123 }).add({ type: 'litecoin', height: 456 }),
        name: 'should discriminate by litecoin height',
      },
      {
        leaves: [
          { type: 'litecoin', height: 123 },
          { type: 'litecoin', height: 123 },
        ] as Leaf[],
        expected: newLeaves().add({ type: 'litecoin', height: 123 }),
        name: 'should not discriminate by same litecoin height',
      },
      {
        leaves: [
          { type: 'ethereum', height: 123 },
          { type: 'ethereum', height: 456 },
        ] as Leaf[],
        expected: newLeaves().add({ type: 'ethereum', height: 123 }).add({ type: 'ethereum', height: 456 }),
        name: 'should discriminate by ethereum height',
      },
      {
        leaves: [
          { type: 'ethereum', height: 123 },
          { type: 'ethereum', height: 123 },
        ] as Leaf[],
        expected: newLeaves().add({ type: 'ethereum', height: 123 }),
        name: 'should not discriminate by same ethereum height',
      },
    ])('$name', ({ leaves, expected }: { leaves: Leaf[]; expected: MergeSet<Leaf> }) => {
      expect(
        mergeSetToString(
          leaves.reduce((prev: MergeSet<Leaf>, leaf: Leaf): MergeSet<Leaf> => prev.add(leaf), newLeaves()),
        ),
      ).toStrictEqual(mergeSetToString(expected));
    });
  });

  describe('newTree()', () => {
    test('should build empty tree', () => {
      expect(treeToString(newTree())).toStrictEqual('[]()');
    });
  });
});
