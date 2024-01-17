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

import type { Edge, Leaf, Op, Timestamp, Tree } from '../src/types';

import {
  edgeToString,
  leafOrEdgeToString,
  leafToString,
  mergeMapToString,
  mergeSetToString,
  opToString,
  timestampToString,
  treeToString,
} from './helpers';
import { newEdges, newLeaves, newTree } from '../src/internals';
import { MergeMap, MergeSet, uint8ArrayFromHex } from '../src/utils';

describe('Helpers', () => {
  describe('opToString()', () => {
    it.each([
      {
        input: { type: 'sha1' } as Op,
        expected: 'sha1',
        name: 'should stringify sha1',
      },
      {
        input: { type: 'ripemd160' } as Op,
        expected: 'ripemd160',
        name: 'should stringify ripemd160',
      },
      {
        input: { type: 'sha256' } as Op,
        expected: 'sha256',
        name: 'should stringify sha256',
      },
      {
        input: { type: 'keccak256' } as Op,
        expected: 'keccak256',
        name: 'should stringify keccak256',
      },
      {
        input: { type: 'reverse' } as Op,
        expected: 'reverse',
        name: 'should stringify reverse',
      },
      {
        input: { type: 'hexlify' } as Op,
        expected: 'hexlify',
        name: 'should stringify hexlify',
      },
      {
        input: { type: 'append', operand: Uint8Array.of(1, 2, 3) } as Op,
        expected: 'append:010203',
        name: 'should stringify append',
      },
      {
        input: { type: 'prepend', operand: Uint8Array.of(1, 2, 3) } as Op,
        expected: 'prepend:010203',
        name: 'should stringify prepend',
      },
    ])('$name', ({ input, expected }: { input: Op; expected: string }) => {
      expect(opToString(input)).toStrictEqual(expected);
    });
  });

  describe('edgeToString()', () => {
    it.each([
      {
        input: [{ type: 'sha1' }, newTree()] as Edge,
        expected: 'sha1=>{[]()}',
        name: 'should stringify sha1 edge',
      },
      {
        input: [{ type: 'ripemd160' }, newTree()] as Edge,
        expected: 'ripemd160=>{[]()}',
        name: 'should stringify ripemd160 edge',
      },
      {
        input: [{ type: 'sha256' }, newTree()] as Edge,
        expected: 'sha256=>{[]()}',
        name: 'should stringify sha256 edge',
      },
      {
        input: [{ type: 'keccak256' }, newTree()] as Edge,
        expected: 'keccak256=>{[]()}',
        name: 'should stringify keccak256 edge',
      },
      {
        input: [{ type: 'reverse' }, newTree()] as Edge,
        expected: 'reverse=>{[]()}',
        name: 'should stringify reverse edge',
      },
      {
        input: [{ type: 'hexlify' }, newTree()] as Edge,
        expected: 'hexlify=>{[]()}',
        name: 'should stringify hexlify edge',
      },
      {
        input: [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        expected: 'append:010203=>{[]()}',
        name: 'should stringify append edge',
      },
      {
        input: [{ type: 'prepend', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        expected: 'prepend:010203=>{[]()}',
        name: 'should stringify prepend edge',
      },
    ])('$name', ({ input, expected }: { input: Edge; expected: string }) => {
      expect(edgeToString(input)).toStrictEqual(expected);
    });
  });

  describe('leafToString()', () => {
    it.each([
      {
        input: { type: 'pending', url: new URL('https://www.example.com') } as Leaf,
        expected: 'pending:https://www.example.com/',
        name: 'should stringify pending leaf',
      },
      {
        input: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(9, 0) } as Leaf,
        expected: 'unknown:0102030405060708:0900',
        name: 'should stringify unknown leaf',
      },
      {
        input: { type: 'bitcoin', height: 123 } as Leaf,
        expected: 'bitcoin:123',
        name: 'should stringify bitcoin leaf',
      },
      {
        input: { type: 'litecoin', height: 123 } as Leaf,
        expected: 'litecoin:123',
        name: 'should stringify litecoin leaf',
      },
      {
        input: { type: 'ethereum', height: 123 } as Leaf,
        expected: 'ethereum:123',
        name: 'should stringify ethereum leaf',
      },
    ])('$name', ({ input, expected }: { input: Leaf; expected: string }) => {
      expect(leafToString(input)).toStrictEqual(expected);
    });
  });

  describe('leafOrEdgeToString()', () => {
    it.each([
      {
        input: [{ type: 'sha1' }, newTree()] as Edge,
        expected: 'sha1=>{[]()}',
        name: 'should stringify sha1 edge',
      },
      {
        input: [{ type: 'ripemd160' }, newTree()] as Edge,
        expected: 'ripemd160=>{[]()}',
        name: 'should stringify ripemd160 edge',
      },
      {
        input: [{ type: 'sha256' }, newTree()] as Edge,
        expected: 'sha256=>{[]()}',
        name: 'should stringify sha256 edge',
      },
      {
        input: [{ type: 'keccak256' }, newTree()] as Edge,
        expected: 'keccak256=>{[]()}',
        name: 'should stringify keccak256 edge',
      },
      {
        input: [{ type: 'reverse' }, newTree()] as Edge,
        expected: 'reverse=>{[]()}',
        name: 'should stringify reverse edge',
      },
      {
        input: [{ type: 'hexlify' }, newTree()] as Edge,
        expected: 'hexlify=>{[]()}',
        name: 'should stringify hexlify edge',
      },
      {
        input: [{ type: 'append', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        expected: 'append:010203=>{[]()}',
        name: 'should stringify append edge',
      },
      {
        input: [{ type: 'prepend', operand: Uint8Array.of(1, 2, 3) }, newTree()] as Edge,
        expected: 'prepend:010203=>{[]()}',
        name: 'should stringify prepend edge',
      },
      {
        input: { type: 'pending', url: new URL('https://www.example.com') } as Leaf,
        expected: 'pending:https://www.example.com/',
        name: 'should stringify pending leaf',
      },
      {
        input: { type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of(9, 0) } as Leaf,
        expected: 'unknown:0102030405060708:0900',
        name: 'should stringify unknown leaf',
      },
      {
        input: { type: 'bitcoin', height: 123 } as Leaf,
        expected: 'bitcoin:123',
        name: 'should stringify bitcoin leaf',
      },
      {
        input: { type: 'litecoin', height: 123 } as Leaf,
        expected: 'litecoin:123',
        name: 'should stringify litecoin leaf',
      },
      {
        input: { type: 'ethereum', height: 123 } as Leaf,
        expected: 'ethereum:123',
        name: 'should stringify ethereum leaf',
      },
    ])('$name', ({ input, expected }: { input: Leaf | Edge; expected: string }) => {
      expect(leafOrEdgeToString(input)).toStrictEqual(expected);
    });
  });

  describe('mergeSetToString()', () => {
    it.each([
      {
        input: newLeaves(),
        expected: '',
        name: 'should stringify empty MergeSet',
      },
      {
        input: newLeaves().add({ type: 'bitcoin', height: 123 }),
        expected: 'bitcoin:123',
        name: 'should stringify singleton MergeSet',
      },
      {
        input: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 456 }),
        expected: 'bitcoin:123,bitcoin:456',
        name: 'should stringify non-empty MergeSet',
      },
    ])('$name', ({ input, expected }: { input: MergeSet<Leaf>; expected: string }) => {
      expect(mergeSetToString(input)).toStrictEqual(expected);
    });
  });

  describe('mergeMapToString()', () => {
    it.each([
      {
        input: newEdges(),
        expected: '',
        name: 'should stringify empty MergeMap',
      },
      {
        input: newEdges().add({ type: 'sha1' }, newTree()),
        expected: 'sha1=>{[]()}',
        name: 'should stringify singleton MergeMap',
      },
      {
        input: newEdges().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
        expected: 'sha1=>{[]()},sha256=>{[]()}',
        name: 'should stringify singleton MergeMap',
      },
    ])('$name', ({ input, expected }: { input: MergeMap<Op, Tree>; expected: string }) => {
      expect(mergeMapToString(input)).toStrictEqual(expected);
    });
  });

  describe('treeToString()', () => {
    it.each([
      {
        input: newTree(),
        expected: '[]()',
        name: 'should stringify empty tree',
      },
      {
        input: { edges: newEdges(), leaves: newLeaves().add({ type: 'bitcoin', height: 123 }) },
        expected: '[bitcoin:123]()',
        name: 'should stringify tree with one leaf',
      },
      {
        input: {
          edges: newEdges(),
          leaves: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 456 }),
        },
        expected: '[bitcoin:123,bitcoin:456]()',
        name: 'should stringify tree with two leaves',
      },
      {
        input: { edges: newEdges().add({ type: 'sha1' }, newTree()), leaves: newLeaves() },
        expected: '[](sha1=>{[]()})',
        name: 'should stringify tree with one edge',
      },
      {
        input: {
          edges: newEdges().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
          leaves: newLeaves(),
        },
        expected: '[](sha1=>{[]()},sha256=>{[]()})',
        name: 'should stringify tree with two edges',
      },
      {
        input: {
          edges: newEdges().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
          leaves: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 456 }),
        },
        expected: '[bitcoin:123,bitcoin:456](sha1=>{[]()},sha256=>{[]()})',
        name: 'should stringify tree with two leaves and two edges',
      },
    ])('$name', ({ input, expected }: { input: Tree; expected: string }) => {
      expect(treeToString(input)).toStrictEqual(expected);
    });
  });

  describe('timestampToString()', () => {
    it.each([
      {
        input: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('0011223344556677889900aabbccddeeff112233') },
          tree: newTree(),
        } as Timestamp,
        expected: '<1:sha1:0011223344556677889900aabbccddeeff112233:[]()>',
        name: 'should stringify empty timestamp',
      },
      {
        input: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('0011223344556677889900aabbccddeeff112233') },
          tree: {
            edges: newEdges().add({ type: 'sha1' }, newTree()).add({ type: 'sha256' }, newTree()),
            leaves: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 456 }),
          },
        } as Timestamp,
        expected:
          '<1:sha1:0011223344556677889900aabbccddeeff112233:[bitcoin:123,bitcoin:456](sha1=>{[]()},sha256=>{[]()})>',
        name: 'should stringify non-empty timestamp',
      },
    ])('$name', ({ input, expected }: { input: Timestamp; expected: string }) => {
      expect(timestampToString(input)).toStrictEqual(expected);
    });
  });
});
