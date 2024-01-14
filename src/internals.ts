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

import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha1 } from '@noble/hashes/sha1';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';

import { Edge, Leaf, Op, Tree } from './types';
import { MergeMap, MergeSet, uint8ArrayConcat, uint8ArrayToHex } from './utils';

export function callOp(op: Op, msg: Uint8Array): Uint8Array {
  switch (op.type) {
    case 'sha1':
      return sha1(msg);
    case 'ripemd160':
      return ripemd160(msg);
    case 'sha256':
      return sha256(msg);
    case 'keccak256':
      return keccak_256(msg);
    case 'append':
      return Uint8Array.of(...msg, ...op.operand);
    case 'prepend':
      return Uint8Array.of(...op.operand, ...msg);
    case 'reverse':
      return msg.toReversed();
    case 'hexlify':
      return new TextEncoder().encode(uint8ArrayToHex(msg));
  }
}

export function incorporateTreeToTree(left: Tree, right: Tree): Tree {
  left.leaves.incorporate(right.leaves);
  left.edges.incorporate(right.edges);
  return left;
}

export function incorporateToTree(tree: Tree, edgeOrLeaf: Edge | Leaf): Tree {
  if (Array.isArray(edgeOrLeaf)) {
    tree.edges.add(...edgeOrLeaf);
  } else {
    tree.leaves.add(edgeOrLeaf);
  }
  return tree;
}

export function newEdges(): MergeMap<Op, Tree> {
  return new MergeMap<Op, Tree>(
    (op: Op): string => {
      switch (op.type) {
        case 'append':
        case 'prepend':
          return `${op.type}:${uint8ArrayToHex(op.operand)}`;
        default:
          return op.type;
      }
    },
    (left: Tree, right: Tree): Tree => incorporateTreeToTree(left, right),
  );
}

export function newLeaves(): MergeSet<Leaf> {
  return new MergeSet<Leaf>(
    (leaf: Leaf): string => {
      switch (leaf.type) {
        case 'pending':
          return `${leaf.type}:${leaf.url.toString()}`;
        case 'unknown':
          return `${leaf.type}:${uint8ArrayToHex(leaf.header)}:${uint8ArrayToHex(leaf.payload)}`;
        default:
          return `${leaf.type}:${leaf.height}`;
      }
    },
    (left: Leaf, _right: Leaf): Leaf => {
      return left;
    },
  );
}

export function newTree(): Tree {
  return { edges: newEdges(), leaves: newLeaves() };
}

export function normalizeTimestamp(tree: Tree): Tree | undefined {
  tree.edges.entries().forEach(([op, subTree]: [Op, Tree]) => {
    tree.edges.remove(op);
    const nSubTree: Tree | undefined = normalizeTimestamp(subTree);
    if (undefined === nSubTree) {
      return;
    }
    if (0 === nSubTree.leaves.size() && 1 === nSubTree.edges.size()) {
      const [subOp, nSubSubTree]: [Op, Tree] = nSubTree.edges.entries()[0]!;
      switch (`${op.type}:${subOp.type}`) {
        case 'reverse:reverse':
          // reverse(reverse(x)) -> x
          tree.leaves.incorporate(nSubSubTree.leaves);
          tree.edges.incorporate(nSubSubTree.edges);
          break;
        case 'append:append':
          // append(append(x, t), s) -> append(x, ts))
          tree.edges.add(
            {
              type: 'append',
              operand: uint8ArrayConcat([
                (op as { operand: Uint8Array }).operand,
                (subOp as { operand: Uint8Array }).operand,
              ]),
            },
            nSubSubTree,
          );
          break;
        case 'prepend:prepend':
          // prepend(prepend(x, t), s) -> prepend(x, st)
          tree.edges.add(
            {
              type: 'prepend',
              operand: uint8ArrayConcat([
                (subOp as { operand: Uint8Array }).operand,
                (op as { operand: Uint8Array }).operand,
              ]),
            },
            nSubSubTree,
          );
          break;
        case 'reverse:append':
          // append(reverse(x), s) -> reverse(prepend(x, reverse(s)))
          tree.edges.add(
            {
              type: 'prepend',
              operand: (subOp as { operand: Uint8Array }).operand.toReversed(),
            },
            {
              leaves: newLeaves(),
              edges: newEdges().add({ type: 'reverse' }, nSubSubTree),
            },
          );
          break;
        case 'reverse:prepend':
          // prepend(reverse(x), s) -> reverse(append(x, reverse(s)))
          tree.edges.add(
            {
              type: 'append',
              operand: (subOp as { operand: Uint8Array }).operand.toReversed(),
            },
            {
              leaves: newLeaves(),
              edges: newEdges().add({ type: 'reverse' }, nSubSubTree),
            },
          );
          break;
        case 'prepend:append':
          // append(prepend(x, t), s) -> prepend(append(x, s), t)
          tree.edges.add(
            {
              type: 'append',
              operand: (subOp as { operand: Uint8Array }).operand,
            },
            {
              leaves: newLeaves(),
              edges: newEdges().add(
                {
                  type: 'prepend',
                  operand: (op as { operand: Uint8Array }).operand,
                },
                nSubSubTree,
              ),
            },
          );
          break;
        default:
          tree.edges.add(op, nSubTree);
      }
    } else {
      tree.edges.add(op, nSubTree);
    }
  });
  return 0 !== tree.leaves.size() + tree.edges.size() ? tree : undefined;
}
