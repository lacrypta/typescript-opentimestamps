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

import type { Edge, Leaf, Op, Timestamp, Tree } from './types';

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

export function coalesceOperations(tree: Tree): Tree {
  tree.edges.values().forEach(coalesceOperations);
  if (0 !== tree.leaves.size()) {
    return tree;
  }
  tree.edges.entries().forEach(([op, subTree]: [Op, Tree]): void => {
    if (0 === subTree.leaves.size() && 1 === subTree.edges.size()) {
      const [subOp, subSubTree]: [Op, Tree] = subTree.edges.entries()[0]!;
      if ('prepend' === op.type && 'prepend' === subOp.type) {
        tree.edges
          .remove(op)
          .add({ type: 'prepend', operand: uint8ArrayConcat([subOp.operand, op.operand]) }, subSubTree);
      } else if ('append' === op.type && 'append' === subOp.type) {
        tree.edges
          .remove(op)
          .add({ type: 'append', operand: uint8ArrayConcat([op.operand, subOp.operand]) }, subSubTree);
      }
    }
  });
  return tree;
}

export function leafPathToTree(leafPath: { operations: Op[]; leaf: Leaf }): Tree {
  let tree: Tree = { leaves: newLeaves().add(leafPath.leaf), edges: newEdges() };
  for (let i = leafPath.operations.length; 0 < i; i--) {
    const thisOp: Op = leafPath.operations[i - 1]!;
    tree = { leaves: newLeaves(), edges: newEdges().add(thisOp, tree) };
  }
  return tree;
}

export function atomizePrependOp(prefix: Uint8Array): Op[] {
  const ops: Op[] = [];
  prefix.toReversed().forEach((value: number): void => {
    ops.push({ type: 'prepend', operand: Uint8Array.of(value) });
  });
  return ops;
}

export function atomizeAppendOp(suffix: Uint8Array): Op[] {
  const ops: Op[] = [];
  suffix.forEach((value: number): void => {
    ops.push({ type: 'append', operand: Uint8Array.of(value) });
  });
  return ops;
}

export function normalizeOps(operations: Op[]): Op[] {
  let prefix: Uint8Array = Uint8Array.of();
  let suffix: Uint8Array = Uint8Array.of();
  let reverse: boolean = false;
  let ops: Op[] = [];
  for (let i: number = 0; i < operations.length; i++) {
    const thisOp: Op = operations[i]!;
    switch (thisOp.type) {
      case 'reverse':
        [prefix, reverse, suffix] = [suffix.toReversed(), !reverse, prefix.toReversed()];
        break;
      case 'append':
        suffix = uint8ArrayConcat([suffix, thisOp.operand]);
        break;
      case 'prepend':
        prefix = uint8ArrayConcat([thisOp.operand, prefix]);
        break;
      default:
        if (0 !== prefix.length) {
          ops = ops.concat(atomizePrependOp(prefix));
          prefix = Uint8Array.of();
        }
        if (0 !== suffix.length) {
          ops = ops.concat(atomizeAppendOp(suffix));
          suffix = Uint8Array.of();
        }
        if (reverse) {
          ops.push({ type: 'reverse' });
          reverse = false;
        }
        ops.push(thisOp);
    }
  }
  if (0 !== prefix.length) {
    ops = ops.concat(atomizePrependOp(prefix));
  }
  if (0 !== suffix.length) {
    ops = ops.concat(atomizeAppendOp(suffix));
  }
  if (reverse) {
    ops.push({ type: 'reverse' });
  }
  return ops;
}

export function leafPathsFromTree(tree: Tree, path: Op[]): { operations: Op[]; leaf: Leaf }[] {
  const result: { operations: Op[]; leaf: Leaf }[] = [];
  tree.leaves.values().forEach((leaf: Leaf): void => {
    result.push({ operations: path, leaf });
  });
  tree.edges.entries().forEach(([op, subTree]: [Op, Tree]): void => {
    leafPathsFromTree(subTree, path.concat([op])).forEach((leafPath: { operations: Op[]; leaf: Leaf }): void => {
      result.push(leafPath);
    });
  });
  return result;
}

export function normalizeTimestamp(timestamp: Timestamp): Timestamp | undefined {
  const tree: Tree = coalesceOperations(
    leafPathsFromTree(timestamp.tree, [])
      .map((leafPath: { operations: Op[]; leaf: Leaf }) => {
        return { operations: normalizeOps(leafPath.operations), leaf: leafPath.leaf };
      })
      .map(leafPathToTree)
      .reduce(incorporateTreeToTree, newTree()),
  );

  return 0 === tree.leaves.size() + tree.edges.size()
    ? undefined
    : {
        fileHash: timestamp.fileHash,
        version: timestamp.version,
        tree,
      };
}
