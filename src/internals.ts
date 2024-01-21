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

import type { Edge, Leaf, Op, Ops, Path, Paths, Timestamp, Tree } from './types';

import { LeafHeader, Tag } from './types';
import {
  MergeMap,
  MergeSet,
  textEncoder,
  uint8ArrayCompare,
  uint8ArrayConcat,
  uint8ArrayFromHex,
  uint8ArrayReversed,
  uint8ArrayToHex,
} from './utils';

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
      return uint8ArrayReversed(msg);
    case 'hexlify':
      return textEncoder.encode(uint8ArrayToHex(msg));
  }
}

export function callOps(ops: Ops, msg: Uint8Array): Uint8Array {
  return ops.reduce((prevMsg: Uint8Array, op: Op): Uint8Array => callOp(op, prevMsg), msg);
}

export function compareLeaves(left: Leaf, right: Leaf): number {
  const headerCompare: number = uint8ArrayCompare(
    'unknown' == left.type ? left.header : uint8ArrayFromHex(LeafHeader[left.type as keyof typeof LeafHeader]),
    'unknown' == right.type ? right.header : uint8ArrayFromHex(LeafHeader[right.type as keyof typeof LeafHeader]),
  );
  if (0 === headerCompare) {
    switch (left.type) {
      case 'pending':
        return uint8ArrayCompare(
          textEncoder.encode(left.url.toString()),
          textEncoder.encode((right as { url: URL }).url.toString()),
        );
      case 'unknown':
        return uint8ArrayCompare(left.payload, (right as { payload: Uint8Array }).payload);
      default:
        return left.height - (right as { height: number }).height;
    }
  }
  return headerCompare;
}

export function compareOps(left: Op, right: Op): number {
  const tagCompare: number = Tag[left.type] - Tag[right.type];
  if (0 === tagCompare && ('append' === left.type || 'prepend' === left.type)) {
    return uint8ArrayCompare(left.operand, (right as { operand: Uint8Array }).operand);
  }
  return tagCompare;
}

export function compareEdges(left: Edge, right: Edge): number {
  const [[leftOp], [rightOp]]: [Edge, Edge] = [left, right];
  return compareOps(leftOp, rightOp);
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

export function decoalesceOperations(tree: Tree): Tree {
  tree.edges.values().forEach((subTree: Tree): Tree => decoalesceOperations(subTree));
  if (1 === tree.edges.size()) {
    const [op, subTree]: Edge = tree.edges.entries()[0]!;
    if (0 === subTree.leaves.size() && 2 === subTree.edges.size()) {
      if (
        'prepend' === op.type &&
        1 === op.operand.length &&
        'prepend:prepend' ===
          subTree.edges
            .keys()
            .map((subOp: Op): string => subOp.type)
            .join(':')
      ) {
        const [[subOp1, subSubTree1], [subOp2, subSubTree2]]: [Edge, Edge] = subTree.edges.entries() as [Edge, Edge];
        tree.edges
          .remove(op)
          .add(
            { type: 'prepend', operand: uint8ArrayConcat((subOp1 as { operand: Uint8Array }).operand, op.operand) },
            subSubTree1,
          )
          .add(
            { type: 'prepend', operand: uint8ArrayConcat((subOp2 as { operand: Uint8Array }).operand, op.operand) },
            subSubTree2,
          );
      } else if (
        'append' === op.type &&
        1 === op.operand.length &&
        'append:append' ===
          subTree.edges
            .keys()
            .map((subOp: Op): string => subOp.type)
            .join(':')
      ) {
        const [[subOp1, subSubTree1], [subOp2, subSubTree2]]: [Edge, Edge] = subTree.edges.entries() as [Edge, Edge];
        tree.edges
          .remove(op)
          .add(
            { type: 'append', operand: uint8ArrayConcat(op.operand, (subOp1 as { operand: Uint8Array }).operand) },
            subSubTree1,
          )
          .add(
            { type: 'append', operand: uint8ArrayConcat(op.operand, (subOp2 as { operand: Uint8Array }).operand) },
            subSubTree2,
          );
      }
    }
  }
  return tree;
}

export function coalesceOperations(tree: Tree): Tree {
  tree.edges.values().forEach(coalesceOperations);
  if (0 !== tree.leaves.size()) {
    return tree;
  }
  tree.edges.entries().forEach(([op, subTree]: Edge): void => {
    if (0 === subTree.leaves.size() && 1 === subTree.edges.size()) {
      const [subOp, subSubTree]: Edge = subTree.edges.entries()[0]!;
      if ('prepend' === op.type && 'prepend' === subOp.type) {
        tree.edges
          .remove(op)
          .add({ type: 'prepend', operand: uint8ArrayConcat(subOp.operand, op.operand) }, subSubTree);
      } else if ('append' === op.type && 'append' === subOp.type) {
        tree.edges.remove(op).add({ type: 'append', operand: uint8ArrayConcat(op.operand, subOp.operand) }, subSubTree);
      }
    }
  });
  return tree;
}

export function atomizePrependOp(prefix: Uint8Array): Ops {
  const ops: Ops = [];
  uint8ArrayReversed(prefix).forEach((value: number): void => {
    ops.push({ type: 'prepend', operand: Uint8Array.of(value) });
  });
  return ops;
}

export function atomizeAppendOp(suffix: Uint8Array): Ops {
  const ops: Ops = [];
  suffix.forEach((value: number): void => {
    ops.push({ type: 'append', operand: Uint8Array.of(value) });
  });
  return ops;
}

export function normalizeOps(operations: Ops): Ops {
  let prefix: Uint8Array = Uint8Array.of();
  let suffix: Uint8Array = Uint8Array.of();
  let reverse: boolean = false;
  let ops: Ops = [];
  for (let i: number = 0; i < operations.length; i++) {
    const thisOp: Op = operations[i]!;
    switch (thisOp.type) {
      case 'reverse':
        [prefix, reverse, suffix] = [uint8ArrayReversed(suffix), !reverse, uint8ArrayReversed(prefix)];
        break;
      case 'append':
        // append(reverse(x), s) --> reverse(prepend(x, reverse(s)))
        if (reverse) {
          prefix = uint8ArrayConcat(uint8ArrayReversed(thisOp.operand), prefix);
        } else {
          suffix = uint8ArrayConcat(suffix, thisOp.operand);
        }
        break;
      case 'prepend':
        // prepend(reverse(x), s) --> reverse(append(x, reverse(s)))
        if (reverse) {
          suffix = uint8ArrayConcat(suffix, uint8ArrayReversed(thisOp.operand));
        } else {
          prefix = uint8ArrayConcat(thisOp.operand, prefix);
        }
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

export function pathsToTree(paths: Paths): Tree {
  return paths
    .map((path: Path): Tree => {
      return path.operations.reduceRight(
        (tree: Tree, op: Op): Tree => {
          const result: Tree = newTree();
          result.edges.add(op, tree);
          return result;
        },
        { leaves: newLeaves().add(path.leaf), edges: newEdges() },
      );
    })
    .reduce(incorporateTreeToTree, newTree());
}

export function treeToPaths(tree: Tree, path: Ops = []): Paths {
  const result: Paths = [];
  tree.leaves.values().forEach((leaf: Leaf): void => {
    result.push({ operations: path, leaf });
  });
  tree.edges.entries().forEach(([op, subTree]: Edge): void => {
    treeToPaths(subTree, path.concat([op])).forEach((leafPath: Path): void => {
      result.push(leafPath);
    });
  });
  return result;
}

export function normalizeTimestamp(timestamp: Timestamp): Timestamp | undefined {
  const tree: Tree = decoalesceOperations(
    coalesceOperations(
      pathsToTree(
        treeToPaths(timestamp.tree).map((path: Path): { operations: Ops; leaf: Leaf } => {
          return { operations: normalizeOps(path.operations), leaf: path.leaf };
        }),
      ),
    ),
  );

  return 0 === tree.leaves.size() + tree.edges.size()
    ? undefined
    : {
        fileHash: timestamp.fileHash,
        version: timestamp.version,
        tree,
      };
}
