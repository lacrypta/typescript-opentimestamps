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

/**
 * This module defines all basic types and constants used.
 *
 * @packageDocumentation
 * @module
 */

'use strict';

import { MergeMap, MergeSet, uint8ArrayFromHex } from './utils';

/**
 * A simple type alias to refer to a list of {@link Op | operations}.
 *
 */
export type Ops = Op[];

/**
 * A "Path" consists of a list of {@link Ops | operations} with a corresponding {@link Leaf}, representing a full path
 * from the message to attest to an attestation proper.
 *
 */
export type Path = {
  /**
   * The {@link Ops} in this {@link Path}.
   *
   */
  operations: Ops;

  /**
   * The {@link Leaf} in this {@link Path}.
   *
   */
  leaf: Leaf;
};

/**
 * A simple type alias to refer to a list of {@link Path}s.
 *
 */
export type Paths = Path[];

/**
 * A simple type alias to refer to a {@link Tree}'s edges.
 *
 */
export type Edge = [Op, Tree];

/**
 * Tags are single-byte values used to indicate the structural components found in an `ots` file.
 *
 */
export enum Tag {
  /**
   * Tag indicating that the next element in the `ots` file is an attestation.
   *
   */
  attestation = 0x00,

  /**
   * Tag indicating that the next element in the `ots` file is a SHA1 {@link Op}.
   *
   */
  sha1 = 0x02,

  /**
   * Tag indicating that the next element in the `ots` file is a RIPEMD160 {@link Op}.
   *
   */
  ripemd160 = 0x03,

  /**
   * Tag indicating that the next element in the `ots` file is a SHA256 {@link Op}.
   *
   */
  sha256 = 0x08,

  /**
   * Tag indicating that the next element in the `ots` file is a KECCAK256 {@link Op}.
   *
   */
  keccak256 = 0x67,

  /**
   * Tag indicating that the next element in the `ots` file is an append {@link Op}.
   *
   */
  append = 0xf0,

  /**
   * Tag indicating that the next element in the `ots` file is a prepend {@link Op}.
   *
   */
  prepend = 0xf1,

  /**
   * Tag indicating that the next element in the `ots` file is a reverse {@link Op}.
   *
   */
  reverse = 0xf2,

  /**
   * Tag indicating that the next element in the `ots` file is a "hexlify" {@link Op}.
   *
   */
  hexlify = 0xf3,
}

/**
 * Headers are used to identify {@link Leaf} types in an `ots` file.
 *
 * Headers are 8-byte sequences, and each {@link Leaf} type has an associated one.
 * Unknown {@link Leaf | leaves} carry their `header` with them.
 *
 */
export enum LeafHeader {
  /**
   * 8-byte header describing a Bitcoin {@link Leaf}.
   *
   * This header consists of bytes `05:88:96:0d:73:d7:19:01`.
   *
   */
  bitcoin = '0588960d73d71901',

  /**
   * 8-byte header describing a Litecoin {@link Leaf}.
   *
   * This header consists of bytes `06:86:9a:0d:73:d7:1b:45`.
   *
   */
  litecoin = '06869a0d73d71b45',

  /**
   * 8-byte header describing an Ethereum {@link Leaf}.
   *
   * This header consists of bytes `30:fe:80:87:b5:c7:ea:d7`.
   *
   */
  ethereum = '30fe8087b5c7ead7',

  /**
   * 8-byte header describing a pending {@link Leaf}.
   *
   * This header consists of bytes `83:df:e3:0d:2e:f9:0c:8e`.
   *
   */
  pending = '83dfe30d2ef90c8e',
}

/**
 * This 31-byte header is used to identify `ots` files, it is simply a magic constant.
 *
 * The header consists of bytes `00:4f:70:65:6e:54:69:6d:65:73:74:61:6d:70:73:00:00:50:72:6f:6f:66:00:bf:89:e2:e8:84:e8:92:94`.
 *
 */
export const magicHeader: Uint8Array = uint8ArrayFromHex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294',
);

/**
 * This constant is used to indicate that the next element in an `ots` file is _not_ the last one.
 *
 */
export const nonFinal: number = 0xff;

// ----------------------------------------------------------------------------------------------------------------------------------------
// -- API ---------------------------------------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------------------------------------------

/**
 * A "Leaf" represents an attestation on a blockchain or a pending attestation on a Calendar.
 *
 * Leaves are realized as tagged unions utilizing the `type` field as discriminator.
 *
 * Unknown attestations are "future-proofing" devices: there's no way of verifying them on the current version of the standard,
 * but are nonetheless supported in case a new blockchain is supported in the future.
 *
 */
export type Leaf =
  | {
      /**
       * The discriminator declaring this to be a Bitcoin attestation leaf.
       *
       */
      type: 'bitcoin';

      /**
       * The block-height at which the Merkle root can be found.
       *
       */
      height: number;
    }
  | {
      /**
       * The discriminator declaring this to be a Litecoin attestation leaf.
       *
       */
      type: 'litecoin';

      /**
       * The block-height at which the Merkle root can be found.
       *
       */
      height: number;
    }
  | {
      /**
       * The discriminator declaring this to be an Ethereum attestation leaf.
       *
       */
      type: 'ethereum';

      /**
       * The block-height at which the Merkle root can be found.
       *
       */
      height: number;
    }
  | {
      /**
       * The discriminator declaring this to be a _pending_ attestation leaf.
       *
       */
      type: 'pending';

      /**
       * The Calendar's {@link !URL} to consult for updates.
       *
       */
      url: URL;
    }
  | {
      /**
       * The discriminator declaring this to be an _unknown_ attestation leaf.
       *
       */
      type: 'unknown';

      /**
       * The 8-byte header identifying this (unknown) leaf type.
       *
       */
      header: Uint8Array;

      /**
       * The unknown leaf's payload.
       *
       */
      payload: Uint8Array;
    };

/**
 * An "Operation" is simply a unary operation to apply to the message being attested (an {@link !Uint8Array}).
 *
 * Operations are realized as tagged unions utilizing the `type` field as discriminator.
 *
 */
export type Op =
  | {
      /**
       * The discriminator declaring this to be a SHA1-hashing operation.
       *
       * Upon executing this operation the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = sha1(oldMsg);
       * ```
       *
       */
      type: 'sha1';
    }
  | {
      /**
       * The discriminator declaring this to be a RIPEMD160-hashing operation.
       *
       * Upon executing this operation the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = ripemd160(oldMsg);
       * ```
       *
       */
      type: 'ripemd160';
    }
  | {
      /**
       * The discriminator declaring this to be a SHA256-hashing operation.
       *
       * Upon executing this operation the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = sha256(oldMsg);
       * ```
       *
       */
      type: 'sha256';
    }
  | {
      /**
       * The discriminator declaring this to be a KECCAK256-hashing operation.
       *
       * Upon executing this operation the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = keccak256(oldMsg);
       * ```
       *
       */
      type: 'keccak256';
    }
  | {
      /**
       * The discriminator declaring this to be a reversal operation.
       *
       * Upon executing this operation the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = oldMsg.toReversed();
       * ```
       *
       */
      type: 'reverse';
    }
  | {
      /**
       * The discriminator declaring this to be a "hexlify" operation.
       *
       * Upon executing this operation the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = oldMsg
       *     .reduce((result: string, value: number): string => result + value.toString(16).padStart(2, '0'), '')
       *     .toLowerCase();
       * ```
       *
       */
      type: 'hexlify';
    }
  | {
      /**
       * The discriminator declaring this to be an appending operation.
       *
       * Upon executing this operation the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = Uint8Array.of(...oldMsg, ...operand);
       * ```
       *
       */
      type: 'append';

      /**
       * The operand for the appending operation.
       *
       * Note how the presence of this operand as part of the operation itself makes it effectively a _unary_ operation.
       *
       */
      operand: Uint8Array;
    }
  | {
      /**
       * The discriminator declaring this to be aa prepending operation.
       *
       * Upon executing this operation the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = Uint8Array.of(...operand, ...oldMsg);
       * ```
       *
       */
      type: 'prepend';

      /**
       * The operand for the prepending operation.
       *
       * Note how the presence of this operand as part of the operation itself makes it effectively a _unary_ operation.
       *
       */
      operand: Uint8Array;
    };

/**
 * A "Tree" is the result of combining several {@link Paths} and merging their common prefixes to save space.
 *
 * This is implemented as a [Rose Tree](https://en.wikipedia.org/wiki/Rose_tree), with edges being decorated by {@link Op}s that
 * lead to other Trees, and terminals being simply {@link Leaf} elements.
 *
 * Furthermore, there's no point in having repeated {@link Leaf | leaves}, so a {@link MergeSet} is used to merge them;
 * likewise, there's no point in having repeated {@link Op} edges, so a {@link MergeMap} is used to merge the target Trees.
 *
 */
export type Tree = {
  /**
   * The leaves associated to this Tree node, as a {@link MergeSet} of {@link Leaf | leaves}.
   *
   */
  leaves: MergeSet<Leaf>;

  /**
   * The edges associated to this Tree node, as a {@link MergeMap} mapping {@link Op}s to Trees.
   *
   */
  edges: MergeMap<Op, Tree>;
};

/**
 * A "File Hash" is a way of representing both a hashing algorithm used and its resulting value.
 *
 * File Hashes are realized as tagged unions utilizing the `algorithm` field as discriminator.
 */
export type FileHash =
  | {
      /**
       * The discriminator declaring this to be a SHA1 hashing result.
       *
       */
      algorithm: 'sha1';

      /**
       * The hashing result proper.
       *
       */
      value: Uint8Array;
    }
  | {
      /**
       * The discriminator declaring this to be a RIPEMD160 hashing result.
       *
       */
      algorithm: 'ripemd160';

      /**
       * The hashing result proper.
       *
       */
      value: Uint8Array;
    }
  | {
      /**
       * The discriminator declaring this to be a SHA256 hashing result.
       *
       */
      algorithm: 'sha256';

      /**
       * The hashing result proper.
       *
       */
      value: Uint8Array;
    }
  | {
      /**
       * The discriminator declaring this to be a KECCAK256 hashing result.
       *
       */
      algorithm: 'keccak256';

      /**
       * The hashing result proper.
       *
       */
      value: Uint8Array;
    };

/**
 * A "Timestamp" is the representation of an `ots` file.
 *
 * A Timestamp is realized simply as a mapping type.
 *
 */
export type Timestamp = {
  /**
   * The protocol version number this Timestamp was constructed by.
   *
   * The current implementation will only ever generate and write version `1`.
   *
   */
  version: number;

  /**
   * The {@link FileHash} being attested.
   *
   */
  fileHash: FileHash;

  /**
   * The timestamp's {@link Tree}, containing attestation {@link Leaf | leaves} and {@link Op | operations}.
   *
   */
  tree: Tree;
};

/**
 * Verifiers are callbacks used to verify that a {@link Leaf} is indeed valid.
 *
 * This type alias captures the required callback prototype.
 *
 * @param msg - The message to validate.
 * @param leaf - The {@link Leaf} to validate against.
 * @returns `undefined` if the validator does not apply to the provided {@link Leaf}, the UNIX timestamp corresponding to the block the {@link Leaf} refers to if valid.
 * @throws {@link !Error} if validation failed.
 */
export type Verifier = (msg: Uint8Array, leaf: Leaf) => Promise<number | undefined>;
