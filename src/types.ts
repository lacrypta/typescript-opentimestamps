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

import { MergeMap, MergeSet } from './utils';

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
 * A "Tree" is the result of combining several paths and merging their common prefixes to save space.
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
