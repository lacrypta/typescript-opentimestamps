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

/**
 * This module defines all basic types and constants used.
 *
 * @packageDocumentation
 * @module
 */

/**
 * An interface for an iteration over the standard {@link !Set} generic class, that's supposed to allow for identical elements to be identified and merged together.
 *
 * @typeParam V - The type of the contained elements.
 */
export interface MergeSet<V> {
  /**
   * Return the number of elements in the {@link MergeSet}.
   *
   * @returns The number of elements in the {@link MergeSet}.
   */
  size(): number;

  /**
   * Return a list of _values_ stored in a {@link MergeSet}.
   *
   * @returns The list of values in the {@link MergeSet}.
   */
  values(): V[];

  /**
   * Remove the given value from the {@link MergeSet}.
   *
   * @param value - The value to remove.
   * @returns The original {@link MergeSet} with the given {@link value} removed, for chaining.
   */
  remove(value: V): this;

  /**
   * Add the given value to the {@link MergeSet}.
   *
   * @param value - The value to add to the {@link MergeSet}.
   * @returns The original {@link MergeSet} with the given {@link value} added, for chaining.
   */
  add(value: V): this;

  /**
   * Add _all_ elements of the given {@link MergeSet} to the current one.
   *
   * @param other - The {@link MergeSet} to incorporate into this one.
   * @returns The original {@link MergeSet} with the given other {@link MergeSet} incorporated, for chaining.
   */
  incorporate(other: MergeSet<V>): this;
}

/**
 * An interface for an iteration over the standard {@link !Map} generic class, that allows for identical keys to be identified and their associated values be merged together.
 *
 * @typeParam K - The type of the contained keys.
 * @typeParam V - The type of the contained values.
 */
export interface MergeMap<K, V> {
  /**
   * Return the number of elements in the {@link MergeMap}.
   *
   * @returns The number of elements in the {@link MergeMap}.
   */
  size(): number;

  /**
   * Return a list of _Keys_ stored in a {@link MergeMap}.
   *
   * @returns The list of keys in the {@link MergeMap}.
   */
  keys(): K[];

  /**
   * Return a list of _values_ stored in a {@link MergeMap}.
   *
   * @returns The list of values in the {@link MergeMap}.
   */
  values(): V[];

  /**
   * Return a list of _entries_ (ie. key / value pairs) stored in a {@link MergeMap}.
   *
   * @returns The list of entries in the {@link MergeMap}.
   */
  entries(): [K, V][];

  /**
   * Remove the given key from the {@link MergeMap}.
   *
   * @param key - The key to remove.
   * @returns The original {@link MergeMap} with the given {@link key} removed, for chaining.
   */
  remove(key: K): this;

  /**
   * Add the given key / value pair to the {@link MergeMap}.
   *
   * @param key - The key to add to the {@link MergeMap}.
   * @param value - The value to add to the {@link MergeMap}.
   * @returns The original {@link MergeMap} with the given {@link key} / {@link value} pair added, for chaining.
   */
  add(key: K, value: V): this;

  /**
   * Add _all_ key / value pairs of the given {@link MergeMap} to the current one.
   *
   * @param other - The {@link MergeMap} to incorporate into this one.
   * @returns The original {@link MergeMap} with the given other {@link MergeMap} incorporated, for chaining.
   */
  incorporate(other: MergeMap<K, V>): this;
}

/**
 * A {@link Leaf} represents an attestation on a blockchain or a pending attestation on a calendar.
 *
 * {@link Leaf | Leaves} are realized as tagged unions utilizing the `type` field as discriminator.
 *
 * Unknown attestations are "future-proofing" devices: there's no way of verifying them on the current version of the standard,
 * but are nonetheless supported in case a new blockchain is supported in the future.
 *
 */
export type Leaf =
  | {
      /**
       * The discriminator declaring this to be a Bitcoin attestation.
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
       * The discriminator declaring this to be a Litecoin attestation.
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
       * The discriminator declaring this to be an Ethereum attestation.
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
       * The discriminator declaring this to be a _pending_ attestation.
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
       * The discriminator declaring this to be an _unknown_ attestation.
       *
       */
      type: 'unknown';

      /**
       * The 8-byte header identifying this (unknown) attestation type.
       *
       */
      header: Uint8Array;

      /**
       * The unknown attestation's payload.
       *
       */
      payload: Uint8Array;
    };

/**
 * An {@link Op | Operation} is simply a transformation to apply to the message being attested (an {@link !Uint8Array}).
 *
 * Operations are realized as tagged unions utilizing the `type` field as discriminator.
 *
 */
export type Op =
  | {
      /**
       * The discriminator declaring this to be a SHA1-hashing transformation.
       *
       * Upon executing, the message will be transformed thus:
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
       * The discriminator declaring this to be a RIPEMD160-hashing transformation.
       *
       * Upon executing, the message will be transformed thus:
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
       * The discriminator declaring this to be a SHA256-hashing transformation.
       *
       * Upon executing, the message will be transformed thus:
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
       * The discriminator declaring this to be a KECCAK256-hashing transformation.
       *
       * Upon executing, the message will be transformed thus:
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
       * The discriminator declaring this to be a reversal transformation.
       *
       * Upon executing, the message will be transformed thus:
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
       * The discriminator declaring this to be a "hexlify" transformation.
       *
       * Upon executing, the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = oldMsg
       *   .reduce(
       *     (result: string, value: number): string =>
       *       result + value.toString(16).padStart(2, '0'),
       *     '',
       *   )
       *   .toLowerCase();
       * ```
       *
       */
      type: 'hexlify';
    }
  | {
      /**
       * The discriminator declaring this to be an appending transformation.
       *
       * Upon executing, the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = Uint8Array.of(...oldMsg, ...operand);
       * ```
       *
       */
      type: 'append';

      /**
       * The operand for the appending transformation.
       *
       * Note how the presence of this operand as part of the {@link Op | operation} itself makes it effectively a _unary_ transformation.
       *
       */
      operand: Uint8Array;
    }
  | {
      /**
       * The discriminator declaring this to be aa prepending transformation.
       *
       * Upon executing, the message will be transformed thus:
       *
       * ```typescript
       * let newMsg: Uint8Array = Uint8Array.of(...operand, ...oldMsg);
       * ```
       *
       */
      type: 'prepend';

      /**
       * The operand for the prepending transformation.
       *
       * Note how the presence of this operand as part of the {@link Op | operation} itself makes it effectively a _unary_ transformation.
       *
       */
      operand: Uint8Array;
    };

/**
 * A {@link Tree} is the result of combining several paths and merging their common prefixes to save space.
 *
 * This is implemented as a [Rose Tree](https://en.wikipedia.org/wiki/Rose_tree), with edges being decorated by {@link Op | operations} that
 * lead to other {@link Tree | Trees}, and terminals being simply {@link Leaf} elements.
 *
 * Furthermore, there's no point in having repeated {@link Leaf | leaves}, so a {@link MergeSet} is used to merge them; likewise, there's no point in having repeated {@link Op} edges, so a {@link MergeMap} is used to merge the target {@link Tree | Trees}.
 *
 */
export type Tree = {
  /**
   * The {@link Leaf | leaves} associated to this {@link Tree} node, as a {@link MergeSet} of {@link Leaf | leaves}.
   *
   */
  leaves: MergeSet<Leaf>;

  /**
   * The edges associated to this {@link Tree} node, as a {@link MergeMap} mapping {@link Op | operations} to {@link Tree | Trees}.
   *
   */
  edges: MergeMap<Op, Tree>;
};

/**
 * A {@link FileHash} is a way of representing both a hashing algorithm used and its resulting value.
 *
 * {@link FileHash | FileHashes} are realized as tagged unions utilizing the `algorithm` field as discriminator.
 *
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
 * {@link Verifier | Verifiers} are callbacks used to verify that a {@link Leaf} is indeed valid.
 *
 * This type alias captures the required callback prototype.
 *
 * @param msg - The message to validate.
 * @param leaf - The {@link Leaf} to validate against.
 * @returns `undefined` if the validator does not apply to the provided {@link Leaf}, the UNIX timestamp corresponding to the block the {@link Leaf} refers to if valid.
 * @throws {@link !Error} if validation failed.
 */
export type Verifier = (msg: Uint8Array, leaf: Leaf) => Promise<number | undefined>;
