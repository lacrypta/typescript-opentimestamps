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
 * This library will allow you to interact with Timestamps.
 *
 * # What are Timestamps?
 *
 * ...
 *
 * # How does OpenTimestamps work?
 *
 * ...
 *
 * ```mermaid
 * sequenceDiagram
 *     autonumber
 *     participant U as User
 *     participant C as Calendar
 *     participant B as Blockchain
 *     %
 *     U ->> C: submit
 *     activate U
 *     activate B
 *     activate C
 *     C -->> U: pending attestation
 *     deactivate C
 *     deactivate U
 *     %
 *     C -) B: transaction
 *     activate C
 *     B --) C: transaction added to block
 *     deactivate C
 *     %
 *     U ->> C: upgrade
 *     activate U
 *     activate C
 *     C -->> U: upgraded tree
 *     deactivate C
 *     deactivate U
 *     %
 *     U ->> B: query for Merkle root
 *     activate U
 *     B -->> U: Merkle root
 *     %
 *     deactivate B
 * ```
 *
 * ...
 *
 * @packageDocumentation
 * @module typescript-opentimestamps
 */

import type { Timestamp } from './types';

export type { FileHash, Leaf, MergeMap, MergeSet, Op, Timestamp, Tree, Verifier } from './types';

import { info as _info } from './info';
import { newTree as _newTree } from './internals';
import { canShrink as _canShrink, canUpgrade as _canUpgrade, canVerify as _canVerify } from './predicates';
import { read as _read } from './read';
import { shrink as _shrink } from './shrink';
import { submit as _submit } from './submit';
import { upgrade as _upgrade } from './upgrade';
import { assert as _assert, is as _is, validate as _validate } from './validation';
import { write as _write } from './write';

import { verify as _verify } from './verify';
import { default as verifiers } from './verifiers';

/**
 * Construct an empty {@link Tree}.
 *
 * @example
 * ```typescript
 * import { newTree } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(newTree());
 *   // {
 *   //   edges: EdgeMap { keySet: {}, mapping: {} },
 *   //   leaves: LeafSet { mapping: {} }
 *   // }
 * ```
 *
 * @returns The empty tree constructed.
 */
export const newTree = _newTree;

/**
 * Generate a human-readable string form the given {@link Timestamp}.
 *
 * Human-readable strings are generated as a concatenation of:
 *
 * - The {@link Timestamp}'s `version` (as a _"faux comment"_, and only if the `verbose` parameter is true).
 * - The {@link Timestamp}'s `fileHash` as a simple function call.
 * - Function call trees for the main {@link Timestamp} `tree`.
 *
 * @example
 * ```typescript
 * import type { Timestamp } from '@lacrypta/typescript-opentimestamps';
 *
 * import { info, read } from '@lacrypta/typescript-opentimestamps';
 *
 * const timestamp: Timestamp = read(Uint8Array.of(
 *   0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *   0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *   0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *   0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *   0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xf1,
 *   0x03, 0x01, 0x02, 0x03, 0xff, 0xf1, 0x03, 0x04, 0x05,
 *   0x06, 0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19,
 *   0x01, 0x02, 0xc8, 0x03, 0xf2, 0xf0, 0x03, 0x07, 0x08,
 *   0x09, 0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19,
 *   0x01, 0x01, 0x7b
 * ));
 *
 * console.log(info(timestamp));
 *   // msg = sha1(FILE)
 *   //  -> msg = reverse(msg)
 *   //     msg = append(msg, 030201070809)
 *   //     bitcoinVerify(msg, 123)
 *   //  -> msg = prepend(msg, 040506010203)
 *   //     bitcoinVerify(msg, 456)
 * console.log(info(timestamp, true));
 *   // # version: 1
 *   // msg = sha1(FILE)
 *   //     = 0102030405060708090a0b0c0d0e0f1011121314
 *   //  -> msg = reverse(msg)
 *   //         = 14131211100f0e0d0c0b0a090807060504030201
 *   //     msg = append(msg, 030201070809)
 *   //         = 14131211100f0e0d0c0b0a090807060504030201030201070809
 *   //     bitcoinVerify(msg, 123)
 *   //  -> msg = prepend(msg, 040506010203)
 *   //         = 0405060102030102030405060708090a0b0c0d0e0f1011121314
 *   //     bitcoinVerify(msg, 456)
 * ```
 *
 * @param timestamp - File hash to generate human-readable string for.
 * @param verbose - Whether to include the `value` field in the output or not.
 * @returns Human-readable string generated.
 */
export const info = _info;

/**
 * Determine whether the given {@link Timestamp} can be shrunk on the given chain.
 *
 * In order for a {@link Timestamp} to be shrunk, it needs to have at least one attestation on the given chain, and at least one other attestation.
 * Shrinking it would remove all but the oldest attestation on the given chain.
 *
 * @example
 * ```typescript
 * import {canShrink, read } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(canShrink(read(
 *   Uint8Array.of(
 *     0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *     0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *     0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *     0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *     0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *     0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
 *     0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     0x01, 0x7b, 0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7,
 *     0x19, 0x01, 0x02, 0xc8, 0x03,
 *   ),
 * ), 'bitcoin'));
 *   // true
 * console.log(canShrink(read(
 *   Uint8Array.of(
 *     0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *     0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *     0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *     0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *     0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *     0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x00,
 *     0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01, 0x01,
 *     0x7b
 *   ),
 * ), 'bitcoin'));
 *   // false
 * ```
 *
 * @param timestamp - The {@link Timestamp} being queried.
 * @param chain - The blockchain in question.
 * @returns `true` if the given {@link Timestamp} can be shrunk on the given chain, `false` otherwise.
 */
export const canShrink = _canShrink;

/**
 * Determine whether the given {@link Timestamp} can be upgraded.
 *
 * In order for a {@link Timestamp} to be upgraded, it needs to have at least one `pending` attestation.
 *
 * @example
 * ```typescript
 * import { canUpgrade, read } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(canUpgrade(read(
 *   Uint8Array.of(
 *     0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *     0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *     0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *     0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *     0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *     0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
 *     0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     0x01, 0x7b, 0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9,
 *     0x0c, 0x8e, 0x19, 0x18, 0x68, 0x74, 0x74, 0x70, 0x73,
 *     0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
 *     0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
 *     0x2f,
 *   ),
 * )));
 *   // true
 *
 * console.log(canUpgrade(read(
 *   Uint8Array.of(
 *     0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *     0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *     0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *     0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *     0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *     0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
 *     0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     0x01, 0x7b, 0x00, 0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7,
 *     0x1b, 0x45, 0x01, 0x7b
 *   ),
 * )));
 *   // false
 * ```
 *
 * @param timestamp - The {@link Timestamp} in question.
 * @returns `true` if the given {@link Timestamp} can be upgraded, `false` otherwise.
 */
export const canUpgrade = _canUpgrade;

/**
 * Determine whether the given {@link Timestamp} can be verified.
 *
 * In order for a {@link Timestamp} to be verified, it needs to have at least one non-`pending` attestation.
 *
 * @example
 * ```typescript
 * import { canVerify, read } from './src';
 *
 * console.log(canVerify(read(
 *   Uint8Array.of(
 *     0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *     0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *     0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *     0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *     0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *     0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
 *     0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     0x01, 0x7b, 0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9,
 *     0x0c, 0x8e, 0x19, 0x18, 0x68, 0x74, 0x74, 0x70, 0x73,
 *     0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
 *     0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
 *     0x2f
 *   ),
 * )));
 *   // true
 *
 * console.log(canVerify(read(
 *   Uint8Array.of(
 *     0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *     0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *     0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *     0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *     0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *     0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
 *     0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
 *     0x1a, 0x19, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
 *     0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d,
 *     0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x31,
 *     0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
 *     0x1a, 0x19, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
 *     0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d,
 *     0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x32
 *   ),
 * )));
 *   // false
 * ```
 *
 * @param timestamp - The {@link Timestamp} in question.
 * @returns `true` if the given {@link Timestamp} can be verified, `false` otherwise.
 */
export const canVerify = _canVerify;

/**
 * Read a {@link Timestamp} from the given data substrate.
 *
 * {@link Timestamp}s are stored as a sequence of "parts":
 *
 * 1. A "magic header" to indicate that this is a {@link Timestamp} data stream.
 * 2. The serialization format `version`, as a `UINT`.
 * 3. The serialized {@link FileHash}.
 * 4. The serialized {@link Tree}.
 *
 * This function will read the given data stream, and return the resulting {@link Timestamp} value.
 *
 * @example
 * ```typescript
 * import { read } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(read(
 *   Uint8Array.of(
 *     0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73,
 *     0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f,
 *     0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
 *     1,
 *     0x02,
 *     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
 *     0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
 *     0x00,
 *     0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     1,
 *     123,
 *   ),
 * ));
 *   // {
 *   //   fileHash: { algorithm: 'sha1', value: Uint8Array(20) [ ... ] },
 *   //   version: 1,
 *   //   tree: {
 *   //     edges: EdgeMap { keySet: {}, mapping: {} },
 *   //     leaves: LeafSet { mapping: [Object] }
 *   //   }
 *   // }
 * ```
 *
 * @example
 * ```typescript
 * import { read } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(read(
 *   Uint8Array.of(
 *     0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73,
 *     0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f,
 *     0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
 *     1,
 *     0x02,
 *     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
 *     0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
 *     0x00,
 *     0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     1,
 *     123,
 *     4,
 *     5,
 *     6,
 *     7,
 *     8,
 *     9,
 *   ),
 * ));
 *   // Error: Garbage at EOF
 * ```
 *
 * @param data - The data substrate to use.
 * @returns The read Timestamp.
 * @throws {@link !Error} when there's additional data past the Timestamp's value.
 */
export const read = _read;

/**
 * Shrink the given {@link Timestamp} on the given chain.
 *
 * Shrinking a {@link Timestamp} consists of eliminating all paths other than the one leading to the _oldest_ {@link Leaf} on the given chain.
 * This allows the {@link Timestamp} to be smaller, only keeping the most stringent attestation for the chose chain.
 *
 * Note that shrinking multiple times does nothing.
 *
 * @example
 * ```typescript
 * import type { Timestamp } from '@lacrypta/typescript-opentimestamps';
 *
 * import { info, read, shrink } from '@lacrypta/typescript-opentimestamps';
 *
 * const timestamp: Timestamp = read(
 *   Uint8Array.of(
 *     0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *     0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *     0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *     0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *     0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *     0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
 *     0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     0x01, 0x7b, 0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7,
 *     0x19, 0x01, 0x02, 0xc8, 0x03,
 *   ),
 * );
 * console.log(info(shrink(timestamp, 'bitcoin')));
 *   // msg = sha1(FILE)
 *   // bitcoinVerify(msg, 123)
 * console.log(info(shrink(shrink(timestamp, 'bitcoin'), 'bitcoin')));
 *   // msg = sha1(FILE)
 *   // bitcoinVerify(msg, 123)
 * ```
 *
 * @param timestamp - The {@link Timestamp} to shrink.
 * @param chain - The chain to look into for shrinking.
 * @returns The shrunken {@link Timestamp}.
 */
export const shrink = _shrink;

/**
 * Submit the given value to the given list of calendars.
 *
 * This function will take an algorithm (one of `sha1`, `ripemd160`, `sha256`, or `keccak256`), and an algorithm value (either a 20- or 32-byte value), and submits said value to each of the given calendars.
 *
 * Prior to submission, a "fudge" value is hashed alongside the given one, to prevent information leakage.
 * This fudge value may be given explicitly, or it may be randomly generated if none given.
 *
 * Errors encountered upon submission are not thrown, but rather collected and returned alongside the resulting timestamp.
 *
 * @example
 * ```typescript
 * import type { Timestamp } from '@lacrypta/typescript-opentimestamps';
 *
 * import { info, submit } from '@lacrypta/typescript-opentimestamps';
 *
 * const { timestamp, errors }: { timestamp: Timestamp; errors: Error[] } = await submit(
 *   'sha1',
 *   Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *   Uint8Array.of(1, 2, 3, 12, 23, 123),
 * );
 *
 * console.log(info(timestamp));
 *   // msg = sha1(FILE)
 *   // msg = append(msg, 0102030c177b)
 *   // msg = sha256(msg)
 *   //  -> msg = append(msg, 7bcfb7de87d0394c023b35e16003f936)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, a831953f37b90a9f5ebbcdee7e968622aff0c000c67c9fb8bee3eaf992959693)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, 65cb5387)
 *   //     msg = append(msg, b31df2f301366f3c)
 *   //     pendingVerify(msg, https://alice.btc.calendar.opentimestamps.org/)
 *   //  -> msg = append(msg, b7ed9e86271b179715445d568316d1d5)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, 65cb5387)
 *   //     msg = append(msg, 279f5cc8a3eea096)
 *   //     pendingVerify(msg, https://bob.btc.calendar.opentimestamps.org/)
 *   //  -> msg = append(msg, b852c30e4a6b1420c27d50a7cd40c7d2)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, c80f4d3abef43c6017ce3db34d3b7389a09ab31ae274204e12cd8babb1bafa95)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, 65cb5388)
 *   //     msg = append(msg, ddf860cef5179119)
 *   //     pendingVerify(msg, https://finney.calendar.eternitywall.com/)
 *   //  -> msg = append(msg, e71ef69c247fc026beb260bb38b01545)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, 767bc5417dca9794849f2d67c10480f6c1b715f6dfb0444b9218d36ab55d2d75)
 *   //     msg = sha256(msg)
 *   //     msg = prepend(msg, 65cb5388)
 *   //     msg = append(msg, b1d4d0b7fb122cea)
 *   //     pendingVerify(msg, https://btc.calendar.catallaxy.com/)
 * console.log(errors);
 *   // []
 * ```
 *
 * @param algorithm - The hashing algorithm to use.
 * @param value - The value to hash.
 * @param fudge - The fudging string to add (if not given, use a 16 random bytes).
 * @param calendarUrls - The calendars to submit the hashed value to, if not give, use default values.
 * @returns An object, mapping `timestamp` to the resulting {@link Timestamp}, and `errors` to a list of {@link !Error}s encountered.
 */
export const submit = _submit;

export const upgrade = _upgrade;

/**
 * {@link Timestamp} type-predicate.
 *
 * @example
 * ```typescript
 * import { newTree, is } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(is(123));
 *   // false
 * console.log(is({}));
 *   // false
 * console.log(is({ version: 1 }));
 *   // false
 * console.log(is(
 *   {
 *     version: 1,
 *     fileHash: {
 *       algorithm: 'sha1',
 *       value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *     },
 *   },
 * ));
 *   // false
 * console.log(is(
 *   {
 *     version: 1,
 *     fileHash: {
 *       algorithm: 'sha1',
 *       value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *     },
 *     tree: newTree(),
 *   },
 * )); // true
 * ```
 *
 * @param timestamp - Datum to check.
 * @returns `true` if the given datum is indeed a {@link Timestamp}, `false` otherwise.
 * @see [Using type predicates](https://www.typescriptlang.org/docs/handbook/2/narrowing.html#using-type-predicates)
 */
export const is = _is;

/**
 * {@link Timestamp} Assertion-function.
 *
 * > This function internally calls {@link validate}.
 *
 * @example
 * ```typescript
 * import { newTree, assert } from '@lacrypta/typescript-opentimestamps';
 *
 * assert({
 *   version: 1,
 *   fileHash: {
 *     algorithm: 'sha1',
 *     value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                          11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *   },
 *   tree: newTree(),
 * });
 *   // OK
 * ```
 *
 * @example
 * ```typescript
 * import { assert } from '@lacrypta/typescript-opentimestamps';
 *
 * assert(123);
 *   // Error: Expected non-null object
 * assert({});
 *   // Error: Expected key .version
 * assert({ version: 1 });
 *   // Error: Expected key .fileHash
 * assert({
 *   version: 1,
 *   fileHash: {
 *     algorithm: 'sha1',
 *     value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                          11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *   },
 * });
 *   // Error: Expected key .tree
 * ```
 *
 * @param timestamp - Datum to assert.
 * @see [Assertion Functions](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-3-7.html#assertion-functions)
 */
export const assert: (timestamp: unknown) => asserts timestamp is Timestamp = _assert;

/**
 * Validate that the given datum is a well-formed {@link Timestamp}.
 *
 * @example
 * ```typescript
 * import { newTree, validate } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(validate(
 *   {
 *     version: 1,
 *     fileHash: {
 *       algorithm: 'sha1',
 *       value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *     },
 *     tree: newTree(),
 *   },
 * ));
 *   // {
 *   //   version: 1,
 *   //   fileHash: { algorithm: 'sha1', value: Uint8Array(20) [ ... ] },
 *   //   tree: {
 *   //     edges: EdgeMap { keySet: {}, mapping: {} },
 *   //     leaves: LeafSet { mapping: {} }
 *   //   }
 *   // }
 * ```
 *
 * @example
 * ```typescript
 * import { validate } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(validate(123));
 *   // Error: Expected non-null object
 * console.log(validate({}));
 *   // Error: Expected key .version
 * console.log(validate({ version: 1 }));
 *   // Error: Expected key .fileHash
 * console.log(validate({
 *   version: 1,
 *   fileHash: {
 *     algorithm: 'sha1',
 *     value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                          11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *   },
 * }));
 *   // Error: Expected key .tree
 * ```
 *
 * @param timestamp - Data to validate.
 * @returns The validated {@link Timestamp}.
 * @throws {@link !Error} If the given datum has no `.version` key.
 * @throws {@link !Error} If the given datum has no `.fileHash` key.
 * @throws {@link !Error} If the given datum has no `.tree` key.
 */
export const validate = _validate;

/**
 * Write a {@link Timestamp}'s value.
 *
 * A {@link Timestamp} is written by concatenating the following parts in order:
 *
 * 1. A "magic header" to indicate that this is an ots.
 * 2. The `version` used to write the value.
 * 3. The {@link Timestamp}'s {@link FileHash}.
 * 4. The {@link Timestamp}'s {@link Tree}.
 *
 * @example
 * ```typescript
 * import { newTree, write } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(write(
 *   {
 *     version: 1,
 *     fileHash: {
 *       algorithm: 'sha1',
 *       value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *     },
 *     tree: newTree(),
 *   },
 * ));
 *   // Uint8Array(53) [
 *   //   0,  79, 112, 101, 110,  84, 105, 109, 101, 115, 116,
 *   //  97, 109, 112, 115,   0,   0,  80, 114, 111, 111, 102,
 *   //   0, 191, 137, 226, 232, 132, 232, 146, 148,   1,   2,
 *   //   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,
 *   //  12,  13,  14,  15,  16,  17,  18,  19,  20
 *   // ]
 * ```
 *
 * @param timestamp - The value to write.
 * @returns The written value.
 */
export const write = _write;

export const verify = _verify;

export { verifiers };
