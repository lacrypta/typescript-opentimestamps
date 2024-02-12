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
 * # How are Timestamps stored?
 *
 * ...
 *
 * ```ini
 * ; Primitive derivation rules
 * ;
 * ; These derivation rules constitute the basis for byte-based (de)serialization.
 * ;
 * ; <uint>s are the serialization of an arbitrary length unsigned integer value.
 * ; It is serialized into a multi-byte little-endian encoding using 7-bits-per-byte
 * ; with the MSB indicating continuation into the next byte (high) or marking the end
 * ; of the multi-byte serialization (low).
 * ;
 * ; <bytes> are the serialization of an arbitrary length byte value.
 * ; It is serialized as a <uint> indicating the number of <OCTET>s that follow and
 * ; constitute the actual serialized byte string.
 * ;
 * ; <url>s are the serialization of HTTPS URLs, it constitutes a specialization of
 * ; the <bytes> derivation rule.
 * ; All characters involved are singe-byte values and no percent-encoding is allowed.
 * ; A JavaScript RegExp to validate this pattern is:
 * ;   /^https:\/\/[a-zA-Z0-9_.-]+(:[0-9]+)?(\/[a-zA-Z0-9_.:-]+)*\/?$/
 *
 * uint  = *%x80-ff %x00-7f
 * bytes = uint *OCTET
 * url   = uint
 *         %s"https://"
 *         1*(ALPHA / DIGIT / "-" / "." / "_") [ ":" 1*DIGIT ]
 *         *( "/" 1*( ALPHA / DIGIT / "-" / "." / "_" / ":" ) )
 *         [ "/" ]
 *
 * ; Attestation derivation rules
 * ;
 * ; An attestation consists of an 8-byte "tag" (similar to the tags defined above)
 * ; that discriminates the attestation type proper, followed by a <bytes>
 * ; production; the bytes value of this <bytes> constitutes the attestation's
 * ; "payload".
 * ; All "determined" attestations (those using the Bitcoin, Ethereum, and Litecoin
 * ; blockchains) have a payload consisting solely of a <uint> value indicating
 * ; the block height where the attestation was indeed included in the blockchain;
 * ; this means that the <bytes> will be effectively a <uint> <uint>.
 * ; Pending attestations' payload consist of a <url> derivation itself; this means
 * ; that the <bytes> will be effectively <uint> <uint> *<OCTET>.
 * ; Unknown attestations simply ignore their <bytes> value.
 *
 * attestation-bitcoin  = %x05.88.96.0d.73.d7.19.01
 * attestation-litecoin = %x06.86.9a.0d.73.d7.1b.45
 * attestation-ethereum = %x30.fe.80.87.b5.c7.ea.d7
 * attestation-pending  = %x83.df.e3.0d.2e.f9.0c.8e
 * attestation-unknown  = 8OCTET
 *
 * attestation = ( attestation-pending  uint    url )
 *             / ( attestation-bitcoin  uint   uint )
 *             / ( attestation-ethereum uint   uint )
 *             / ( attestation-litecoin uint   uint )
 *             / ( attestation-unknown  uint *OCTET )
 *
 * ; Operations derivation rules
 * ;
 * ; Operations consist of a single-byte tag (the <op-*> derivation rules) and a number
 * ; of associated arguments.
 * ; Operations are divided into three different types: binary, unary, and attestations.
 * ; Binary operations (viz. append and prepend) are serialized as their tag, a <bytes>
 * ; operand, and a (recursive) <timestamp>.
 * ; Unary operations (viz. reverse, hexlify, sha1, ripemd160, sha256, keccak256) are
 * ; serialized as their tag, and a (recursive) <timestamp>.
 * ; Finally, attestations are simply serialized as their tag, and an <attestation>
 * ; derivation.
 *
 * op-attestation = %x00  ; not explicitly referred to as such in the code
 * op-sha1        = %x02
 * op-ripemd160   = %x03
 * op-sha256      = %x08
 * op-keccak256   = %x67
 * op-append      = %xf0
 * op-prepend     = %xf1
 * op-reverse     = %xf2  ; not present in all code bases
 * op-hexlify     = %xf3  ; not present in all code bases
 *
 * op = ( op-append      bytes   timestamp )
 *    / ( op-prepend     bytes   timestamp )
 *    / ( op-reverse             timestamp )
 *    / ( op-hexlify             timestamp )
 *    / ( op-sha1                timestamp )
 *    / ( op-ripemd160           timestamp )
 *    / ( op-sha256              timestamp )
 *    / ( op-keccak256           timestamp )
 *    / ( op-attestation       attestation )
 *
 * ; Timestamp derivation rules
 * ;
 * ; Timestamps consist of a number of operations (as defined above), where non-final
 * ; operations are preceded by a <non-final> tag.
 * ; Timestamps MUST NOT be empty (ie. at least an attestation or an operation proper
 * ; MUST be present).
 *
 * non-final = %xff
 * timestamp = *( non-final op ) op
 *
 * ; Detached Timestamp File derivation rules
 * ;
 * ; A detached timestamp file consists of a 31 byte magic header, a <uint> indicating
 * ; the serialization version to use (only version 1 is defined so far), a <file-hash>,
 * ; and a <timestamp>.
 * ; Each <file-hash> is simply an algorithm tag, followed by the prescribed number of
 * ; bytes required for its value (20 bytes for sha1 and ripemd160, 32 bytes for sha256
 * ; and keccak256).
 *
 * magic-header = %x00.4f.70.65.6e.54.69.6d.65.73.74.61.6d.70.73.00.00.50.72.6f.6f.66.00.bf.89.e2.e8.84.e8.92.94
 *
 * file-hash = ( op-sha1      20OCTET )
 *           / ( op-ripemd160 20OCTET )
 *           / ( op-sha256    32OCTET )
 *           / ( op-keccak256 32OCTET )
 *
 * DETACHED = magic-header
 *            uint
 *            file-hash
 *            timestamp
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
 * console.log(
 *   canUpgrade(
 *     read(
 *       Uint8Array.of(
 *         0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *         0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *         0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *         0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *         0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *         0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
 *         0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *         0x01, 0x7b, 0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9,
 *         0x0c, 0x8e, 0x19, 0x18, 0x68, 0x74, 0x74, 0x70, 0x73,
 *         0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
 *         0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
 *         0x2f,
 *       ),
 *     ),
 *   ),
 * );
 *   // true
 *
 * console.log(
 *   canUpgrade(
 *     read(
 *       Uint8Array.of(
 *         0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *         0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *         0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *         0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *         0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *         0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
 *         0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *         0x01, 0x7b, 0x00, 0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7,
 *         0x1b, 0x45, 0x01, 0x7b
 *       ),
 *     ),
 *   ),
 * );
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
 * console.log(
 *   canVerify(
 *     read(
 *       Uint8Array.of(
 *         0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *         0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *         0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *         0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *         0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *         0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
 *         0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *         0x01, 0x7b, 0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9,
 *         0x0c, 0x8e, 0x19, 0x18, 0x68, 0x74, 0x74, 0x70, 0x73,
 *         0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
 *         0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
 *         0x2f
 *       ),
 *     ),
 *   ),
 * );
 *   // true
 *
 * console.log(
 *   canVerify(
 *     read(
 *       Uint8Array.of(
 *         0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65,
 *         0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50,
 *         0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8,
 *         0x84, 0xe8, 0x92, 0x94, 0x01, 0x02, 0x01, 0x02, 0x03,
 *         0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
 *         0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
 *         0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
 *         0x1a, 0x19, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
 *         0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d,
 *         0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x31,
 *         0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
 *         0x1a, 0x19, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
 *         0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d,
 *         0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x32
 *       ),
 *     ),
 *   ),
 * );
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

export const shrink = _shrink;

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
