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
 * This module exposes binary reading functions.
 *
 * A {@link types!Timestamp | Timestamp} is stored as a sequence of bytes.
 * In order to understand how this is done, let us build an [ABNF](https://en.wikipedia.org/wiki/Augmented_Backus%E2%80%93Naur_form) grammar for it.
 *
 * First, let's deal with the _primitive derivation rules_, these derivation rules constitute the basis for byte-based (de)serialization.
 *
 * ```ini
 * uint  = *%x80-ff %x00-7f
 * bytes = uint *OCTET
 * url   = uint
 *         %s"https://"
 *         1*(ALPHA / DIGIT / "-" / "." / "_") [ ":" 1*DIGIT ]
 *         *( "/" 1*( ALPHA / DIGIT / "-" / "." / "_" / ":" ) )
 *         [ "/" ]
 * ```
 *
 * `<uint>`s are the serialization of an arbitrary length unsigned integer value.
 * It is serialized into a multi-byte little-endian encoding using 7-bits-per-byte with the MSB indicating continuation into the next byte (high) or marking the end of the multi-byte serialization (low).
 *
 * `<bytes>` are the serialization of an arbitrary length byte value.
 * It is serialized as a `<uint>` indicating the number of `<OCTET>`s that follow and constitute the actual serialized byte string.
 *
 * `<url>`s are the serialization of HTTPS URLs, it constitutes a specialization of the `<bytes>` derivation rule.
 * All characters involved are singe-byte values and no percent-encoding is allowed.
 * A JavaScript {@link !RegExp} to validate this pattern is:
 *
 * ```perl
 * /^https:\\/\\/[a-zA-Z0-9_.-]+(:[0-9]+)?(\\/[a-zA-Z0-9_.:-]+)*\\/?$/
 * ```
 *
 * Now, let's deal with _attestation derivation rules_ (nb. "attestations" are what we call {@link types!Leaf | Leaves}).
 *
 *
 * ```ini
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
 * ```
 *
 * An `<attestation>` consists of an 8-byte "tag" (similar to the tags defined further down) that discriminates the {@link types!Leaf | attestation} type proper, followed by a `<bytes>`; the bytes value of this `<bytes>` constitutes the {@link types!Leaf | attestation}'s "payload".
 *
 * All "determined" {@link types!Leaf | attestation} (those using the Bitcoin, Ethereum, and Litecoin blockchains) have a payload consisting solely of a `<uint>` value indicating the block height where the {@link types!Leaf | attestation} was indeed included in the blockchain; this means that the `<bytes>` will be effectively a `<uint> <uint>`.
 *
 * Pending {@link types!Leaf | attestation}' payload consist of a `<url>` itself; this means that the `<bytes>` will be effectively `<uint> <uint> *<OCTET>`.
 *
 * Unknown {@link types!Leaf | attestations} simply ignore their `<bytes>` value.
 *
 * Now, let's deal with _{@link types!Op | operations} derivation rules_.
 *
 * ```ini
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
 * ```
 *
 * {@link types!Op | Operations} consist of a single-byte tag (the `<op-*>` rules) and a number of associated arguments.
 * {@link types!Op | Operations} are divided into three different types: binary, unary, and {@link types!Leaf | attestations}.
 *
 * Binary {@link types!Op | operations} (viz. `append` and `prepend`) are serialized as their tag, a `<bytes>` operand, and a (recursive) `<timestamp>`.
 *
 * Unary {@link types!Op | operations} (viz. `reverse`, `hexlify`, `sha1`, `ripemd160`, `sha256`, and `keccak256`) are serialized as their tag, and a (recursive) `<timestamp>`.
 *
 * Finally, {@link types!Leaf | attestations} are simply serialized as their tag, and an `<attestation>`.
 *
 * We can now define the {@link types!Timestamp | Timestamp} rules:
 *
 * ```ini
 * non-final = %xff
 * timestamp = *( non-final op ) op
 * ```
 *
 * Timestamps consist of a number of operations (as defined above), where non-final operations are preceded by a `<non-final>` tag.
 * Timestamps **must not** be empty (ie. at least an attestation or an operation proper **must** be present).
 *
 * Finally, a "detached" timestamp file's rules are:
 *
 * ```ini
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
 * A {@link types!Timestamp | detached timestamp} file consists of a 31 byte {@link internals!magicHeader | magic header}, a `<uint>` indicating the serialization version to use (only version `1` is defined so far), a `<file-hash>`, and a `<timestamp>`.
 *
 * A `<file-hash>` is simply an algorithm tag, followed by the prescribed number of bytes required for its value (20 bytes for `sha1` and `ripemd160`, 32 bytes for `sha256` and `keccak256`).
 *
 * @packageDocumentation
 * @module
 */

import type { Edge } from './internals';
import type { FileHash, Leaf, Timestamp, Tree } from './types';

import { incorporateToTree, magicHeader, newTree, nonFinal, Tag } from './internals';
import { textDecoder, uint8ArrayEquals, uint8ArrayToHex } from './utils';
import { validateCalendarUrl } from './validation';

/**
 * Extract the given number of bytes, from the given position onwards, from the given data substrate.
 *
 * @example
 * ```typescript
 * import { getBytes } from './src/read';
 *
 * console.log(getBytes(2, Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9), 5));
 *   // [ Uint8Array(2) [ 6, 7 ], 7 ]
 * ```
 *
 * @example
 * ```typescript
 * import { getBytes } from './src/read';
 *
 * console.log(getBytes(8, Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9), 5));
 *   // Error: Unexpected EOF reading bytes at position 5
 * ```
 *
 * @param length - The number of bytes to extract.
 * @param data - The data substrate to use.
 * @param index - The position from which to start extraction.
 * @returns A pair, consisting of the extracted bytes, and the new data `index`.
 * @throws {@link !Error} when there are not enough bytes to fulfill the request.
 */
export function getBytes(length: number, data: Uint8Array, index: number): [Uint8Array, number] {
  if (data.length < index + length) {
    throw new Error(`Unexpected EOF reading bytes at position ${index}`);
  }
  return [data.slice(index, index + length), index + length];
}

/**
 * Extract a single byte, from the given position onwards, from the given data substrate.
 *
 * > This function internally calls {@link getBytes}.
 *
 * @example
 * ```typescript
 * import { getByte } from './src/read';
 *
 * console.log(getByte(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9), 5));
 *   // [ 6, 6 ]
 * ```
 *
 * @example
 * ```typescript
 * import { getByte } from './src/read';
 *
 * console.log(getByte(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9), 15));
 *   // Error: Unexpected EOF reading bytes at position 15
 * ```
 *
 * @param data - The data substrate to use.
 * @param index - The position from which to extract.
 * @returns A pair, consisting of the extracted byte, and the new data `index`.
 */
export function getByte(data: Uint8Array, index: number): [number, number] {
  const [[result], idx]: [Uint8Array, number] = getBytes(1, data, index);
  return [result!, idx];
}

/**
 * Read a multi-byte unsigned integer, from the given position onwards, from the given data substrate.
 *
 * Multi-byte unsigned integers (ie. `UINT`s) are stored in byte-based little-endian ordering, and use the most-significant-bit to indicate whether more bytes need to be read.
 * Pictorially, if the number to store has the following bit-pattern:
 *
 * ```
 * aaaaaaabbbbbbbcccccccddddddd
 * ```
 *
 * it will be stored as (leftmost bytes appear _first_ in the data stream, leftmost bits are more significant):
 *
 * ```
 * 1ddddddd 1ccccccc 1bbbbbbb 0aaaaaaa
 * ```
 *
 * > This function internally calls {@link getByte}.
 *
 * @example
 * ```typescript
 * import { readUint } from './src/read';
 *
 * console.log(readUint(Uint8Array.of(0x00), 0));
 *   // [ 0, 1 ]
 * console.log(readUint(Uint8Array.of(0x80, 0x00), 0));
 *   // [ 0, 2 ]
 * console.log(readUint(Uint8Array.of(0x80, 0x01), 0));
 *   // [ 128, 2 ]
 * ```
 *
 * @example
 * ```typescript
 * import { readUint } from './src/read';
 *
 * console.log(readUint(Uint8Array.of(0x80), 0));
 *   // Error: Unexpected EOF reading bytes at position 1
 * ```
 *
 * @param data - The data substrate to use.
 * @param index - The position from which to read.
 * @returns A pair, consisting of the read number, and the new data `index`.
 */
export function readUint(data: Uint8Array, index: number): [number, number] {
  let result: number = 0;
  let displacement: number = 0;
  let [current, idx]: [number, number] = getByte(data, index);
  while (current & 0x80) {
    result += (0x7f & current) << (7 * displacement++);
    [current, idx] = getByte(data, idx);
  }
  return [result + (current << (7 * displacement)), idx];
}

/**
 * Read a variable-length bytes value, from the given position onwards, from the given data substrate.
 *
 * Variable-length bytes (ie. `VARBYTE`) are stored as two consecutive entities: a `UINT` specifying the number of bytes that follow, and the bytes themselves.
 *
 * > This function internally calls {@link readUint}.
 * >
 * > This function internally calls {@link getBytes}.
 *
 * @example
 * ```typescript
 * import { readBytes } from './src/read';
 *
 * console.log(readBytes(Uint8Array.of(0x01, 123), 0));
 *   // [ Uint8Array(1) [ 123 ], 2 ]
 * console.log(readBytes(Uint8Array.of(0x02, 1, 2, 3), 0));
 *   // [ Uint8Array(2) [ 1, 2 ], 3 ]
 * ```
 *
 * @example
 * ```typescript
 * import { readBytes } from './src/read';
 *
 * console.log(readBytes(Uint8Array.of(0x03, 1), 0));
 *   // Error: Unexpected EOF reading bytes at position 1
 * ```
 *
 * @param data - The data substrate to use.
 * @param index - The position from which to read.
 * @returns A pair, consisting of the read bytes, and the new data `index`.
 */
export function readBytes(data: Uint8Array, index: number): [Uint8Array, number] {
  const [length, idx]: [number, number] = readUint(data, index);
  const [result, idx2]: [Uint8Array, number] = getBytes(length, data, idx);
  return [result, idx2];
}

/**
 * Read a variable-length _calendar_ {@link !URL}, from the given position onwards, from the given data substrate.
 *
 * Variable-length calendar {@link !URL | URLs} are stored as a `VARBYTE`, when read, they're also validated via {@link validateCalendarUrl}.
 *
 * > This function internally calls {@link readBytes}.
 * >
 * > This function internally calls {@link validateCalendarUrl}.
 *
 * @example
 * ```typescript
 * import { readUrl } from './src/read';
 *
 * const url: string = 'https://www.example.com';
 *
 * console.log(readUrl(
 *   Uint8Array.of(
 *     url.length,
 *     ...new TextEncoder().encode(url),
 *   ),
 *   0,
 * ));
 *   // [ URL { ... }, 24 ]
 * ```
 *
 * @example
 * ```typescript
 * import { readUrl } from './src/read';
 *
 * const url: string = 'https://www.example.com?something=else';
 *
 * console.log(readUrl(
 *   Uint8Array.of(
 *     url.length,
 *     ...new TextEncoder().encode(url),
 *   ),
 *   0,
 * ));
 *   // Error: Invalid URL
 * ```
 *
 * @param data - The data substrate to use.
 * @param index - The position from which to read.
 * @returns A pair, consisting of the read {@link !URL}, and the new data `index`.
 */
export function readUrl(data: Uint8Array, index: number): [URL, number] {
  const [url, idx]: [Uint8Array, number] = readBytes(data, index);
  return [new URL(validateCalendarUrl(textDecoder.decode(url))), idx];
}

/**
 * Read a fixed-length byte literal, from the given position onwards, from the given data substrate, fail if not found.
 *
 * > This function internally calls {@link getBytes}.
 *
 * @example
 * ```typescript
 * import { readLiteral } from './src/read';
 *
 * console.log(readLiteral(
 *   Uint8Array.of(1, 2, 3, 4),
 *   0,
 *   Uint8Array.of(1, 2),
 * ));
 *   // [ Uint8Array(2) [ 1, 2 ], 2 ]
 * console.log(readLiteral(
 *   Uint8Array.of(1, 2, 3, 4),
 *   1,
 *   Uint8Array.of(2, 3),
 * ));
 *   // [ Uint8Array(2) [ 2, 3 ], 3 ]
 * ```
 *
 * @example
 * ```typescript
 * import { readLiteral } from './src/read';
 *
 * console.log(readLiteral(
 *   Uint8Array.of(1, 2, 3, 4),
 *   0,
 *   Uint8Array.of(3, 4),
 * ));
 *   // Error: Literal mismatch (expected 0304 but found 0102) at position 0
 * ```
 *
 * @param data - The data substrate to use.
 * @param index - The position from which to read.
 * @param literal - The literal to check for.
 * @returns A pair, consisting of the read literal, and the new data `index`.
 * @throws {@link !Error} when the given literal is not found.
 */
export function readLiteral(data: Uint8Array, index: number, literal: Uint8Array): [Uint8Array, number] {
  const [found, idx]: [Uint8Array, number] = getBytes(literal.length, data, index);
  if (!uint8ArrayEquals(found, literal)) {
    throw new Error(
      `Literal mismatch (expected ${uint8ArrayToHex(literal)} but found ${uint8ArrayToHex(found)}) at position ${index}`,
    );
  }
  return [found, idx];
}

/**
 * Read the `payload` portion of a "done" {@link Leaf} (ie. a {@link Leaf} with `type` equal to `'bitcoin'`, `'litecoin'`, or `'ethereum'`).
 *
 * A "done" {@link Leaf}'s payload consists solely of an `UINT`, that constitutes the {@link Leaf}'s `height` value.
 *
 * > This function internally calls {@link readUint}.
 *
 * @example
 * ```typescript
 * import { readDoneLeafPayload } from './src/read';
 *
 * console.log(readDoneLeafPayload(Uint8Array.of(0x00)));
 *   // 0
 * console.log(readDoneLeafPayload(Uint8Array.of(0x80, 0x00)));
 *   // 0
 * ```
 *
 * @example
 * ```typescript
 * import { readDoneLeafPayload } from './src/read';
 *
 * console.log(readDoneLeafPayload(Uint8Array.of(0x80)));
 *   // Error: Unexpected EOF reading bytes at position 1
 * console.log(readDoneLeafPayload(Uint8Array.of(0x00, 0x00)));
 *   // Error: Garbage at end of attestation payload
 * ```
 *
 * @param payload - Payload data to read.
 * @returns The read `height` value.
 * @throws {@link !Error} when the payload contains additional data past the `UINT`'s value.
 */
export function readDoneLeafPayload(payload: Uint8Array): number {
  const [height, length]: [number, number] = readUint(payload, 0);
  if (payload.length !== length) {
    throw new Error('Garbage at end of attestation payload');
  }
  return height;
}

/**
 * Read the `payload` portion of a pending {@link Leaf} (ie. a {@link Leaf} with `type` equal to `'pending'`).
 *
 * A pending {@link Leaf}'s payload consists solely of an {@link !URL}, that constitutes the {@link Leaf}'s `url` value.
 *
 * > This function internally calls {@link readUrl}.
 *
 * @example
 * ```typescript
 * import { readPendingLeafPayload } from './src/read';
 *
 * const url: string = 'https://www.example.com';
 *
 * console.log(readPendingLeafPayload(
 *   Uint8Array.of(
 *     url.length,
 *     ...new TextEncoder().encode(url),
 *   )
 * ));
 *   // URL { ... }
 * ```
 *
 * @example
 * ```typescript
 * import { readPendingLeafPayload } from './src/read';
 *
 * const url: string = 'https://www.example.com';
 *
 * console.log(readPendingLeafPayload(
 *   Uint8Array.of(
 *     url.length,
 *     ...new TextEncoder().encode(url),
 *     1,
 *     2,
 *     3,
 *   ),
 * ));
 *   // Error: Garbage at end of Pending attestation payload
 * ```
 *
 * @param payload - Payload data to read.
 * @returns The read {@link !URL} value.
 * @throws {@link !Error} when the payload contains additional data past the {@link !URL}'s value.
 */
export function readPendingLeafPayload(payload: Uint8Array): URL {
  const [url, length]: [URL, number] = readUrl(payload, 0);
  if (payload.length !== length) {
    throw new Error('Garbage at end of Pending attestation payload');
  }
  return url;
}

/**
 * Read a {@link Leaf}, from the given position onwards, from the given data substrate.
 *
 * {@link Leaf | Leaves} are stored as an 8-byte header, followed by a `VARBYTE` payload.
 *
 * > This function internally calls {@link getBytes}.
 * >
 * > This function internally calls {@link readBytes}.
 * >
 * > This function internally calls {@link readDoneLeafPayload}.
 * >
 * > This function internally calls {@link readPendingLeafPayload}.
 *
 * @example
 * ```typescript
 * import { readLeaf } from './src/read';
 *
 * const url: string = 'https://www.example.com';
 *
 * console.log(readLeaf(
 *   Uint8Array.of(
 *     0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     1,
 *     123,
 *   ),
 *   0,
 * ));
 *   // [ { type: 'bitcoin', height: 123 }, 10 ]
 * console.log(readLeaf(
 *   Uint8Array.of(
 *     0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45,
 *     1,
 *     123,
 *   ),
 *   0,
 * ));
 *   // [ { type: 'litecoin', height: 123 }, 10 ]
 * console.log(readLeaf(
 *   Uint8Array.of(
 *     0x30, 0xfe, 0x80, 0x87, 0xb5, 0xc7, 0xea, 0xd7,
 *     1,
 *     123,
 *   ),
 *   0,
 * ));
 *   // [ { type: 'ethereum', height: 123 }, 10 ]
 * console.log(readLeaf(
 *   Uint8Array.of(
 *     0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
 *     url.length + 1,
 *     url.length,
 *     ...new TextEncoder().encode(url)
 *   ),
 *   0,
 * ));
 *   // [ { type: 'pending', url: URL { ... } }, 33 ]
 * console.log(readLeaf(
 *   Uint8Array.of(
 *     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
 *     4,
 *     3, 1, 2, 3
 *   ),
 *   0,
 * ));
 *   // [
 *   //   {
 *   //     type: 'unknown',
 *   //     header: Uint8Array(8) [ 1, 2, 3, 4, 5, 6, 7, 8 ],
 *   //     payload: Uint8Array(4) [ 3, 1, 2, 3 ]
 *   //   },
 *   //   13
 *   // ]
 * ```
 *
 * @param data - The data substrate to use.
 * @param index - The position from which to read.
 * @returns A pair, consisting of the read {@link Leaf}, and the new data `index`.
 */
export function readLeaf(data: Uint8Array, index: number): [Leaf, number] {
  const [header, idx]: [Uint8Array, number] = getBytes(8, data, index);
  const [payload, idx2]: [Uint8Array, number] = readBytes(data, idx);
  const sHeader: string = uint8ArrayToHex(header);
  switch (sHeader) {
    case '0588960d73d71901':
      return [{ type: 'bitcoin', height: readDoneLeafPayload(payload) }, idx2];
    case '06869a0d73d71b45':
      return [{ type: 'litecoin', height: readDoneLeafPayload(payload) }, idx2];
    case '30fe8087b5c7ead7':
      return [{ type: 'ethereum', height: readDoneLeafPayload(payload) }, idx2];
    case '83dfe30d2ef90c8e':
      return [{ type: 'pending', url: readPendingLeafPayload(payload) }, idx2];
    default:
      return [{ type: 'unknown', header, payload }, idx2];
  }
}

/**
 * Read either an {@link Edge} or a {@link Leaf}, from the given position onwards, from the given data substrate.
 *
 * {@link Leaf | Leaves} are signalled by a `0x00` byte, followed by the {@link Leaf}'s content.
 *
 * {@link Edge | Edges} are signalled by a non-`0x00` byte that identifies their `type` (cf. {@link Tag}), followed by the {@link Edge}'s content.
 * Unary {@link Edge} `type`s (ie. `'sha1'`, `'ripemd160'`, `'sha256'`, `'keccak256'`, `'reverse'`, and `'hexlify'`) are followed by a {@link Tree}'s content, whilst binary {@link Edge} `type`s (ie. `'append'` and `'prepend'`) are followed by a `VARBYTE` (their `operand`) and then a {@link Tree}'s content.
 *
 * > This function internally calls {@link getByte}.
 * >
 * > This function internally calls {@link readLeaf}.
 * >
 * > This function internally calls {@link readTree}.
 * >
 * > This function internally calls {@link readBytes}.
 *
 * @example
 * ```typescript
 * import { readEdgeOrLeaf } from './src/read';
 *
 * console.log(readEdgeOrLeaf(
 *   Uint8Array.of(
 *     0x00,
 *     0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     1,
 *     123,
 *   ),
 *   0,
 * ));
 *   // [ { type: 'bitcoin', height: 123 }, 11 ]
 * console.log(readEdgeOrLeaf(
 *   Uint8Array.of(
 *     0x02,
 *     0x00,
 *     0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     1,
 *     123,
 *   ),
 *   0,
 * ));
 *   // [ [ { type: 'sha1' }, { edges: EdgeMap {}, leaves: LeafSet {} } ], 12 ]
 * console.log(readEdgeOrLeaf(
 *   Uint8Array.of(
 *     0xf0,
 *     3,
 *     1, 2, 3,
 *     0x00,
 *     0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     1,
 *     123,
 *   ),
 *   0,
 * ));
 *   // [
 *   //   [
 *   //     { type: 'append', operand: [Uint8Array] },
 *   //     { edges: [EdgeMap], leaves: [LeafSet] }
 *   //   ],
 *   //   16
 *   // ]
 * ```
 *
 * @example
 * ```typescript
 * import { readEdgeOrLeaf } from './src/read';
 *
 * console.log(readEdgeOrLeaf(Uint8Array.of(0x77), 0));
 *   // Error: Unknown operation 77 at position 0
 * ```
 *
 * @param data - The data substrate to use.
 * @param index - The position from which to read.
 * @returns A pair, consisting of the read {@link Edge} or {@link Leaf}, and the new data `index`.
 * @throws {@link !Error} when the {@link Edge} `type` is not known.
 */
export function readEdgeOrLeaf(data: Uint8Array, index: number): [Edge | Leaf, number] {
  const [tag, idx]: [number, number] = getByte(data, index);
  switch (tag) {
    case 0x00:
      return readLeaf(data, idx);
    case 0x02:
    case 0x03:
    case 0x08:
    case 0x67:
    case 0xf2:
    case 0xf3: {
      const [tree, idx2]: [Tree, number] = readTree(data, idx);
      return [
        [{ type: Tag[tag] as 'sha1' | 'ripemd160' | 'sha256' | 'keccak256' | 'reverse' | 'hexlify' }, tree],
        idx2,
      ];
    }
    case 0xf0:
    case 0xf1: {
      const [operand, idx2]: [Uint8Array, number] = readBytes(data, idx);
      const [tree, idx3]: [Tree, number] = readTree(data, idx2);
      return [[{ type: Tag[tag] as 'append' | 'prepend', operand }, tree], idx3];
    }
    default:
      throw new Error(`Unknown operation ${uint8ArrayToHex(Uint8Array.of(tag))} at position ${index}`);
  }
}

/**
 * Read a {@link Tree}, from the given position onwards, from the given data substrate.
 *
 * {@link Tree | Trees} are stored as sequences of values, with a special "tag" (ie. {@link internals!nonFinal | `0xff`}) signifying that the one that follows is **not** the last value in the {@link Tree}.
 * Values themselves can be either {@link Leaf | Leaves} or {@link Edge | Edges}.
 *
 * > This function internally calls {@link readEdgeOrLeaf}.
 *
 * @example
 * ```typescript
 * import { readTree } from './src/read';
 *
 * console.log(readTree(
 *   Uint8Array.of(
 *     0xff,
 *     0x00,
 *     0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *     1,
 *     123,
 *     0x00,
 *     0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45,
 *     1,
 *     123,
 *   ),
 *   0,
 * ));
 *   // [ { edges: EdgeMap {}, leaves: LeafSet {} }, 23 ]
 * ```
 *
 * @param data - The data substrate to use.
 * @param index - The position from which to read.
 * @returns A pair, consisting of the read {@link Tree}, and the new data `index`.
 */
export function readTree(data: Uint8Array, index: number): [Tree, number] {
  const result: Tree = newTree();
  let idx: number = index;
  while (nonFinal === data[idx]) {
    const [edgeOrLeaf, idx2]: [Edge | Leaf, number] = readEdgeOrLeaf(data, idx + 1);
    incorporateToTree(result, edgeOrLeaf);
    idx = idx2;
  }
  const [edgeOrLeaf, idx2]: [Edge | Leaf, number] = readEdgeOrLeaf(data, idx);
  incorporateToTree(result, edgeOrLeaf);
  return [result, idx2];
}

/**
 * Read a {@link FileHash}, from the given position onwards, from the given data substrate.
 *
 * {@link FileHash | File hashes} are stored as a single-byte hash algorithm indicator, followed by a fixed-length byte sequence that stores the hash value proper.
 * For "short" hash algorithms (ie. `'sha1'` and `'ripemd160'`), the fixed-length sequence has 20 bytes; for "long" hash algorithms (ie. `'sha256'` and `'keccak256'`), the fixed-length sequence has 32 bytes.
 *
 * > This function internally calls {@link getByte}.
 * >
 * > This function internally calls {@link getBytes}.
 *
 * @example
 * ```typescript
 * import { readFileHash } from './src/read';
 *
 * console.log(readFileHash(
 *   Uint8Array.of(
 *     0x02,
 *     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
 *     0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
 *   ),
 *   0,
 * ));
 *   // [ { algorithm: 'sha1', value: Uint8Array(20) [ ... ] }, 21 ]
 * console.log(readFileHash(
 *   Uint8Array.of(
 *     0x03,
 *     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
 *     0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
 *   ),
 *   0,
 * ));
 *   // [ { algorithm: 'ripemd160', value: Uint8Array(20) [ ... ] }, 21 ]
 * console.log(readFileHash(
 *   Uint8Array.of(
 *     0x08,
 *     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
 *     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
 *     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
 *     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
 *   ),
 *   0,
 * ));
 *   // [ { algorithm: 'sha256', value: Uint8Array(32) [ ... ] }, 33 ]
 * console.log(readFileHash(
 *   Uint8Array.of(
 *     0x67,
 *     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
 *     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
 *     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
 *     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
 *   ),
 *   0,
 * ));
 *   // [ { algorithm: 'keccak256', value: Uint8Array(32) [ ... ] }, 33 ]
 * ```
 *
 * @example
 * ```typescript
 * import { readFileHash } from './src/read';
 *
 * console.log(readFileHash(Uint8Array.of(0x77), 0));
 *   // Error: Unknown hashing algorithm 77 at position 0
 * ```
 *
 * @param data - The data substrate to use.
 * @param index - The position from which to read.
 * @returns A pair, consisting of the read {@link FileHash}, and the new data `index`.
 * @throws {@link !Error} when the hash algorithm is unknown.
 */
export function readFileHash(data: Uint8Array, index: number): [FileHash, number] {
  const [tag, idx]: [number, number] = getByte(data, index);
  switch (tag) {
    case 0x02:
    case 0x03: {
      const [value, idx2]: [Uint8Array, number] = getBytes(20, data, idx);
      return [{ algorithm: Tag[tag] as 'sha1' | 'ripemd160', value }, idx2];
    }
    case 0x08:
    case 0x67: {
      const [value, idx2]: [Uint8Array, number] = getBytes(32, data, idx);
      return [{ algorithm: Tag[tag] as 'sha256' | 'keccak256', value }, idx2];
    }
    default:
      throw new Error(`Unknown hashing algorithm ${uint8ArrayToHex(Uint8Array.of(tag))} at position ${index}`);
  }
}

/**
 * Read a `version`, from the given position onwards, from the given data substrate.
 *
 * `version`s are stored as simple `UINT` values, prior to returning, they're validated.
 *
 * > This function internally calls {@link readUint}.
 *
 * @example
 * ```typescript
 * import { readVersion } from './src/read';
 *
 * console.log(readVersion(Uint8Array.of(0x01), 0));
 *   // [ 1, 1 ]
 * console.log(readVersion(Uint8Array.of(0x81, 0x00), 0));
 *   // [ 1, 2 ]
 * ```
 *
 * @example
 * ```typescript
 * import { readVersion } from './src/read';
 *
 * console.log(readVersion(Uint8Array.of(0x00), 0));
 *   // Error: Unrecognized version (expected 1 but found 0) at position 0
 * console.log(readVersion(Uint8Array.of(0x02), 0));
 *   // Error: Unrecognized version (expected 1 but found 2) at position 0
 * ```
 *
 * @param data - The data substrate to use.
 * @param index - The position from which to read.
 * @returns A pair, consisting of the read version, and the new data `index`.
 * @throws {@link !Error} when the version is unrecognized.
 */
export function readVersion(data: Uint8Array, index: number): [number, number] {
  const [version, idx]: [number, number] = readUint(data, index);
  if (1 !== version) {
    throw new Error(`Unrecognized version (expected 1 but found ${version}) at position ${index}`);
  }
  return [version, idx];
}

/**
 * Read a {@link Timestamp} from the given data substrate.
 *
 * {@link Timestamp | Timestamps} are stored as a sequence of "parts":
 *
 * 1. A {@link magicHeader | "magic header"} to indicate that this is a {@link Timestamp} data stream.
 * 2. The serialization format `version`, as a `UINT`.
 * 3. The serialized {@link FileHash}.
 * 4. The serialized {@link Tree}.
 *
 * This function will read the given data stream, and return the resulting {@link Timestamp} value.
 *
 * > This function internally calls {@link readLiteral}.
 * >
 * > This function internally calls {@link readVersion}.
 * >
 * > This function internally calls {@link readFileHash}.
 * >
 * > This function internally calls {@link readTree}.
 *
 * @example
 * ```typescript
 * import { read } from './src/read';
 *
 * console.log(read(Uint8Array.of(
 *   0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73,
 *   0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f,
 *   0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
 *   1,
 *   0x02,
 *   0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
 *   0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
 *   0x00,
 *   0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *   1,
 *   123,
 * )));
 *   // {
 *   //   version: 1,
 *   //   fileHash: { algorithm: 'sha1', value: Uint8Array(20) [ ... ] },
 *   //   tree: { edges: EdgeMap {}, leaves: LeafSet {} }
 *   // }
 * ```
 *
 * @example
 * ```typescript
 * import { read } from './src/read';
 *
 * console.log(read(Uint8Array.of(
 *   0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73,
 *   0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f,
 *   0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
 *   1,
 *   0x02,
 *   0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
 *   0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
 *   0x00,
 *   0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
 *   1,
 *   123,
 *   4,
 *   5,
 *   6,
 *   7,
 *   8,
 *   9,
 * )));
 *   // Error: Garbage at EOF
 * ```
 *
 * @param data - The data substrate to use.
 * @returns The read {@link Timestamp}.
 * @throws {@link !Error} when there's additional data past the {@link Timestamp}'s value.
 */
export function read(data: Uint8Array): Timestamp {
  const idx: number = readLiteral(data, 0, magicHeader)[1];
  const [version, idx2]: [number, number] = readVersion(data, idx);
  const [fileHash, idx3]: [FileHash, number] = readFileHash(data, idx2);
  const [tree, idx4]: [Tree, number] = readTree(data, idx3);

  if (data.length !== idx4) {
    throw new Error('Garbage at EOF');
  }

  return { version, fileHash, tree };
}
