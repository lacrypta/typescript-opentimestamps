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
 * This module defines several useful utilities that don't necessarily fit anywhere else.
 *
 * @packageDocumentation
 * @module
 */

/**
 * Serialize the given {@link !Uint8Array} to a hex string.
 *
 * @example
 * ```typescript
 * import { uint8ArrayToHex } from './src/utils';
 *
 * console.log(uint8ArrayToHex(Uint8Array.of(1, 2, 3, 4, 5, 6)));
 *   // 010203040506
 * ```
 *
 * @param data - Data to serialize as hex.
 * @returns The resulting hex string.
 */
export function uint8ArrayToHex(data: Uint8Array): string {
  return data
    .reduce((result: string, value: number): string => result + value.toString(16).padStart(2, '0'), '')
    .toLowerCase();
}

/**
 * Deserialize the given hex string into a {@link !Uint8Array}.
 *
 * @example
 * ```typescript
 * import { uint8ArrayFromHex } from './src/utils';
 *
 * console.log(uint8ArrayFromHex('010203040506'));
 *   // Uint8Array(6) [ 1, 2, 3, 4, 5, 6 ]
 * ```
 *
 * @example
 * ```typescript
 * import { uint8ArrayFromHex } from './src/utils';
 *
 * console.log(uint8ArrayFromHex('102030405'));
 *   // Uncaught Error: Hex value should be of even length, found 9
 * console.log(uint8ArrayFromHex('102030405x'));
 *   // Uncaught Error: Malformed hex string
 * ```
 *
 * @param hex - Hex string to deserialize.
 * @returns The deserialized {@link !Uint8Array}.
 * @throws {@link !Error} if the given hex string length is odd.
 * @throws {@link !Error} if the given hex string contains non-hexadecimal characters.
 */
export function uint8ArrayFromHex(hex: string): Uint8Array {
  if (hex.length % 2) {
    throw new Error(`Hex value should be of even length, found ${hex.length}`);
  }
  return Uint8Array.from(
    (hex.match(/../g) ?? []).map((pair: string): number => {
      if (!pair.match(/^[0-9a-f]{2}$/i)) {
        throw new Error('Malformed hex string');
      }
      return Number.parseInt(pair, 16);
    }),
  );
}

/**
 * Serialize the given {@link !Uint8Array} to a base64 string.
 *
 * @example
 * ```typescript
 * import { uint8ArrayToBase64 } from './src/utils';
 *
 * console.log(uint8ArrayToBase64(Uint8Array.of(1, 2, 3, 4, 5, 6)));
 *   // AQIDBAUG
 * ```
 *
 * @param data - Data to serialize as base64.
 * @returns The resulting base64 string.
 */
export function uint8ArrayToBase64(data: Uint8Array): string {
  let sData: string = '';
  data.forEach((x: number): void => {
    sData += String.fromCharCode(x);
  });
  return btoa(sData);
}

/**
 * Deserialize the given base64 string into a {@link !Uint8Array}.
 *
 * @example
 * ```typescript
 * import { uint8ArrayFromBase64 } from './src/utils';
 *
 * console.log(uint8ArrayFromBase64('AQIDBAUG'));
 *   // Uint8Array(6) [ 1, 2, 3, 4, 5, 6 ]
 * ```
 *
 * @example
 * ```typescript
 * import { uint8ArrayFromBase64 } from './src/utils';
 *
 * console.log(uint8ArrayFromBase64('AQIDBAUG['));
 *   // DOMException [InvalidCharacterError]: Invalid character
 *
 * console.log(uint8ArrayFromBase64('AQIDBAUGa'));
 *   // DOMException [InvalidCharacterError]: The string to be decoded is not correctly encoded.
 * ```
 *
 * @param base64 - Base64 string to deserialize.
 * @returns The deserialized {@link !Uint8Array}.
 * @throws {@link !DOMException} if the given base64 string contains invalid characters.
 * @throws {@link !DOMException} if the given base64 string is not correctly encoded.
 */
export function uint8ArrayFromBase64(base64: string): Uint8Array {
  return Uint8Array.from(atob(base64), (c: string): number => c.charCodeAt(0));
}

/**
 * Determine whether two {@link !Uint8Array | Uint8Arrays} are indeed equal to each other.
 *
 * @example
 * ```typescript
 * import { uint8ArrayEquals } from './src/utils';
 *
 * console.log(uint8ArrayEquals(Uint8Array.of(), Uint8Array.of()));
 *   // true
 * console.log(uint8ArrayEquals(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3)));
 *   // true
 * console.log(uint8ArrayEquals(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4)));
 *   // false
 * ```
 *
 * @param left - The first {@link !Uint8Array | array} to compare.
 * @param right - The second {@link !Uint8Array | array} to compare.
 * @returns `true` if both {@link !Uint8Array | arrays} are equal, `false` otherwise.
 */
export function uint8ArrayEquals(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.length === right.length && left.every((element: number, index: number): boolean => element === right[index])
  );
}

/**
 * Compare the given {@link !Uint8Array | Uint8Arrays} lexicographically.
 *
 * @example
 * ```typescript
 * import { uint8ArrayCompare } from './src/utils';
 *
 * console.log(uint8ArrayCompare(Uint8Array.of(), Uint8Array.of()));
 *   // 0
 * console.log(uint8ArrayCompare(Uint8Array.of(1, 2, 3), Uint8Array.of()));
 *   // 3
 * console.log(uint8ArrayCompare(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2)));
 *   // 1
 * console.log(uint8ArrayCompare(Uint8Array.of(1), Uint8Array.of(1, 2)));
 *   // -1
 * console.log(uint8ArrayCompare(Uint8Array.of(1), Uint8Array.of(1, 2, 3)));
 *   // -2
 * ```
 *
 * @param left - The first {@link !Uint8Array | array} to compare.
 * @param right - The second {@link !Uint8Array | array} to compare.
 * @returns `0` if both {@link !Uint8Array | arrays} are equal, a positive number if the `left` {@link !Uint8Array | array} is bigger, a negative number otherwise.
 */
export function uint8ArrayCompare(left: Uint8Array, right: Uint8Array): number {
  for (let i: number = 0; i < left.length && i < right.length; i++) {
    if (left[i]! != right[i]!) {
      return left[i]! - right[i]!;
    }
  }
  return left.length - right.length;
}

/**
 * Concatenate the given {@link !Uint8Array | Uint8Arrays}.
 *
 * @example
 * ```typescript
 * import { uint8ArrayConcat } from './src/utils';
 *
 * console.log(uint8ArrayConcat());
 *   // Uint8Array(0) []
 * console.log(uint8ArrayConcat(Uint8Array.of(1, 2, 3)));
 *   // Uint8Array(3) [ 1, 2, 3 ]
 * console.log(uint8ArrayConcat(Uint8Array.of(1), Uint8Array.of(2)));
 *   // Uint8Array(2) [ 1, 2 ]
 * ```
 *
 * @see https://stackoverflow.com/a/49129872
 * @param arrays - The {@link !Uint8Array | arrays} to concatenate.
 * @returns The resulting concatenated {@link !Uint8Array}.
 */
export function uint8ArrayConcat(...arrays: Uint8Array[]): Uint8Array {
  const result: Uint8Array = new Uint8Array(
    arrays
      .map((item: Uint8Array): number => item.length)
      .reduce((prev: number, curr: number): number => prev + curr, 0),
  );
  let offset = 0;
  arrays.forEach((item: Uint8Array): void => {
    result.set(item, offset);
    offset += item.length;
  });
  return result;
}

/**
 * Return the reversal of the give {@link !Uint8Array} as a new {@link !Uint8Array}.
 *
 * @example
 * ```typescript
 * import { uint8ArrayReversed } from './src/utils';
 *
 * console.log(uint8ArrayReversed(Uint8Array.of()));
 *   // Uint8Array(0) []
 * console.log(uint8ArrayReversed(Uint8Array.of(1, 2, 3)));
 *   // Uint8Array(3) [ 3, 2, 1 ]
 * ```
 *
 * @param array - The {@link !Uint8Array | array} to reverse.
 * @returns The reversed {@link !Uint8Array}.
 */
export function uint8ArrayReversed(array: Uint8Array): Uint8Array {
  const result: Uint8Array = new Uint8Array(array.length);
  array.forEach((value: number, index: number): void => {
    result.set([value], array.length - index - 1);
  });
  return result;
}

/**
 * Perform a {@link !fetch} request with the given parameters, and return the response body as a {@link !Uint8Array}.
 *
 * @example
 * ```typescript
 * import { fetchBody } from './src/utils';
 *
 * fetchBody(new URL('http://example.org'))
 *   .then((body: Uint8Array): void => { console.log(...body); });
 *   // 60 33 100 111 99 116 121 112 101 32 ... 62 10 60 47 104 116 109 108 62 10
 * ```
 *
 * @example
 * ```typescript
 * import { fetchBody } from './src/utils';
 *
 * fetchBody(new URL('something://else'))
 *   .catch((e: unknown): void => { console.log(e); });
 *   // TypeError: fetch failed ...
 * fetchBody(new URL('http://example.com'))
 *   .catch((e: unknown): void => { console.log(e); });
 *   // TypeError: fetch failed ...
 * ```
 *
 * @see https://stackoverflow.com/a/72718732
 * @param url - The {@link !URL} to fetch.
 * @param init - The {@link !fetch} options to use.
 * @returns The response body as a {@link !Uint8Array}.
 * @throws {@link !Error} If there are errors performing the {@link !fetch} call.
 */
export async function fetchBody(url: URL, init?: RequestInit): Promise<Uint8Array> {
  try {
    const response: Response = await fetch(url, init);
    if (!response.ok || null === response.body) {
      throw new Error('Error retrieving response body');
    }
    return new Uint8Array(await new Response(response.body).arrayBuffer());
  } catch (e: unknown) {
    if (e instanceof Error) {
      throw e;
    } else {
      throw new Error('Unknown fetch() error');
    }
  }
}

/**
 * Perform a `GET` request with the standard `opentimestamps` headers and retrieve the response body as a {@link !Uint8Array}.
 *
 * @example
 * ```typescript
 * import { retrieveGetBody } from './src/utils';
 *
 * retrieveGetBody(new URL('http://example.org'))
 *   .then((body: Uint8Array): void => { console.log(...body); })
 *   // 60 33 100 111 99 116 121 112 101 32 ... 62 10 60 47 104 116 109 108 62 10
 * ```
 *
 * @example
 * ```typescript
 * import { retrieveGetBody } from './src/utils';
 *
 * retrieveGetBody(new URL('something://else'))
 *   .catch((e: unknown): void => { console.log(e); });
 *   // TypeError: fetch failed ...
 * retrieveGetBody(new URL('http://example.com'))
 *   .catch((e: unknown) => { console.log(e); });
 *   // TypeError: fetch failed ...
 * ```
 *
 * @param url - The {@link !URL} to fetch.
 * @returns The response body as a {@link !Uint8Array}.
 * @throws {@link !Error} If there are errors performing the {@link !fetch} call.
 */
export async function retrieveGetBody(url: URL): Promise<Uint8Array> {
  return await fetchBody(url, {
    method: 'GET',
    headers: {
      Accept: 'application/vnd.opentimestamps.v1',
      'User-Agent': 'typescript-opentimestamps',
    },
  });
}

/**
 * Perform a `POST` request with the standard `opentimestamps` headers and retrieve the response body as a {@link !Uint8Array}.
 *
 * @example
 * ```typescript
 * import { retrievePostBody } from './src/utils';
 *
 * retrievePostBody(
 *   new URL('http://example.org'),
 *   Uint8Array.of(),
 * ).then((body: Uint8Array): void => { console.log(...body); });
 *   // 60 33 100 111 99 116 121 112 101 32 ... 62 10 60 47 104 116 109 108 62 10
 * ```
 *
 * @example
 * ```typescript
 * import { retrievePostBody } from './src/utils';
 *
 * retrievePostBody(
 *   new URL('something://else'),
 *   Uint8Array.of(),
 * ).catch((e: unknown): void => { console.log(e); });
 *   // TypeError: fetch failed ...
 * retrievePostBody(
 *   new URL('http://example.com'),
 *   Uint8Array.of(),
 * ).catch((e: unknown): void => { console.log(e); });
 *   // TypeError: fetch failed ...
 * ```
 *
 * @param url - The {@link !URL} to fetch.
 * @param body - The `POST` body to send, as a {@link !Uint8Array}.
 * @returns The response body as a {@link !Uint8Array}.
 * @throws {@link !Error} If there are errors performing the {@link !fetch} call.
 */
export async function retrievePostBody(url: URL, body: Uint8Array): Promise<Uint8Array> {
  return await fetchBody(url, {
    method: 'POST',
    headers: {
      Accept: 'application/vnd.opentimestamps.v1',
      'User-Agent': 'typescript-opentimestamps',
    },
    body,
  });
}

/**
 * A single {@link !TextEncoder} instance to avoid re-instantiating it each time.
 *
 * @example
 * ```typescript
 * import { textEncoder } from './src/utils';
 *
 * console.log(textEncoder);
 *   // { encoding: 'utf-8' }
 * ```
 */
export const textEncoder: TextEncoder = new TextEncoder();

/**
 * A single {@link !TextDecoder} instance to avoid re-instantiating it each time.
 *
 * @example
 * ```typescript
 * import { textDecoder } from './src/utils';
 *
 * console.log(textDecoder);
 *   // TextDecoder { encoding: 'utf-8', fatal: false, ignoreBOM: false }
 * ```
 */
export const textDecoder: TextDecoder = new TextDecoder();
