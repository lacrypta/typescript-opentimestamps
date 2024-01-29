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
 * This module defines several useful utilities that don't necessarily fit anywhere else.
 *
 * @packageDocumentation
 * @module
 */

'use strict';

/**
 * Serialize the given {@link !Uint8Array} to a hex string.
 *
 * @example
 * ```typescript
 * console.log(uint8ArrayToHex(Uint8Array.of(1, 2, 3, 4, 5, 6)));  // 010203040506
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
 * console.log(uint8ArrayFromHex('010203040506'));  // Uint8Array(6) [ 1, 2, 3, 4, 5, 6 ]
 * ```
 *
 * @example
 * ```typescript
 * console.log(uint8ArrayFromHex('102030405')));   // Uncaught Error: Hex value should be of even length, found 9
 * console.log(uint8ArrayFromHex('102030405x')));  // Uncaught Error: Malformed hex string
 * ```
 *
 * @param hex - Hex string to deserialize.
 * @returns The deserialized data.
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
 * Determine whether two {@link !Uint8Array}s are indeed equal to each other.
 *
 * @example
 * ```typescript
 * console.log(uint8ArrayEquals(Uint8Array.of(), Uint8Array.of()));                // true
 * console.log(uint8ArrayEquals(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3)));  // true
 * console.log(uint8ArrayEquals(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4)));  // false
 * ```
 *
 * @param left - The first array to compare.
 * @param right - The second array to compare.
 * @returns `true` if both arrays are equal, `false` otherwise.
 */
export function uint8ArrayEquals(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.length === right.length && left.every((element: number, index: number): boolean => element === right[index])
  );
}

/**
 * Compare the given {@link !Uint8Array}s lexicographically.
 *
 * @example
 * ```typescript
 * console.log(uint8ArrayCompare(Uint8Array.of(), Uint8Array.of()));             //  0
 * console.log(uint8ArrayCompare(Uint8Array.of(1, 2, 3), Uint8Array.of()));      //  3
 * console.log(uint8ArrayCompare(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2)));  //  1
 * console.log(uint8ArrayCompare(Uint8Array.of(1), Uint8Array.of(1, 2)));        // -1
 * console.log(uint8ArrayCompare(Uint8Array.of(1), Uint8Array.of(1, 2, 3)));     // -2
 * ```
 *
 * @param left - The first array to compare.
 * @param right - The second array to compare.
 * @returns `0` if both arrays are equal, a positive `number` if the {@link left} array is bigger, a negative `number` otherwise.
 */
export function uint8ArrayCompare(left: Uint8Array, right: Uint8Array): number {
  for (let i: number = 0; i < left.length && i < right.length; i++) {
    if (left[i]! != right[i]!) {
      return left[i]! - right[i]!;
    }
  }
  return left.length - right.length;
}

// ref: https://stackoverflow.com/a/49129872
/**
 * Concatenate the given {@link !Uint8Array}s.
 *
 * @example
 * ```typescript
 * console.log(uint8ArrayConcat());                                    // Uint8Array(0) []
 * console.log(uint8ArrayConcat(Uint8Array.of(1, 2, 3)));              // Uint8Array(3) [ 1, 2, 3 ]
 * console.log(uint8ArrayConcat(Uint8Array.of(1), Uint8Array.of(2)));  // Uint8Array(2) [ 1, 2 ]
 * ```
 *
 * @param arrays - The arrays to concatenate.
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
 * console.log(uint8ArrayReversed(Uint8Array.of()));         // Uint8Array(0) []
 * console.log(uint8ArrayReversed(Uint8Array.of(1, 2, 3)));  // Uint8Array(3) [ 3, 2, 1 ]
 * ```
 *
 * @param array - The array to reverse.
 * @returns The reversed array.
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
 * fetchBody(new URL('http://example.org')).then((body: Uint8Array): void => {
 *   console.log(...body);
 * });  // 60 33 100 111 99 116 121 112 101 32 ... 62 10 60 47 104 116 109 108 62 10
 * ```
 *
 * @example
 * ```typescript
 * fetchBody(new URL('something://else')).catch((e: unknown): void => {
 *   console.log(e);
 * });  // TypeError: fetch failed ...
 * fetchBody(new URL('http://example.com')).catch((e: unknown): void => {
 *   console.log(e);
 * });  // TypeError: fetch failed ...
 * ```
 *
 * @param url - The {@link !URL} to fetch.
 * @param init - The {@link !fetch} options to use.
 * @returns The response body as a {@link Uint8Array}.
 * @throws {@link !Error} If there are errors performing the {@link !fetch} call.
 */
export async function fetchBody(url: URL, init?: RequestInit): Promise<Uint8Array> {
  try {
    const response: Response = await fetch(url, init);
    if (!response.ok || null === response.body) {
      throw new Error('Error retrieving response body');
    }
    // ref: https://stackoverflow.com/a/72718732
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
 * retrieveGetBody(new URL('http://example.org')).then((body: Uint8Array): void => {
 *   console.log(...body);
 * });  // 60 33 100 111 99 116 121 112 101 32 ... 62 10 60 47 104 116 109 108 62 10
 * ```
 *
 * @example
 * ```typescript
 * retrieveGetBody(new URL('something://else')).catch((e: unknown): void => {
 *   console.log(e);
 * });  // TypeError: fetch failed ...
 * retrieveGetBody(new URL('http://example.com')).catch((e: unknown) => {
 *   console.log(e);
 * });  // TypeError: fetch failed ...
 * ```
 *
 * @param url - The {@link !URL} to fetch.
 * @returns The response body as a {@link Uint8Array}.
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
 * retrievePostBody(new URL('http://example.org'), Uint8Array.of()).then((body: Uint8Array): void => {
 *   console.log(...body);
 * });  // 60 33 100 111 99 116 121 112 101 32 ... 62 10 60 47 104 116 109 108 62 10
 * ```
 *
 * @example
 * ```typescript
 * retrievePostBody(new URL('something://else'), Uint8Array.of()).catch((e: unknown): void => {
 *   console.log(e);
 * });  // TypeError: fetch failed ...
 * retrievePostBody(new URL('http://example.com'), Uint8Array.of()).catch((e: unknown): void => {
 *   console.log(e);
 * });  // TypeError: fetch failed ...
 * ```
 *
 * @param url - The {@link !URL} to fetch.
 * @param body - The `POST` body to send, as a {@link !Uint8Array}.
 * @returns The response body as a {@link Uint8Array}.
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
 * console.log(textEncoder);  // { encoding: 'utf-8' }
 * ```
 */
export const textEncoder: TextEncoder = new TextEncoder();

/**
 * A single {@link !TextDecoder} instance to avoid re-instantiating it each time.
 *
 * @example
 * ```typescript
 * console.log(textDecoder);  // TextDecoder { encoding: 'utf-8', fatal: false, ignoreBOM: false }
 * ```
 */
export const textDecoder: TextDecoder = new TextDecoder();

// ----------------------------------------------------------------------------------------------------------------------------------------
// -- API ---------------------------------------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------------------------------------------

/**
 * A namespace to collect type declarations for {@link MergeSet} and {@link MergeMap} usage.
 *
 */
// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace Merge {
  /**
   * The type of the callback that will transform an element into a string (implicitly defining what "equality" between elements means) in a {@link MergeSet} or equivalent keys for {@link MergeMap}s.
   *
   * @typeParam T - The type of the {@link MergeSet} contained elements or {@link MergeMap} keys.
   * @param key - The element to transform into a string for mapping purposes.
   * @returns The string representation of the given element.
   */
  export type ToKey<T> = (key: T) => string;

  /**
   * The type of the callback that will be used to combine two equivalent elements within the {@link MergeSet} or equivalent values in a {@link MergeMap}.
   *
   * @typeParam T - The type of the {@link MergeSet} contained elements or {@link MergeMap} values.
   * @param left - The already existing element in the {@link MergeSet} or value in the {@link MergeMap}.
   * @param right - The element one seeks to add to the {@link MergeSet} or the value one seeks to add to the {@link MergeMap}.
   * @returns The combined element to replace the already existing element or value.
   */
  export type Combine<T> = (left: T, right: T) => T;
}

/**
 * An iteration over the standard {@link !Set} generic class, that allows for identical elements to be identified and merged together.
 *
 * A `MergeSet` allows the user to specify _how_ two elements should be compared for equality, and _what_ to do when equal
 * elements are added to the same `MergeSet`.
 *
 * This is realized via the {@link toKey} and {@link combine} constructor parameters:
 *
 * - **{@link toKey}:** takes an elements and returns a `string` that represents it unequivocally (ie. two elements returning the same
 *   `string` will be taken to be equal themselves).
 * - **{@link combine}:** takes two elements and returns the result of _combining_ them into a single element (this is used to store a single
 *   copy of every element in the `MergeSet`)
 *
 * @example
 * ```typescript
 * import { Merge, MergeSet } from '@lacrypta/typescript-opentimestamps';
 *
 * const toKey: Merge.ToKey<string> = (key: string): string => key;
 * const combine: Merge.Combine<string> = (left: string, right: string): string => `${left}:${right}`;
 *
 * const aMergeSet: MergeSet<string> = new MergeSet<string>(toKey, combine);
 *
 * aMergeSet.add('a').add('a').add('b').add('c').add('d');
 * console.log(aMergeSet.values());  // [ 'a:a', 'b', 'c', 'd' ]
 * aMergeSet.remove('a');
 * console.log(aMergeSet.values());  // [ 'b', 'c', 'd' ]
 * console.log(aMergeSet.size());    // 3
 *
 * const anotherMergeSet: MergeSet<string> = new MergeSet<string>(toKey, combine);
 * anotherMergeSet.add('w').add('x').add('y').add('z');
 *
 * aMergeSet.incorporate(anotherMergeSet);
 * console.log(aMergeSet.values());  // [ 'b', 'c', 'd', 'w', 'x', 'y', 'z' ]
 * console.log(aMergeSet.size());    // 7
 * ```
 *
 * @typeParam V - The type of the contained elements.
 */
export class MergeSet<V> {
  /**
   * The {@link MergeSet} is implemented via a {@link !Record} that maps "keys" (derived using the {@link toKey} parameter) to actual values.
   *
   * This is the main storage mapping used to implement the {@link MergeSet}.
   *
   */
  private readonly mapping: Record<string, V>;

  /**
   * The callback that will transform an element into a `string` (implicitly defining what "equality" between elements means).
   *
   */
  private readonly toKey: Merge.ToKey<V>;

  /**
   * The callback that will be used to combine two equivalent elements within the {@link MergeSet}.
   *
   */
  private readonly combine: Merge.Combine<V>;

  /**
   * The {@link MergeSet} constructor.
   *
   * This constructor takes as parameters the key-generation and combination callbacks to use.
   *
   * @example
   * ```typescript
   * import { Merge, MergeSet } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<string> = (key: string): string => key;
   * const combine: Merge.Combine<string> = (left: string, right: string): string => `${left}:${right}`;
   *
   * const aMergeSet: MergeSet<string> = new MergeSet<string>(toKey, combine);
   * ```
   *
   * @typeParam V - The type of the contained elements.
   * @param toKey - The callback that will transform an element into a string (implicitly defining what "equality" between elements means).
   * @param combine - The callback that will be used to combine two equivalent elements within the {@link MergeSet}.
   */
  constructor(toKey: Merge.ToKey<V>, combine: Merge.Combine<V>) {
    this.mapping = {};
    this.toKey = toKey;
    this.combine = combine;
  }

  /**
   * Perform the addition "heavy-lifting" within a {@link MergeSet}.
   *
   * @param key - The `string` key to use (previously passed through {@link toKey}).
   * @param value - The actual value to add.
   * @returns The {@link MergeSet} instance, for chaining.
   */
  private doAdd(key: string, value: V): this {
    this.mapping[key] = key in this.mapping ? this.combine(this.mapping[key]!, value) : value;
    return this;
  }

  /**
   * Return the number of elements in the {@link MergeSet}.
   *
   * @example
   * ```typescript
   * import { Merge, MergeSet } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<string> = (key: string): string => key;
   * const combine: Merge.Combine<string> = (left: string, right: string): string => `${left}:${right}`;
   *
   * const aMergeSet: MergeSet<string> = new MergeSet<string>(toKey, combine);
   *
   * aMergeSet.add('a').add('a').add('b').add('c').add('d');
   * console.log(aMergeSet.size());    // 4
   * ```
   *
   * @returns The number of elements in the {@link MergeSet}.
   */
  public size(): number {
    return this.values().length;
  }

  /**
   * Return a list of _values_ stored in a {@link MergeSet}.
   *
   * @example
   * ```typescript
   * import { Merge, MergeSet } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<string> = (key: string): string => key;
   * const combine: Merge.Combine<string> = (left: string, right: string): string => `${left}:${right}`;
   *
   * const aMergeSet: MergeSet<string> = new MergeSet<string>(toKey, combine);
   *
   * aMergeSet.add('a').add('a').add('b').add('c').add('d');
   * console.log(aMergeSet.values());  // [ 'a:a', 'b', 'c', 'd' ]
   * ```
   *
   * @returns The list of values in the {@link MergeSet}.
   */
  public values(): V[] {
    return Object.values(this.mapping);
  }

  /**
   * Remove the given value from the {@link MergeSet}.
   *
   * @example
   * ```typescript
   * import { Merge, MergeSet } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<string> = (key: string): string => key;
   * const combine: Merge.Combine<string> = (left: string, right: string): string => `${left}:${right}`;
   *
   * const aMergeSet: MergeSet<string> = new MergeSet<string>(toKey, combine);
   *
   * aMergeSet.add('a').add('a').add('b').add('c').add('d');
   * console.log(aMergeSet.values());  // [ 'a:a', 'b', 'c', 'd' ]
   *
   * aMergeSet.remove('a');
   * console.log(aMergeSet.values());  // [ 'b', 'c', 'd' ]
   * ```
   *
   * @param value - The value to remove.
   * @returns The original {@link MergeSet} with the given {@link value} removed, for chaining.
   */
  public remove(value: V): this {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.mapping[this.toKey(value)];
    return this;
  }

  /**
   * Add the given value to the {@link MergeSet}.
   *
   * @example
   * ```typescript
   * import { Merge, MergeSet } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<string> = (key: string): string => key;
   * const combine: Merge.Combine<string> = (left: string, right: string): string => `${left}:${right}`;
   *
   * const aMergeSet: MergeSet<string> = new MergeSet<string>(toKey, combine);
   *
   * aMergeSet.add('a').add('a').add('b').add('c').add('d');
   * console.log(aMergeSet.values());  // [ 'a:a', 'b', 'c', 'd' ]
   *
   * aMergeSet.add('d');
   * console.log(aMergeSet.values());  // [ 'b', 'c', 'd' ]
   * ```
   *
   * @param value - The value to add to the {@link MergeSet}.
   * @returns The original {@link MergeSet} with the given {@link value} added, for chaining.
   */
  public add(value: V): this {
    return this.doAdd(this.toKey(value), value);
  }

  /**
   * Add _all_ elements of the given {@link MergeSet} to the current one.
   *
   * @example
   * ```typescript
   * import { Merge, MergeSet } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<string> = (key: string): string => key;
   * const combine: Merge.Combine<string> = (left: string, right: string): string => `${left}:${right}`;
   *
   * const aMergeSet: MergeSet<string> = new MergeSet<string>(toKey, combine);
   * aMergeSet.add('a').add('a').add('b').add('c').add('d');
   *
   * const anotherMergeSet: MergeSet<string> = new MergeSet<string>(toKey, combine);
   * anotherMergeSet.add('w').add('x').add('y').add('z');
   *
   * aMergeSet.incorporate(anotherMergeSet);
   * console.log(aMergeSet.values());  // [ 'a:a', 'b', 'c', 'd', 'w', 'x', 'y', 'z' ]
   * ```
   *
   * @param other - The {@link MergeSet} to incorporate into this one.
   * @returns The original {@link MergeSet} with the given other {@link MergeSet} incorporated, for chaining.
   */
  public incorporate(other: typeof this): this {
    Object.entries(other.mapping).forEach(([key, value]: [string, V]): void => {
      this.doAdd(key, value);
    });
    return this;
  }
}

/**
 * An iteration over the standard {@link !Map} generic class, that allows for identical keys to be identified and their associated values be merged together.
 *
 * A `MergeMap` allows the user to specify _how_ two keys should be compared for equality, and _what_ to do with the corresponding values when equal
 * keys are added to the same `MergeMap`.
 *
 * This is realized via the {@link toKey} and {@link combine} constructor parameters:
 *
 * - **{@link toKey}:** takes a key and returns a `string` that represents it unequivocally (ie. two keys returning the same
 *   `string` will be taken to be equal themselves).
 * - **{@link combine}:** takes two values and returns the result of _combining_ them into a single value (this is used to store a single
 *   copy of every key / value pair in the `MergeMap`)
 *
 * @example
 * ```typescript
 * import { Merge, MergeMap } from '@lacrypta/typescript-opentimestamps';
 *
 * const toKey: Merge.ToKey<number> = (key: number): string => (key % 10).toString();
 * const combine: Merge.Combine<string> = (left: string, right: string): string =>
 *   left < right ? `(${left}:${right})` : `(${right}:${left})`;
 *
 * const aMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
 *
 * aMergeMap.add(1, 'a').add(1, 'aa').add(2, 'b').add(3, 'c');
 * aMergeMap.add(4, 'd');
 *
 * console.log(aMergeMap.entries());  // [ [ 1, '(a:aa)' ], [ 2, 'b' ], [ 3, 'c' ], [ 4, 'd' ] ]
 * console.log(aMergeMap.keys());     // [ 1, 2, 3, 4 ]
 * console.log(aMergeMap.values());   // [ '(a:aa)', 'b', 'c', 'd' ]
 * console.log(aMergeMap.size());     // 4
 *
 * aMergeMap.remove(4);
 *
 * console.log(aMergeMap.entries());  // [ [ 1, '(a:aa)' ], [ 2, 'b' ], [ 3, 'c' ] ]
 * console.log(aMergeMap.keys());     // [ 1, 2, 3 ]
 * console.log(aMergeMap.values());   // [ '(a:aa)', 'b', 'c' ]
 * console.log(aMergeMap.size());     // 3
 *
 * const anotherMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
 * anotherMergeMap.add(1, 'w').add(2, 'x').add(3, 'y').add(4, 'z');
 * aMergeMap.incorporate(anotherMergeMap);
 *
 * console.log(aMergeMap.entries());  // [ [ 1, '((a:aa):w)' ], [ 2, '(b:x)' ], [ 3, '(c:y)' ], [ 4, 'z' ] ]
 * console.log(aMergeMap.keys());     // [ 1, 2, 3, 4 ]
 * console.log(aMergeMap.values());   // [ '((a:aa):w)', '(b:x)', '(c:y)', 'z' ]
 * console.log(aMergeMap.size());     // 4
 * ```
 *
 * @typeParam K - The type of the contained keys.
 * @typeParam V - The type of the contained values.
 */
export class MergeMap<K, V> {
  /**
   * The {@link MergeSet} is implemented via a pair of {@link !Record}s; the first one maps "keys" (derived using the {@link toKey} parameter) to actual keys.
   *
   * This is the main key-mapping used to implement the {@link MergeMap}.
   *
   */
  private readonly keySet: Record<string, K>;

  /**
   * The {@link MergeSet} is implemented via a pair of {@link !Record}s; the second one maps "keys" (derived using the {@link toKey} parameter) to actual values.
   *
   * This is the main value-mapping used to implement the {@link MergeMap}.
   *
   */
  private readonly mapping: Record<string, V>;

  /**
   * The callback that will transform a key into a `string` (implicitly defining what "equality" between keys means).
   *
   */
  private readonly toKey: Merge.ToKey<K>;

  /**
   * The callback that will be used to combine two equivalent values within the {@link MergeMap}.
   *
   */
  private readonly combine: Merge.Combine<V>;

  /**
   * The {@link MergeMap} constructor.
   *
   * This constructor takes as parameters the key-generation and combination callbacks to use.
   *
   * @example
   * ```typescript
   * import { Merge, MergeMap } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<number> = (key: number): string => (key % 10).toString();
   * const combine: Merge.Combine<string> = (left: string, right: string): string =>
   *   left < right ? `(${left}:${right})` : `(${right}:${left})`;
   *
   * const aMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
   * ```
   *
   * @typeParam K - The type of the contained keys.
   * @typeParam V - The type of the contained values.
   * @param toKey - The callback that will transform a key into a string (implicitly defining what "equality" between keys means).
   * @param combine - The callback that will be used to combine two equivalent values within the {@link MergeMap}.
   */
  constructor(toKey: Merge.ToKey<K>, combine: Merge.Combine<V>) {
    this.keySet = {};
    this.mapping = {};
    this.toKey = toKey;
    this.combine = combine;
  }

  /**
   * Perform the addition "heavy-lifting" within a {@link MergeMap}.
   *
   * @param key - The key to use.
   * @param value - The actual value to add.
   * @returns The {@link MergeMap} instance, for chaining.
   */
  private doAdd(key: K, value: V): this {
    const sKey: string = this.toKey(key);
    this.keySet[sKey] = key;
    this.mapping[sKey] = sKey in this.mapping ? this.combine(this.mapping[sKey]!, value) : value;
    return this;
  }

  /**
   * Return the number of elements in the {@link MergeMap}.
   *
   * @example
   * ```typescript
   * import { Merge, MergeMap } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<number> = (key: number): string => (key % 10).toString();
   * const combine: Merge.Combine<string> = (left: string, right: string): string =>
   *   left < right ? `(${left}:${right})` : `(${right}:${left})`;
   *
   * const aMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
   *
   * aMergeMap.add(1, 'a').add(1, 'aa').add(2, 'b').add(3, 'c');
   *
   * console.log(aMergeMap.size());  // 3
   * ```
   *
   * @returns The number of elements in the {@link MergeMap}.
   */
  public size(): number {
    return this.values().length;
  }

  /**
   * Return a list of _Keys_ stored in a {@link MergeMap}.
   *
   * @example
   * ```typescript
   * import { Merge, MergeMap } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<number> = (key: number): string => (key % 10).toString();
   * const combine: Merge.Combine<string> = (left: string, right: string): string =>
   *   left < right ? `(${left}:${right})` : `(${right}:${left})`;
   *
   * const aMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
   *
   * aMergeMap.add(1, 'a').add(1, 'aa').add(2, 'b').add(3, 'c');
   *
   * console.log(aMergeMap.keys());  // [ 1, 2, 3 ]
   * ```
   *
   * @returns The list of keys in the {@link MergeMap}.
   */
  public keys(): K[] {
    return Object.values(this.keySet);
  }

  /**
   * Return a list of _values_ stored in a {@link MergeMap}.
   *
   * @example
   * ```typescript
   * import { Merge, MergeMap } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<number> = (key: number): string => (key % 10).toString();
   * const combine: Merge.Combine<string> = (left: string, right: string): string =>
   *   left < right ? `(${left}:${right})` : `(${right}:${left})`;
   *
   * const aMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
   *
   * aMergeMap.add(1, 'a').add(1, 'aa').add(2, 'b').add(3, 'c');
   *
   * console.log(aMergeMap.values());  // [ '(a:aa)', 'b', 'c' ]
   * ```
   *
   * @returns The list of values in the {@link MergeMap}.
   */
  public values(): V[] {
    return Object.values(this.mapping);
  }

  /**
   * Return a list of _entries_ (ie. key / value pairs) stored in a {@link MergeMap}.
   *
   * @example
   * ```typescript
   * import { Merge, MergeMap } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<number> = (key: number): string => (key % 10).toString();
   * const combine: Merge.Combine<string> = (left: string, right: string): string =>
   *   left < right ? `(${left}:${right})` : `(${right}:${left})`;
   *
   * const aMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
   *
   * aMergeMap.add(1, 'a').add(1, 'aa').add(2, 'b').add(3, 'c');
   *
   * console.log(aMergeMap.entries());  // [ [ 1, '(a:aa)' ], [ 2, 'b' ], [ 3, 'c' ] ]
   * ```
   *
   * @returns The list of entries in the {@link MergeMap}.
   */
  public entries(): [K, V][] {
    return this.keys().map((key: K): [K, V] => [key, this.mapping[this.toKey(key)]!]);
  }

  /**
   * Remove the given key from the {@link MergeMap}.
   *
   * @example
   * ```typescript
   * import { Merge, MergeMap } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<number> = (key: number): string => (key % 10).toString();
   * const combine: Merge.Combine<string> = (left: string, right: string): string =>
   *   left < right ? `(${left}:${right})` : `(${right}:${left})`;
   *
   * const aMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
   *
   * aMergeMap.add(1, 'a').add(1, 'aa').add(2, 'b').add(3, 'c').add(4, 'd');
   * console.log(aMergeMap.entries());  // [ [ 1, '(a:aa)' ], [ 2, 'b' ], [ 3, 'c' ], [ 4, 'd' ] ]
   *
   * aMergeMap.remove(4);
   * console.log(aMergeMap.entries());  // [ [ 1, '(a:aa)' ], [ 2, 'b' ], [ 3, 'c' ] ]
   * ```
   *
   * @param key - The key to remove.
   * @returns The original {@link MergeMap} with the given {@link key} removed, for chaining.
   */
  public remove(key: K): this {
    const sKey: string = this.toKey(key);
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.mapping[sKey];
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.keySet[sKey];
    return this;
  }

  /**
   * Add the given key / value pair to the {@link MergeMap}.
   *
   * @example
   * ```typescript
   * import { Merge, MergeMap } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<number> = (key: number): string => (key % 10).toString();
   * const combine: Merge.Combine<string> = (left: string, right: string): string =>
   *   left < right ? `(${left}:${right})` : `(${right}:${left})`;
   *
   * const aMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
   *
   * aMergeMap.add(1, 'a').add(1, 'aa').add(2, 'b').add(3, 'c');
   * console.log(aMergeMap.entries());  // [ [ 1, '(a:aa)' ], [ 2, 'b' ], [ 3, 'c' ] ]
   *
   * aMergeMap.add(4, 'd');
   * console.log(aMergeMap.entries());  // [ [ 1, '(a:aa)' ], [ 2, 'b' ], [ 3, 'c' ], [ 4, 'd' ] ]
   * ```
   *
   * @param key - The key to add to the {@link MergeMap}.
   * @param value - The value to add to the {@link MergeMap}.
   * @returns The original {@link MergeMap} with the given {@link key} / {@link value} pair added, for chaining.
   */
  public add(key: K, value: V): this {
    return this.doAdd(key, value);
  }

  /**
   * Add _all_ key / value pairs of the given {@link MergeMap} to the current one.
   *
   * @example
   * ```typescript
   * import { Merge, MergeMap } from '@lacrypta/typescript-opentimestamps';
   *
   * const toKey: Merge.ToKey<number> = (key: number): string => (key % 10).toString();
   * const combine: Merge.Combine<string> = (left: string, right: string): string =>
   *   left < right ? `(${left}:${right})` : `(${right}:${left})`;
   *
   * const aMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
   * aMergeMap.add(1, 'a').add(1, 'aa').add(2, 'b').add(3, 'c');
   *
   * const anotherMergeMap: MergeMap<number, string> = new MergeMap<number, string>(toKey, combine);
   * anotherMergeMap.add(1, 'w').add(2, 'x').add(3, 'y').add(4, 'z');
   *
   * aMergeMap.incorporate(anotherMergeMap);
   * console.log(aMergeMap.entries());  // [ [ 1, '((a:aa):w)' ], [ 2, '(b:x)' ], [ 3, '(c:y)' ], [ 4, 'z' ] ]
   * ```
   *
   * @param other - The {@link MergeMap} to incorporate into this one.
   * @returns The original {@link MergeMap} with the given other {@link MergeMap} incorporated, for chaining.
   */
  public incorporate(other: typeof this): this {
    other.entries().forEach(([key, value]: [K, V]): void => {
      this.doAdd(key, value);
    });
    return this;
  }
}
