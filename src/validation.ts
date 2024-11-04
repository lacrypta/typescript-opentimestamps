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
 * This module exposes validation functions.
 *
 * @packageDocumentation
 * @module
 */

import type { FileHash, Leaf, Op, Timestamp, Tree } from './types';

import { EdgeMap, LeafSet } from './internals';

/**
 * Validate that the given datum is a non-`null` object.
 *
 * @example
 * ```typescript
 * import { validateNonNullObject } from './src/validation';
 *
 * console.log(validateNonNullObject({}));
 *   // {}
 * ```
 *
 * @example
 * ```typescript
 * import { validateNonNullObject } from './src/validation';
 *
 * console.log(validateNonNullObject(123));
 *   // Error: Expected non-null object
 * console.log(validateNonNullObject(null));
 *   // Error: Expected non-null object
 * ```
 *
 * @param obj - Data to validate.
 * @returns The validated object.
 * @throws {@link !Error} If the given datum is not a non-`null` object.
 */
export function validateNonNullObject(obj: unknown): object {
  if ('object' !== typeof obj || null === obj) {
    throw new Error('Expected non-null object');
  }
  return obj;
}

/**
 * Validate that the given datum is an {@link !Uint8Array}.
 *
 * > This function internally calls {@link validateNonNullObject}.
 *
 * @example
 * ```typescript
 * import { validateUint8Array } from './src/validation';
 *
 * console.log(validateUint8Array(Uint8Array.of(1, 2, 3)));
 *   // Uint8Array(3) [ 1, 2, 3 ]
 * ```
 *
 * @example
 * ```typescript
 * import { validateUint8Array } from './src/validation';
 *
 * console.log(validateUint8Array({}));
 *   // Error: Expected Uint8Array
 * ```
 *
 * @param array - Data to validate.
 * @returns The validated {@link !Uint8Array}.
 * @throws {@link !Error} If the given datum is not an {@link !Uint8Array}.
 */
export function validateUint8Array(array: unknown): Uint8Array {
  const obj: object = validateNonNullObject(array);
  if (obj.constructor !== Uint8Array) {
    throw new Error('Expected Uint8Array');
  }
  return array as Uint8Array;
}

/**
 * Validate that the given datum is an {@link !URL}.
 *
 * > This function internally calls {@link validateNonNullObject}.
 *
 * @example
 * ```typescript
 * import { validateURL } from './src/validation';
 *
 * console.log(validateURL(new URL('http://example.com')));
 *   // URL { ... }
 * ```
 *
 * @example
 * ```typescript
 * import { validateURL } from './src/validation';
 *
 * console.log(validateURL({}));
 *   // Error: Expected URL
 * ```
 *
 * @param url - Data to validate.
 * @returns The validated {@link !URL}.
 * @throws {@link !Error} If the given datum is not an {@link !URL}.
 */
export function validateURL(url: unknown): URL {
  const obj: object = validateNonNullObject(url);
  if (obj.constructor !== URL) {
    throw new Error('Expected URL');
  }
  return url as URL;
}

/**
 * Validate that the given datum is a valid calendar {@link !URL} `string`.
 *
 * Calendar {@link !URL | URLs} need to abide by the following [ABNF](https://en.wikipedia.org/wiki/Augmented_Backus%E2%80%93Naur_form):
 *
 * ```ini
 * url = %s"https://"
 *       1*(ALPHA / DIGIT / "-" / "." / "_") [ ":" 1*DIGIT ]
 *       *( "/" 1*( ALPHA / DIGIT / "-" / "." / "_" / ":" ) )
 *       [ "/" ]
 * ```
 *
 * Or equivalently, to the following {@link !RegExp}:
 *
 * ```perl
 * /^https:\\/\\/[a-zA-Z0-9_.-]+(:[0-9]+)?(\\/[a-zA-Z0-9_.:-]+)*\\/?$/
 * ```
 *
 * @example
 * ```typescript
 * import { validateCalendarUrl } from './src/validation';
 *
 * console.log(validateCalendarUrl('https://www.example.com/something'));
 *   // https://www.example.com/something
 * ```
 *
 * @example
 * ```typescript
 * import { validateCalendarUrl } from './src/validation';
 *
 * console.log(validateCalendarUrl(123));
 *   // Error: Expected string
 * console.log(validateCalendarUrl('http://www.example.com'));
 *   // Error: Invalid URL
 * console.log(validateCalendarUrl('https://www.example.com?some=thing'));
 *   // Error: Invalid URL
 * ```
 *
 * @param url - Data to validate.
 * @returns The validated `string`.
 * @throws {@link !Error} If the given datum is not a `string`.
 * @throws {@link !Error} If the given datum does not conform to the conditions given above.
 */
export function validateCalendarUrl(url: unknown): string {
  if ('string' !== typeof url) {
    throw new Error('Expected string');
  }
  if (!/^https:\/\/[a-zA-Z0-9_.-]+(:[0-9]+)?(\/[a-zA-Z0-9_.:-]+)*\/?$/.test(url)) {
    throw new Error('Invalid URL');
  }
  return url;
}

/**
 * Validate that the given datum is a non-negative _safe_ integer.
 *
 * @example
 * ```typescript
 * import { validateNonNegativeInteger } from './src/validation';
 *
 * console.log(validateNonNegativeInteger(1234));
 *   // 1234
 * ```
 *
 * @example
 * ```typescript
 * import { validateNonNegativeInteger } from './src/validation';
 *
 * console.log(validateNonNegativeInteger('something'));
 *   // Error: Expected number
 * console.log(validateNonNegativeInteger(12.34));
 *   // Error: Expected safe-integer
 * console.log(validateNonNegativeInteger(NaN));
 *   // Error: Expected safe-integer
 * console.log(validateNonNegativeInteger(-1234));
 *   // Error: Expected non-negative integer
 * ```
 *
 * @param num - Data to validate.
 * @returns The validated `number`.
 * @throws {@link !Error} If the given datum is not a `number`.
 * @throws {@link !Error} If the given datum is not a _safe_ integer (as per {@link !Number.isSafeInteger}).
 * @throws {@link !Error} If the given datum is negative.
 */
export function validateNonNegativeInteger(num: unknown): number {
  if ('number' !== typeof num) {
    throw new Error('Expected number');
  }
  if (!Number.isSafeInteger(num)) {
    throw new Error('Expected safe-integer');
  }
  if (num < 0) {
    throw new Error('Expected non-negative integer');
  }
  return num;
}

/**
 * Validate that the given `string` is indeed one of the given options.
 *
 * @example
 * ```typescript
 * import { validateOneOfStrings } from './src/validation';
 *
 * console.log(validateOneOfStrings('something', ['something', 'else', 'entirely']));
 *   // something
 * ```
 *
 * @example
 * ```typescript
 * import { validateOneOfStrings } from './src/validation';
 *
 * console.log(validateOneOfStrings('something', ['else', 'entirely']));
 *   // Error: Expected one of [else, entirely]
 * ```
 *
 * @param value - `string` to validate.
 * @param options - Possible options.
 * @returns The validated `string` value.
 * @throws {@link !Error} If the given datum is not among the options provided.
 */
export function validateOneOfStrings(value: string, options: string[]): string {
  if (!options.includes(value)) {
    throw new Error(`Expected one of [${options.join(', ')}]`);
  }
  return value;
}

/**
 * Validate that the given `object` has a well-formed `.type` key.
 *
 * @example
 * ```typescript
 * import { validateObjectHasTypeKey } from './src/validation';
 *
 * console.log(validateObjectHasTypeKey({ type: 'something' }));
 *   // { type: 'something' }
 * ```
 *
 * @example
 * ```typescript
 * import { validateObjectHasTypeKey } from './src/validation';
 *
 * console.log(validateObjectHasTypeKey({}));
 *   // Error: Expected key .type
 * console.log(validateObjectHasTypeKey({ type: 123 }));
 *   // Error: Expected string
 * ```
 *
 * @param obj - `object` to validate.
 * @returns The validated `object`.
 * @throws {@link !Error} If the given `object` has no `.type` key.
 * @throws {@link !Error} If `obj.type` is not a `string`.
 */
export function validateObjectHasTypeKey(obj: object): { type: string } {
  if (!('type' in obj)) {
    throw new Error('Expected key .type');
  }
  if ('string' !== typeof obj.type) {
    throw new Error('Expected string');
  }
  return obj as { type: string };
}

/**
 * Validate that the given `object` has a well-formed `.height` key.
 *
 * > This function internally calls {@link validateNonNegativeInteger}.
 *
 * @example
 * ```typescript
 * import { validateObjectHasHeightKey } from './src/validation';
 *
 * console.log(validateObjectHasHeightKey({ height: 123 }));
 *   // { height: 123 }
 * ```
 *
 * @example
 * ```typescript
 * import { validateObjectHasHeightKey } from './src/validation';
 *
 * console.log(validateObjectHasHeightKey({}));
 *   // Error: Expected key .height
 * ```
 *
 * @param obj - `object` to validate.
 * @returns The validated `object`.
 * @throws {@link !Error} If the given `object` has no `.height` key.
 */
export function validateObjectHasHeightKey(obj: object): { height: number } {
  if (!('height' in obj)) {
    throw new Error('Expected key .height');
  }
  validateNonNegativeInteger(obj.height);
  return obj as { height: number };
}

/**
 * Validate that the given `object` has a well-formed `.url` key.
 *
 * > This function internally calls {@link validateURL}.
 *
 * @example
 * ```typescript
 * import { validateObjectHasUrlKey } from './src/validation';
 *
 * console.log(validateObjectHasUrlKey({ url: new URL('https://www.example.com') }));
 *   // { url: URL { ... } }
 * ```
 *
 * @example
 * ```typescript
 * import { validateObjectHasUrlKey } from './src/validation';
 *
 * console.log(validateObjectHasUrlKey({}));
 *   // Error: Expected key .url
 * ```
 *
 * @param obj - `object` to validate.
 * @returns The validated `object`.
 * @throws {@link !Error} If the given `object` has no `.url` key.
 */
export function validateObjectHasUrlKey(obj: object): { url: URL } {
  if (!('url' in obj)) {
    throw new Error('Expected key .url');
  }
  validateURL(obj.url);
  return obj as { url: URL };
}

/**
 * Validate that the given `object` has a well-formed `.header` key.
 *
 * > This function internally calls {@link validateUint8Array}.
 *
 * @example
 * ```typescript
 * import { validateObjectHasHeaderKey } from './src/validation';
 *
 * console.log(validateObjectHasHeaderKey({ header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8) }));
 *   // { header: Uint8Array(8) [ 1, 2, 3, 4, 5, 6, 7, 8 ] }
 * ```
 *
 * @example
 * ```typescript
 * import { validateObjectHasHeaderKey } from './src/validation';
 *
 * console.log(validateObjectHasHeaderKey({}));
 *   // Error: Expected key .header
 * console.log(validateObjectHasHeaderKey({ header: Uint8Array.of(1, 2, 3, 4) }));
 *   // Error: Expected 8 byte header
 * ```
 *
 * @param obj - `object` to validate.
 * @returns The validated `object`.
 * @throws {@link !Error} If the given `object` has no `.header` key.
 * @throws {@link !Error} If `obj.header`'s length is not 8.
 */
export function validateObjectHasHeaderKey(obj: object): { header: Uint8Array } {
  if (!('header' in obj)) {
    throw new Error('Expected key .header');
  }
  validateUint8Array(obj.header);
  if (8 !== (obj.header as Uint8Array).length) {
    throw new Error('Expected 8 byte header');
  }
  return obj as { header: Uint8Array };
}

/**
 * Validate that the given `object` has a well-formed `.payload` key.
 *
 * > This function internally calls {@link validateUint8Array}.
 *
 * @example
 * ```typescript
 * import { validateObjectHasPayloadKey } from './src/validation';
 *
 * console.log(validateObjectHasPayloadKey({ payload: Uint8Array.of() }));
 *   // { payload: Uint8Array(0) [] }
 * ```
 *
 * @example
 * ```typescript
 * import { validateObjectHasPayloadKey } from './src/validation';
 *
 * console.log(validateObjectHasPayloadKey({}));
 *   // Error: Expected key .payload
 * ```
 *
 * @param obj - `object` to validate.
 * @returns The validated `object`.
 * @throws {@link !Error} If the given `object` has no `.payload` key.
 */
export function validateObjectHasPayloadKey(obj: object): { payload: Uint8Array } {
  if (!('payload' in obj)) {
    throw new Error('Expected key .payload');
  }
  validateUint8Array(obj.payload);
  return obj as { payload: Uint8Array };
}

/**
 * Validate that the given `object` has a well-formed `.operand` key.
 *
 * > This function internally calls {@link validateUint8Array}.
 *
 * @example
 * ```typescript
 * import { validateObjectHasOperandKey } from './src/validation';
 *
 * console.log(validateObjectHasOperandKey({ operand: Uint8Array.of() }));
 *   // { operand: Uint8Array(0) [] }
 * ```
 *
 * @example
 * ```typescript
 * import { validateObjectHasOperandKey } from './src/validation';
 *
 * console.log(validateObjectHasOperandKey({}));
 *   // Error: Expected key .operand
 * ```
 *
 * @param obj - `object` to validate.
 * @returns The validated `object`.
 * @throws {@link !Error} If the given `object` has no `.operand` key.
 */
export function validateObjectHasOperandKey(obj: object): { operand: Uint8Array } {
  if (!('operand' in obj)) {
    throw new Error('Expected key .operand');
  }
  validateUint8Array(obj.operand);
  return obj as { operand: Uint8Array };
}

/**
 * Validate that the given `object` has a well-formed `.leaves` key.
 *
 * > This function internally calls {@link validateNonNullObject}.
 * >
 * > This function internally calls {@link validateLeaf}.
 *
 * @example
 * ```typescript
 * import { LeafSet } from './src/internals';
 * import { validateObjectHasLeavesKey } from './src/validation';
 *
 * console.log(validateObjectHasLeavesKey({ leaves: new LeafSet() }));
 *   // { leaves: LeafSet {} }
 * ```
 *
 * @example
 * ```typescript
 * import { validateObjectHasLeavesKey } from './src/validation';
 *
 * console.log(validateObjectHasLeavesKey({}));
 *   // Error: Expected key .leaves
 * console.log(validateObjectHasLeavesKey({ leaves: 123 }));
 *   // Error: Expected LeafSet
 * ```
 *
 * @param obj - `object` to validate.
 * @returns The validated `object`.
 * @throws {@link !Error} If the given `object` has no `.leaves` key.
 * @throws {@link !Error} If `obj.leaves` is not a {@link LeafSet}.
 */
export function validateObjectHasLeavesKey(obj: object): { leaves: LeafSet } {
  if (!('leaves' in obj)) {
    throw new Error('Expected key .leaves');
  }
  const leaves: object = validateNonNullObject(obj.leaves);
  if (leaves.constructor !== LeafSet) {
    throw new Error('Expected LeafSet');
  }
  (leaves as LeafSet).values().forEach(validateLeaf);

  return obj as { leaves: LeafSet };
}

/**
 * Validate that the given `object` has a well-formed `.edges` key.
 *
 * > This function internally calls {@link validateNonNullObject}.
 * >
 * > This function internally calls {@link validateOp}.
 * >
 * > This function internally calls {@link validateTree}.
 *
 * @example
 * ```typescript
 * import { EdgeMap } from './src/internals';
 * import { validateObjectHasEdgesKey } from './src/validation';
 *
 * console.log(validateObjectHasEdgesKey({ edges: new EdgeMap() }));
 *   // { edges: EdgeMap {} }
 * ```
 *
 * @example
 * ```typescript
 * import { validateObjectHasEdgesKey } from './src/validation';
 *
 * console.log(validateObjectHasEdgesKey({}));
 *   // Error: Expected key .edges
 * console.log(validateObjectHasEdgesKey({ edges: 123 }));
 *   // Error: Expected EdgeMap
 * ```
 *
 * @param obj - `object` to validate.
 * @returns The validated `object`.
 * @throws {@link !Error} If the given `object` has no `.edges` key.
 * @throws {@link !Error} If `obj.edges` is not an {@link EdgeMap}.
 */
export function validateObjectHasEdgesKey(obj: object): { edges: EdgeMap } {
  if (!('edges' in obj)) {
    throw new Error('Expected key .edges');
  }
  const edges: object = validateNonNullObject(obj.edges);
  if (edges.constructor !== EdgeMap) {
    throw new Error('Expected EdgeMap');
  }
  (edges as EdgeMap).keys().forEach(validateOp);
  (edges as EdgeMap).values().forEach(validateTree);

  return obj as { edges: EdgeMap };
}

/**
 * Validate that the given `object` has a well-formed `.algorithm` key.
 *
 * > This function internally calls {@link validateOneOfStrings}.
 *
 * @example
 * ```typescript
 * import { validateObjectHasAlgorithmKey } from './src/validation';
 *
 * console.log(validateObjectHasAlgorithmKey({ algorithm: 'sha1' }));
 *   // { algorithm: 'sha1' }
 * ```
 *
 * @example
 * ```typescript
 * import { validateObjectHasAlgorithmKey } from './src/validation';
 *
 * console.log(validateObjectHasAlgorithmKey({}));
 *   // Error: Expected key .algorithm
 * console.log(validateObjectHasAlgorithmKey({ algorithm: 123 }));
 *   // Error: Expected string
 * ```
 *
 * @param obj - `object` to validate.
 * @returns The validated `object`.
 * @throws {@link !Error} If the given `object` has no `.algorithm` key.
 * @throws {@link !Error} If `obj.edges` is not a `string`.
 */
export function validateObjectHasAlgorithmKey(obj: object): { algorithm: string } {
  if (!('algorithm' in obj)) {
    throw new Error('Expected key .algorithm');
  }
  if ('string' !== typeof obj.algorithm) {
    throw new Error('Expected string');
  }
  validateOneOfStrings(obj.algorithm, ['sha1', 'ripemd160', 'sha256', 'keccak256']);

  return obj as { algorithm: string };
}

/**
 * Validate that the given `object` has a well-formed `.value` key.
 *
 * > This function internally calls {@link validateUint8Array}.
 *
 * @example
 * ```typescript
 * import { validateObjectHasValueKey } from './src/validation';
 *
 * console.log(validateObjectHasValueKey({ value: Uint8Array.of() }));
 *   // { value: Uint8Array(0) [] }
 * ```
 *
 * @example
 * ```typescript
 * import { validateObjectHasValueKey } from './src/validation';
 *
 * console.log(validateObjectHasValueKey({}));
 *   // Error: Expected key .value
 * ```
 *
 * @param obj - `object` to validate.
 * @returns The validated `object`.
 * @throws {@link !Error} If the given `object` has no `.value` key.
 */
export function validateObjectHasValueKey(obj: object): { value: Uint8Array } {
  if (!('value' in obj)) {
    throw new Error('Expected key .value');
  }
  validateUint8Array(obj.value);

  return obj as { value: Uint8Array };
}

/**
 * Validate that the given datum is a well-formed {@link Leaf}.
 *
 * > This function internally calls {@link validateNonNullObject}.
 * >
 * > This function internally calls {@link validateObjectHasTypeKey}.
 * >
 * > This function internally calls {@link validateOneOfStrings}.
 * >
 * > This function internally calls {@link validateObjectHasHeightKey}.
 * >
 * > This function internally calls {@link validateObjectHasUrlKey}.
 * >
 * > This function internally calls {@link validateObjectHasHeaderKey}.
 * >
 * > This function internally calls {@link validateObjectHasPayloadKey}.
 *
 * @example
 * ```typescript
 * import { validateLeaf } from './src/validation';
 *
 * console.log(validateLeaf({ type: 'bitcoin', height: 123 }));
 *   // { type: 'bitcoin', height: 123 }
 * console.log(validateLeaf({ type: 'litecoin', height: 123 }));
 *   // { type: 'litecoin', height: 123 }
 * console.log(validateLeaf({ type: 'ethereum', height: 123 }));
 *   // { type: 'ethereum', height: 123 }
 * console.log(validateLeaf(
 *   {
 *     type: 'pending',
 *     url: new URL('https://www.example.com'),
 *   },
 * ));
 *   // { type: 'pending', url: URL { ... } }
 * console.log(validateLeaf(
 *   {
 *     type: 'unknown',
 *     header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
 *     payload: Uint8Array.of(),
 *   },
 * ));
 *   // {
 *   //   type: 'unknown',
 *   //   header: Uint8Array(8) [ 1, 2, 3, 4, 5, 6, 7, 8 ],
 *   //   payload: Uint8Array(0) [],
 *   // }
 * ```
 *
 * @example
 * ```typescript
 * import { validateLeaf } from './src/validation';
 *
 * console.log(validateLeaf(123));
 *   // Error: Expected non-null object
 * console.log(validateLeaf({}));
 *   // Error: Expected key .type
 * console.log(validateLeaf({ type: 'something' }));
 *   // Error: Expected one of [bitcoin, litecoin, ethereum, pending, unknown]
 * console.log(validateLeaf({ type: 'bitcoin' }));
 *   // Error: Expected key .height
 * console.log(validateLeaf({ type: 'litecoin' }));
 *   // Error: Expected key .height
 * console.log(validateLeaf({ type: 'ethereum' }));
 *   // Error: Expected key .height
 * console.log(validateLeaf({ type: 'pending' }));
 *   // Error: Expected key .url
 * console.log(validateLeaf({ type: 'unknown' }));
 *   // Error: Expected key .header
 * console.log(validateLeaf(
 *   {
 *     type: 'unknown',
 *     header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
 *   },
 * ));
 *   // Error: Expected key .payload
 * ```
 *
 * @param leaf - Data to validate.
 * @returns The validated {@link Leaf}.
 */
export function validateLeaf(leaf: unknown): Leaf {
  const obj: { type: string } = validateObjectHasTypeKey(validateNonNullObject(leaf));

  switch (validateOneOfStrings(obj.type, ['bitcoin', 'litecoin', 'ethereum', 'pending', 'unknown'])) {
    case 'bitcoin':
      validateObjectHasHeightKey(obj);
      return leaf as { type: 'bitcoin'; height: number };
    case 'litecoin':
      validateObjectHasHeightKey(obj);
      return leaf as { type: 'litecoin'; height: number };
    case 'ethereum':
      validateObjectHasHeightKey(obj);
      return leaf as { type: 'ethereum'; height: number };
    case 'pending':
      validateObjectHasUrlKey(obj);
      return leaf as { type: 'pending'; url: URL };
    case 'unknown':
      validateObjectHasHeaderKey(obj);
      validateObjectHasPayloadKey(obj);
      return leaf as { type: 'unknown'; header: Uint8Array; payload: Uint8Array };
  }

  /* istanbul ignore next */
  return undefined as never;
}

/**
 * Validate that the given datum is a well-formed {@link Op}.
 *
 * > This function internally calls {@link validateNonNullObject}.
 * >
 * > This function internally calls {@link validateObjectHasTypeKey}.
 * >
 * > This function internally calls {@link validateOneOfStrings}.
 * >
 * > This function internally calls {@link validateObjectHasOperandKey}.
 *
 * @example
 * ```typescript
 * import { validateOp } from './src/validation';
 *
 * console.log(validateOp({ type: 'sha1' }));
 *   // { type: 'sha1' }
 * console.log(validateOp({ type: 'ripemd160' }));
 *   // { type: 'ripemd160' }
 * console.log(validateOp({ type: 'sha256' }));
 *   // { type: 'sha256' }
 * console.log(validateOp({ type: 'keccak256' }));
 *   // { type: 'keccak256' }
 * console.log(validateOp({ type: 'reverse' }));
 *   // { type: 'reverse' }
 * console.log(validateOp({ type: 'hexlify' }));
 *   // { type: 'hexlify' }
 * console.log(validateOp({ type: 'append', operand: Uint8Array.of() }));
 *   // { type: 'append', operand: Uint8Array(0) [] }
 * console.log(validateOp({ type: 'prepend', operand: Uint8Array.of() }));
 *   // { type: 'prepend', operand: Uint8Array(0) [] }
 * ```
 *
 * @example
 * ```typescript
 * import { validateOp } from './src/validation';
 *
 * console.log(validateOp(123));
 *   // Error: Expected non-null object
 * console.log(validateOp({}));
 *   // Error: Expected key .type
 * console.log(validateOp({ type: 'something' }));
 *   // Error: Expected one of [sha1, ripemd160, sha256, keccak256, reverse, hexlify, append, prepend]
 * console.log(validateOp({ type: 'append' }));
 *   // Error: Expected key .operand
 * console.log(validateOp({ type: 'prepend' }));
 *   // Error: Expected key .operand
 * ```
 *
 * @param op - Data to validate.
 * @returns The validated {@link Op}.
 */
export function validateOp(op: unknown): Op {
  const obj: { type: string } = validateObjectHasTypeKey(validateNonNullObject(op));

  switch (
    validateOneOfStrings(obj.type, [
      'sha1',
      'ripemd160',
      'sha256',
      'keccak256',
      'reverse',
      'hexlify',
      'append',
      'prepend',
    ])
  ) {
    case 'sha1':
      return op as { type: 'sha1' };
    case 'ripemd160':
      return op as { type: 'ripemd160' };
    case 'sha256':
      return op as { type: 'sha256' };
    case 'keccak256':
      return op as { type: 'keccak256' };
    case 'reverse':
      return op as { type: 'reverse' };
    case 'hexlify':
      return op as { type: 'hexlify' };
    case 'append':
      validateObjectHasOperandKey(obj);
      return op as { type: 'append'; operand: Uint8Array };
    case 'prepend':
      validateObjectHasOperandKey(obj);
      return op as { type: 'prepend'; operand: Uint8Array };
  }

  /* istanbul ignore next */
  return undefined as never;
}

/**
 * Validate that the given datum is a well-formed {@link Tree}.
 *
 * > This function internally calls {@link validateNonNullObject}.
 * >
 * > This function internally calls {@link validateObjectHasLeavesKey}.
 * >
 * > This function internally calls {@link validateObjectHasEdgesKey}.
 *
 * @example
 * ```typescript
 * import { newTree } from './src/internals';
 * import { validateTree } from './src/validation';
 *
 * console.log(validateTree(newTree()));
 *   // { edges: EdgeMap {}, leaves: LeafSet {} }
 * ```
 *
 * @example
 * ```typescript
 * import { LeafSet } from './src/internals';
 * import { validateTree } from './src/validation';
 *
 * console.log(validateTree({}));
 *   // Error: Expected key .leaves
 * console.log(validateTree({ leaves: {} }));
 *   // Error: Expected LeafSet
 * console.log(validateTree({ leaves: new LeafSet() }));
 *   // Error: Expected key .edges
 * ```
 *
 * @param tree - Data to validate.
 * @returns The validated {@link Tree}.
 */
export function validateTree(tree: unknown): Tree {
  const obj: object = validateNonNullObject(tree);

  validateObjectHasLeavesKey(obj);
  validateObjectHasEdgesKey(obj);

  return tree as Tree;
}

/**
 * Validate that the given parameters constitute a well-formed {@link FileHash}.
 *
 * > This function internally calls {@link validateOneOfStrings}.
 *
 * @example
 * ```typescript
 * import { validateFileHashValue } from './src/validation';
 *
 * console.log(validateFileHashValue(
 *   'sha1',
 *   Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                 11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 * ));
 *   // { algorithm: 'sha1', value: Uint8Array(20) [ ... ] }
 *
 * console.log(validateFileHashValue(
 *   'ripemd160',
 *   Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                 11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 * ));
 *   // { algorithm: 'ripemd160', value: Uint8Array(20) [ ... ] }
 * console.log(validateFileHashValue(
 *   'sha256',
 *   Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,
 *                  9, 10, 11, 12, 13, 14, 15, 16,
 *                 17, 18, 19, 20, 21, 22, 23, 24,
 *                 25, 26, 27, 28, 29, 30, 31, 32),
 * ));
 *   // { algorithm: 'sha256', value: Uint8Array(32) [ ... ] }
 * console.log(validateFileHashValue(
 *   'keccak256',
 *   Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,
 *                  9, 10, 11, 12, 13, 14, 15, 16,
 *                 17, 18, 19, 20, 21, 22, 23, 24,
 *                 25, 26, 27, 28, 29, 30, 31, 32),
 * ));
 *   // { algorithm: 'keccak256', value: Uint8Array(32) [ ... ] }
 * ```
 *
 * @example
 * ```typescript
 * import { validateFileHashValue } from './src/validation';
 *
 * console.log(validateFileHashValue('something', Uint8Array.of()));
 *   // Error: Expected one of [sha1, ripemd160, sha256, keccak256]
 * console.log(validateFileHashValue('sha1', Uint8Array.of()));
 *   // Error: Expected 20 byte hash
 * console.log(validateFileHashValue('ripemd160', Uint8Array.of()));
 *   // Error: Expected 20 byte hash
 * console.log(validateFileHashValue('sha256', Uint8Array.of()));
 *   // Error: Expected 32 byte hash
 * console.log(validateFileHashValue('keccak256', Uint8Array.of()));
 *   // Error: Expected 32 byte hash
 * ```
 *
 * @param algorithm - Algorithm to validate.
 * @param value - Algorithm's value to validate.
 * @returns The validated {@link FileHash}.
 * @throws {@link !Error} If the algorithms is `'sha1'` or `'ripemd160'` and the value's length is not 20.
 * @throws {@link !Error} If the algorithms is `'sha256'` or `'keccak256'` and the value's length is not 32.
 */
export function validateFileHashValue(algorithm: string, value: Uint8Array): FileHash {
  switch (validateOneOfStrings(algorithm, ['sha1', 'ripemd160', 'sha256', 'keccak256'])) {
    case 'sha1':
    case 'ripemd160':
      if (20 !== value.length) {
        throw new Error('Expected 20 byte hash');
      }
      break;
    case 'sha256':
    case 'keccak256':
      if (32 !== value.length) {
        throw new Error('Expected 32 byte hash');
      }
      break;
  }
  return { algorithm, value } as FileHash;
}

/**
 * Validate that the given datum is a well-formed {@link FileHash}.
 *
 * > This function internally calls {@link validateNonNullObject}.
 * >
 * > This function internally calls {@link validateObjectHasValueKey}.
 * >
 * > This function internally calls {@link validateObjectHasAlgorithmKey}.
 * >
 * > This function internally calls {@link validateFileHashValue}.
 *
 * @example
 * ```typescript
 * import { validateFileHash } from './src/validation';
 *
 * console.log(validateFileHash(
 *   {
 *     algorithm: 'sha1',
 *     value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                          11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *   },
 * ));
 *   // { algorithm: 'sha1', value: Uint8Array(20) [ ... ] }
 * ```
 *
 * @example
 * ```typescript
 * import { validateFileHash } from './src/validation';
 *
 * console.log(validateFileHash(123));
 *   // Error: Expected non-null object
 * console.log(validateFileHash({}));
 *   // Error: Expected key .algorithm
 * console.log(validateFileHash({ algorithm: 'sha1' }));
 *   // Error: Expected key .value
 * ```
 *
 * @param fileHash - Data to validate.
 * @returns The validated {@link FileHash}.
 */
export function validateFileHash(fileHash: unknown): FileHash {
  const obj: object = validateNonNullObject(fileHash);
  validateFileHashValue(validateObjectHasAlgorithmKey(obj).algorithm, validateObjectHasValueKey(obj).value);
  return fileHash as FileHash;
}

/**
 * Validate that the given datum is a recognized version.
 *
 * > This function internally calls {@link validateNonNegativeInteger}.
 *
 * @example
 * ```typescript
 * import { validateVersion } from './src/validation';
 *
 * console.log(validateVersion(1));
 *   // 1
 * ```
 *
 * @example
 * ```typescript
 * import { validateVersion } from './src/validation';
 *
 * console.log(validateVersion(123));
 *   // Error: Expected .version to be 1
 * ```
 *
 * @param version - Data to validate.
 * @returns The validated version number.
 * @throws {@link !Error} If the given datum is not `1`.
 */
export function validateVersion(version: unknown): number {
  validateNonNegativeInteger(version);
  if (1 !== version) {
    throw new Error('Expected .version to be 1');
  }

  return version;
}

/**
 * Validate that the given datum is a well-formed {@link Timestamp}.
 *
 * > This function internally calls {@link validateNonNullObject}.
 * >
 * > This function internally calls {@link validateVersion}.
 * >
 * > This function internally calls {@link validateFileHash}.
 * >
 * > This function internally calls {@link validateTree}.
 *
 * @example
 * ```typescript
 * import { newTree } from './src/internals';
 * import { validate } from './src/validation';
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
 *   //   tree: { edges: EdgeMap {}, leaves: LeafSet {} }
 *   // }
 * ```
 *
 * @example
 * ```typescript
 * import { validate } from './src/validation';
 *
 * console.log(validate(123));
 *   // Error: Expected non-null object
 * console.log(validate({}));
 *   // Error: Expected key .version
 * console.log(validate({ version: 1 }));
 *   // Error: Expected key .fileHash
 * console.log(validate(
 *   {
 *     version: 1,
 *     fileHash: {
 *       algorithm: 'sha1',
 *       value: Uint8Array.of( 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
 *                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *     },
 *   },
 * ));
 *   // Error: Expected key .tree
 * ```
 *
 * @param timestamp - Data to validate.
 * @returns The validated {@link Timestamp}.
 * @throws {@link !Error} If the given datum has no `.version` key.
 * @throws {@link !Error} If the given datum has no `.fileHash` key.
 * @throws {@link !Error} If the given datum has no `.tree` key.
 */
export function validate(timestamp: unknown): Timestamp {
  const obj: object = validateNonNullObject(timestamp);

  if (!('version' in obj)) {
    throw new Error('Expected key .version');
  }
  if (!('fileHash' in obj)) {
    throw new Error('Expected key .fileHash');
  }
  if (!('tree' in obj)) {
    throw new Error('Expected key .tree');
  }

  validateVersion(obj.version);
  validateFileHash(obj.fileHash);
  validateTree(obj.tree);

  return timestamp as Timestamp;
}

/**
 * {@link Timestamp} Assertion-function.
 *
 * > This function internally calls {@link validate}.
 *
 * @example
 * ```typescript
 * import { newTree } from './src/internals';
 * import { assert } from './src/validation';
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
 * import { assert } from './src/validation';
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
export function assert(timestamp: unknown): asserts timestamp is Timestamp {
  void validate(timestamp);
}

/**
 * {@link Timestamp} type-predicate.
 *
 * @example
 * ```typescript
 * import { newTree } from './src/internals';
 * import { is } from './src/validation';
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
 *   }
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
 * ));
 *   // true
 * ```
 *
 * @param timestamp - Datum to check.
 * @returns `true` if the given datum is indeed a {@link Timestamp}, `false` otherwise.
 * @see [Using type predicates](https://www.typescriptlang.org/docs/handbook/2/narrowing.html#using-type-predicates)
 */
export function is(timestamp: unknown): timestamp is Timestamp {
  try {
    assert(timestamp);
    return true;
  } catch {
    return false;
  }
}
