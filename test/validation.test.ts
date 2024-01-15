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

import { incorporateTreeToTree } from '../src/internals';
import { FileHash, Leaf, Op, Tree } from '../src/types';
import { MergeMap, MergeSet, uint8ArrayFromHex } from '../src/utils';
import {
  isTimestamp,
  validateCalendarUrl,
  validateFileHash,
  validateFileHashValue,
  validateLeaf,
  validateNonNegativeInteger,
  validateNonNullObject,
  validateObjectHasEdgesKey,
  validateObjectHasHeaderKey,
  validateObjectHasHeightKey,
  validateObjectHasLeavesKey,
  validateObjectHasOperandKey,
  validateObjectHasPayloadKey,
  validateObjectHasTypeKey,
  validateObjectHasUrlKey,
  validateObjectHashAlgorithmKey,
  validateObjectHashValueKey,
  validateOneOfStrings,
  validateOp,
  validateTimestamp,
  validateTree,
  validateURL,
  validateUint8Array,
  validateVersion,
} from '../src/validation';

describe('Validation', () => {
  describe('validateNonNullObject()', () => {
    it.each([
      {
        obj: {},
        error: null,
        name: 'should return empty object for empty object input',
      },
      {
        obj: { hi: 'there' },
        error: null,
        name: 'should return non-empty object for non-empty object input',
      },
      {
        obj: null,
        error: new Error('Expected non-null object'),
        name: 'should fail for null input',
      },
      {
        obj: 123,
        error: new Error('Expected non-null object'),
        name: 'should fail for non-object input',
      },
    ])('$name', ({ obj, error }: { obj: unknown; error: Error | null }) => {
      if (null === error) {
        expect(validateNonNullObject(obj)).toBe(obj);
      } else {
        expect(() => validateNonNullObject(obj)).toThrow(error);
      }
    });
  });

  describe('validateUint8Array()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected Uint8Array'),
        name: 'should fail for non-Uint8Array object input',
      },
      {
        obj: Uint8Array.of(),
        error: null,
        name: 'should return correctly for Uint8Array input',
      },
    ])('$name', ({ obj, error }: { obj: unknown; error: Error | null }) => {
      if (null === error) {
        expect(validateUint8Array(obj)).toBe(obj);
      } else {
        expect(() => validateUint8Array(obj)).toThrow(error);
      }
    });
  });

  describe('validateURL()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected URL'),
        name: 'should fail for non-URL object input',
      },
      {
        obj: new URL('http://www.example.com'),
        error: null,
        name: 'should return correctly for Uint8Array input',
      },
    ])('$name', ({ obj, error }: { obj: unknown; error: Error | null }) => {
      if (null === error) {
        expect(validateURL(obj)).toBe(obj);
      } else {
        expect(() => validateURL(obj)).toThrow(error);
      }
    });
  });

  describe('validateCalendarUrl()', () => {
    it.each([
      {
        obj: null,
        error: new Error('Expected string'),
        name: 'should fail for non-string input',
      },
      {
        obj: 'http://www.example.com',
        error: new Error('Invalid URL'),
        name: 'should fail for non-ssl url',
      },
      {
        obj: 'https://www.example.com?some=thing&else=entirely',
        error: new Error('Invalid URL'),
        name: 'should fail for url with query string',
      },
      {
        obj: 'https://somebody@www.example.com',
        error: new Error('Invalid URL'),
        name: 'should fail for url with user',
      },
      {
        obj: 'https://www.example.com#somewhere',
        error: new Error('Invalid URL'),
        name: 'should fail for url with fragment',
      },
      {
        obj: 'https://www.example.com#somewhere',
        error: new Error('Invalid URL'),
        name: 'should fail for url with fragment',
      },
      {
        obj: 'https://www.example.com',
        error: null,
        name: 'should return the same input when valid',
      },
    ])('$name', ({ obj, error }: { obj: unknown; error: Error | null }) => {
      if (null === error) {
        expect(validateCalendarUrl(obj)).toStrictEqual(obj);
      } else {
        expect(() => validateCalendarUrl(obj)).toThrow(error);
      }
    });
  });

  describe('validateNonNegativeInteger()', () => {
    it.each([
      {
        obj: null,
        error: new Error('Expected number'),
        name: 'should fail for non-number input',
      },
      {
        obj: NaN,
        error: new Error('Expected safe-integer'),
        name: 'should fail for non-safe integer input',
      },
      {
        obj: Math.PI,
        error: new Error('Expected safe-integer'),
        name: 'should fail for non-safe integer input (again)',
      },
      {
        obj: -5,
        error: new Error('Expected positive integer'),
        name: 'should fail for negative number',
      },
      {
        obj: 0,
        error: null,
        name: 'should return 0 for 0 input',
      },
      {
        obj: 123,
        error: null,
        name: 'should return 123 for 123 input',
      },
    ])('$name', ({ obj, error }: { obj: unknown; error: Error | null }) => {
      if (null === error) {
        expect(validateNonNegativeInteger(obj)).toBe(obj);
      } else {
        expect(() => validateNonNegativeInteger(obj)).toThrow(error);
      }
    });
  });

  describe('validateOneOfStrings()', () => {
    it.each([
      {
        value: '',
        options: [],
        error: new Error('Expected one of []'),
        name: 'should fail for empty options',
      },
      {
        value: 'hi',
        options: ['there'],
        error: new Error('Expected one of [there]'),
        name: 'should fail when not in options',
      },
      {
        value: 'neither',
        options: ['here', 'there'],
        error: new Error('Expected one of [here, there]'),
        name: 'should fail when not in options (again)',
      },
      {
        value: 'here',
        options: ['here', 'there'],
        error: null,
        name: 'should pass when in options',
      },
    ])('$name', ({ value, options, error }: { value: string; options: string[]; error: Error | null }) => {
      if (null === error) {
        expect(validateOneOfStrings(value, options)).toBe(value);
      } else {
        expect(() => validateOneOfStrings(value, options)).toThrow(error);
      }
    });
  });

  describe('validateObjectHasTypeKey()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .type'),
        name: 'should fail when object does not contain .type',
      },
      {
        obj: { type: 123 },
        error: new Error('Expected string'),
        name: 'should fail when .type key is not string',
      },
      {
        obj: { type: 'something' },
        error: null,
        name: 'should pass when well-formed .type key',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateObjectHasTypeKey(obj)).toBe(obj);
      } else {
        expect(() => validateObjectHasTypeKey(obj)).toThrow(error);
      }
    });
  });

  describe('validateObjectHasHeightKey()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .height'),
        name: 'should fail when object does not contain .height',
      },
      {
        obj: { height: 123 },
        error: null,
        name: 'should pass when well-formed .height key',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateObjectHasHeightKey(obj)).toBe(obj);
      } else {
        expect(() => validateObjectHasHeightKey(obj)).toThrow(error);
      }
    });
  });

  describe('validateObjectHasUrlKey()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .url'),
        name: 'should fail when object does not contain .url',
      },
      {
        obj: { url: new URL('http://www.example.com') },
        error: null,
        name: 'should pass when well-formed .url key',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateObjectHasUrlKey(obj)).toBe(obj);
      } else {
        expect(() => validateObjectHasUrlKey(obj)).toThrow(error);
      }
    });
  });

  describe('validateObjectHasHeaderKey()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .header'),
        name: 'should fail when object does not contain .header',
      },
      {
        obj: { header: Uint8Array.of() },
        error: null,
        name: 'should pass when well-formed .header key',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateObjectHasHeaderKey(obj)).toBe(obj);
      } else {
        expect(() => validateObjectHasHeaderKey(obj)).toThrow(error);
      }
    });
  });

  describe('validateObjectHasPayloadKey()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .payload'),
        name: 'should fail when object does not contain .payload',
      },
      {
        obj: { payload: Uint8Array.of() },
        error: null,
        name: 'should pass when well-formed .payload key',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateObjectHasPayloadKey(obj)).toBe(obj);
      } else {
        expect(() => validateObjectHasPayloadKey(obj)).toThrow(error);
      }
    });
  });

  describe('validateObjectHasOperandKey()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .operand'),
        name: 'should fail when object does not contain .operand',
      },
      {
        obj: { operand: Uint8Array.of() },
        error: null,
        name: 'should pass when well-formed .operand key',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateObjectHasOperandKey(obj)).toBe(obj);
      } else {
        expect(() => validateObjectHasOperandKey(obj)).toThrow(error);
      }
    });
  });

  describe('validateObjectHasLeavesKey()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .leaves'),
        name: 'should fail when object does not contain .leaves',
      },
      {
        obj: { leaves: 123 },
        error: new Error('Expected non-null object'),
        name: 'should fail when .leaves key is not non-null object',
      },
      {
        obj: { leaves: {} },
        error: new Error('Expected MergeSet'),
        name: 'should fail when .leaves key is not MergeSet',
      },
      {
        obj: {
          leaves: new MergeSet<Leaf>(
            (_key: Leaf) => '',
            (_left: Leaf, _right: Leaf): Leaf => {
              return { type: 'unknown', header: Uint8Array.of(), payload: Uint8Array.of() };
            },
          ),
        },
        error: null,
        name: 'should pass when well-formed .leaves key',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateObjectHasLeavesKey(obj)).toBe(obj);
      } else {
        expect(() => validateObjectHasLeavesKey(obj)).toThrow(error);
      }
    });
  });

  describe('validateObjectHasEdgesKey()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .edges'),
        name: 'should fail when object does not contain .edges',
      },
      {
        obj: { edges: 123 },
        error: new Error('Expected non-null object'),
        name: 'should fail when .edges key is not non-null object',
      },
      {
        obj: { edges: {} },
        error: new Error('Expected MergeMap'),
        name: 'should fail when .edges key is not MergeMap',
      },
      {
        obj: {
          edges: new MergeMap<Op, Tree>(
            (_key: Op) => '',
            (left: Tree, right: Tree): Tree => {
              return incorporateTreeToTree(left, right);
            },
          ),
        },
        error: null,
        name: 'should pass when well-formed .edges key',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateObjectHasEdgesKey(obj)).toBe(obj);
      } else {
        expect(() => validateObjectHasEdgesKey(obj)).toThrow(error);
      }
    });
  });

  describe('validateObjectHashAlgorithmKey()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .algorithm'),
        name: 'should fail when object does not contain .algorithm',
      },
      {
        obj: { algorithm: 123 },
        error: new Error('Expected string'),
        name: 'should fail when .algorithm key is not string',
      },
      {
        obj: { algorithm: 'none of the above' },
        error: new Error('Expected one of [sha1, ripemd160, sha256, keccak256]'),
        name: 'should fail when .algorithm is not a recognized name',
      },
      {
        obj: { algorithm: 'sha1' },
        error: null,
        name: 'should pass when well-formed .algorithm key (sha1)',
      },
      {
        obj: { algorithm: 'ripemd160' },
        error: null,
        name: 'should pass when well-formed .algorithm key (ripemd160)',
      },
      {
        obj: { algorithm: 'sha256' },
        error: null,
        name: 'should pass when well-formed .algorithm key (sha256)',
      },
      {
        obj: { algorithm: 'keccak256' },
        error: null,
        name: 'should pass when well-formed .algorithm key (keccak256)',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateObjectHashAlgorithmKey(obj)).toBe(obj);
      } else {
        expect(() => validateObjectHashAlgorithmKey(obj)).toThrow(error);
      }
    });
  });

  describe('validateObjectHashValueKey()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .value'),
        name: 'should fail when object does not contain .value',
      },
      {
        obj: { value: 123 },
        error: new Error('Expected non-null object'),
        name: 'should fail when .value key is not non-null object',
      },
      {
        obj: { value: {} },
        error: new Error('Expected Uint8Array'),
        name: 'should fail when .value is not a Uint8Array',
      },
      {
        obj: { value: Uint8Array.of() },
        error: null,
        name: 'should pass when well-formed .value key',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateObjectHashValueKey(obj)).toBe(obj);
      } else {
        expect(() => validateObjectHashValueKey(obj)).toThrow(error);
      }
    });
  });

  describe('validateLeaf()', () => {
    it.each([
      {
        obj: { type: 'none of the above' },
        error: new Error('Expected one of [bitcoin, litecoin, ethereum, pending, unknown]'),
        name: 'should fail when .type is not a leaf type',
      },
      {
        obj: { type: 'bitcoin' },
        error: new Error('Expected key .height'),
        name: 'should fail when "bitcoin" leaf has no .height key',
      },
      {
        obj: { type: 'bitcoin', height: null },
        error: new Error('Expected number'),
        name: 'should fail when "bitcoin" leaf has non-numeric .height',
      },
      {
        obj: { type: 'bitcoin', height: 123 },
        error: null,
        name: 'should pass when "bitcoin" leaf is well-formed',
      },
      {
        obj: { type: 'litecoin' },
        error: new Error('Expected key .height'),
        name: 'should fail when "litecoin" leaf has no .height key',
      },
      {
        obj: { type: 'litecoin', height: null },
        error: new Error('Expected number'),
        name: 'should fail when "litecoin" leaf has non-numeric .height',
      },
      {
        obj: { type: 'litecoin', height: 123 },
        error: null,
        name: 'should pass when "litecoin" leaf is well-formed',
      },
      {
        obj: { type: 'ethereum' },
        error: new Error('Expected key .height'),
        name: 'should fail when "ethereum" leaf has no .height key',
      },
      {
        obj: { type: 'ethereum', height: null },
        error: new Error('Expected number'),
        name: 'should fail when "ethereum" leaf has non-numeric .height',
      },
      {
        obj: { type: 'ethereum', height: 123 },
        error: null,
        name: 'should pass when "ethereum" leaf is well-formed',
      },
      {
        obj: { type: 'pending' },
        error: new Error('Expected key .url'),
        name: 'should fail when "pending" leaf has no .url key',
      },
      {
        obj: { type: 'pending', url: null },
        error: new Error('Expected non-null object'),
        name: 'should fail when "pending" leaf has null .url',
      },
      {
        obj: { type: 'pending', url: new URL('http://www.example.com') },
        error: null,
        name: 'should pass when "pending" leaf is well-formed',
      },
      {
        obj: { type: 'unknown' },
        error: new Error('Expected key .header'),
        name: 'should fail when "unknown" leaf has no .header key',
      },
      {
        obj: { type: 'unknown', header: null },
        error: new Error('Expected non-null object'),
        name: 'should fail when "unknown" leaf has null .header',
      },
      {
        obj: { type: 'unknown', header: Uint8Array.of() },
        error: new Error('Expected key .payload'),
        name: 'should fail when "unknown" leaf has no .payload key',
      },
      {
        obj: { type: 'unknown', header: Uint8Array.of(), payload: null },
        error: new Error('Expected non-null object'),
        name: 'should fail when "unknown" leaf has null .payload',
      },
      {
        obj: { type: 'unknown', header: Uint8Array.of(), payload: Uint8Array.of() },
        error: null,
        name: 'should pass when "unknown" leaf is well-formed',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateLeaf(obj)).toBe(obj);
      } else {
        expect(() => validateLeaf(obj)).toThrow(error);
      }
    });
  });

  describe('validateOp()', () => {
    it.each([
      {
        obj: { type: 'none of the above' },
        error: new Error('Expected one of [sha1, ripemd160, sha256, keccak256, reverse, hexlify, append, prepend]'),
        name: 'should fail when .type is not a operation type',
      },
      {
        obj: { type: 'sha1' },
        error: null,
        name: 'should pass when .type is sha1',
      },
      {
        obj: { type: 'ripemd160' },
        error: null,
        name: 'should pass when .type is ripemd160',
      },
      {
        obj: { type: 'sha256' },
        error: null,
        name: 'should pass when .type is sha256',
      },
      {
        obj: { type: 'keccak256' },
        error: null,
        name: 'should pass when .type is keccak256',
      },
      {
        obj: { type: 'reverse' },
        error: null,
        name: 'should pass when .type is reverse',
      },
      {
        obj: { type: 'hexlify' },
        error: null,
        name: 'should pass when .type is hexlify',
      },
      {
        obj: { type: 'append' },
        error: new Error('Expected key .operand'),
        name: 'should fail when .type is append and no operand is given',
      },
      {
        obj: { type: 'prepend' },
        error: new Error('Expected key .operand'),
        name: 'should fail when .type is prepend and no operand is given',
      },
      {
        obj: { type: 'append', operand: null },
        error: new Error('Expected non-null object'),
        name: 'should fail when .type is append and .operand is null',
      },
      {
        obj: { type: 'prepend', operand: null },
        error: new Error('Expected non-null object'),
        name: 'should fail when .type is prepend and .operand is null',
      },
      {
        obj: { type: 'append', operand: Uint8Array.of() },
        error: null,
        name: 'should pass when .type is append and is well-formed',
      },
      {
        obj: { type: 'prepend', operand: Uint8Array.of() },
        error: null,
        name: 'should pass when .type is prepend and is well-formed',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateOp(obj)).toBe(obj);
      } else {
        expect(() => validateOp(obj)).toThrow(error);
      }
    });
  });

  describe('validateTree()', () => {
    it.each([
      {
        obj: {},
        error: new Error('Expected key .leaves'),
        name: 'should fail when missing .leaves key',
      },
      {
        obj: { leaves: null },
        error: new Error('Expected non-null object'),
        name: 'should fail when .leaves is null',
      },
      {
        obj: {
          leaves: new MergeSet<Leaf>(
            (_key: Leaf) => '',
            (_left: Leaf, _right: Leaf): Leaf => {
              return { type: 'unknown', header: Uint8Array.of(), payload: Uint8Array.of() };
            },
          ),
        },
        error: new Error('Expected key .edges'),
        name: 'should fail when missing .edges key',
      },
      {
        obj: {
          leaves: new MergeSet<Leaf>(
            (_key: Leaf) => '',
            (_left: Leaf, _right: Leaf): Leaf => {
              return { type: 'unknown', header: Uint8Array.of(), payload: Uint8Array.of() };
            },
          ),
          edges: null,
        },
        error: new Error('Expected non-null object'),
        name: 'should fail when .edges is null',
      },
      {
        obj: {
          leaves: new MergeSet<Leaf>(
            (_key: Leaf) => '',
            (_left: Leaf, _right: Leaf): Leaf => {
              return { type: 'unknown', header: Uint8Array.of(), payload: Uint8Array.of() };
            },
          ),
          edges: new MergeMap<Op, Tree>(
            (_key: Op) => '',
            (left: Tree, right: Tree): Tree => {
              return incorporateTreeToTree(left, right);
            },
          ),
        },
        error: null,
        name: 'should pass when .edges is null',
      },
    ])('$name', ({ obj, error }: { obj: object; error: Error | null }) => {
      if (null === error) {
        expect(validateTree(obj)).toBe(obj);
      } else {
        expect(() => validateTree(obj)).toThrow(error);
      }
    });
  });

  describe('validateFileHashValue()', () => {
    it.each([
      {
        algorithm: 'none of the above',
        value: uint8ArrayFromHex(''),
        expected: null,
        error: new Error('Expected one of [sha1, ripemd160, sha256, keccak256]'),
        name: 'should fail when algorithm is unknown',
      },
      {
        algorithm: 'sha1',
        value: uint8ArrayFromHex(''),
        expected: null,
        error: new Error('Expected 20 byte hash'),
        name: 'should fail for sha1 for non 20-byte value',
      },
      {
        algorithm: 'sha1',
        value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f10111213'),
        expected: {
          algorithm: 'sha1',
          value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f10111213'),
        } as FileHash,
        error: null,
        name: 'should pass for sha1 for 20-byte value',
      },
      {
        algorithm: 'sha1',
        value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f1011121314'),
        expected: null,
        error: new Error('Expected 20 byte hash'),
        name: 'should fail for sha1 for non 20-byte value (again)',
      },
      {
        algorithm: 'ripemd160',
        value: uint8ArrayFromHex(''),
        expected: null,
        error: new Error('Expected 20 byte hash'),
        name: 'should fail for ripemd160 for non 20-byte value',
      },
      {
        algorithm: 'ripemd160',
        value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f10111213'),
        expected: {
          algorithm: 'ripemd160',
          value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f10111213'),
        } as FileHash,
        error: null,
        name: 'should pass for ripemd160 for 20-byte value',
      },
      {
        algorithm: 'ripemd160',
        value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f1011121314'),
        expected: null,
        error: new Error('Expected 20 byte hash'),
        name: 'should fail for ripemd160 for non 20-byte value (again)',
      },
      {
        algorithm: 'sha256',
        value: uint8ArrayFromHex(''),
        expected: null,
        error: new Error('Expected 32 byte hash'),
        name: 'should fail for sha256 for non 20-byte value',
      },
      {
        algorithm: 'sha256',
        value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
        expected: {
          algorithm: 'sha256',
          value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
        } as FileHash,
        error: null,
        name: 'should pass for sha256 for 32-byte value',
      },
      {
        algorithm: 'sha256',
        value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'),
        expected: null,
        error: new Error('Expected 32 byte hash'),
        name: 'should fail for sha256 for non 32-byte value (again)',
      },
      {
        algorithm: 'keccak256',
        value: uint8ArrayFromHex(''),
        expected: null,
        error: new Error('Expected 32 byte hash'),
        name: 'should fail for keccak256 for non 32-byte value',
      },
      {
        algorithm: 'keccak256',
        value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
        expected: {
          algorithm: 'keccak256',
          value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
        } as FileHash,
        error: null,
        name: 'should pass for keccak256 for 32-byte value',
      },
      {
        algorithm: 'keccak256',
        value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'),
        expected: null,
        error: new Error('Expected 32 byte hash'),
        name: 'should fail for keccak256 for non 32-byte value (again)',
      },
    ])(
      '$name',
      ({
        algorithm,
        value,
        expected,
        error,
      }:
        | { algorithm: string; value: Uint8Array; expected: FileHash; error: null }
        | { algorithm: string; value: Uint8Array; expected: null; error: Error }) => {
        if (null === error) {
          expect(validateFileHashValue(algorithm, value)).toStrictEqual(expected);
        } else {
          expect(() => validateFileHashValue(algorithm, value)).toThrow(error);
        }
      },
    );
  });

  describe('validateFileHash()', () => {
    it.each([
      {
        fileHash: { algorithm: 'none of the above', value: uint8ArrayFromHex('') },
        error: new Error('Expected one of [sha1, ripemd160, sha256, keccak256]'),
        name: 'should fail when algorithm is unknown',
      },
      {
        fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('') },
        error: new Error('Expected 20 byte hash'),
        name: 'should fail for sha1 for non 20-byte value',
      },
      {
        fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f10111213') },
        error: null,
        name: 'should pass for sha1 for 20-byte value',
      },
      {
        fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f1011121314') },
        error: new Error('Expected 20 byte hash'),
        name: 'should fail for sha1 for non 20-byte value (again)',
      },
      {
        fileHash: { algorithm: 'ripemd160', value: uint8ArrayFromHex('') },
        error: new Error('Expected 20 byte hash'),
        name: 'should fail for ripemd160 for non 20-byte value',
      },
      {
        fileHash: { algorithm: 'ripemd160', value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f10111213') },
        error: null,
        name: 'should pass for ripemd160 for 20-byte value',
      },
      {
        fileHash: { algorithm: 'ripemd160', value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f1011121314') },
        error: new Error('Expected 20 byte hash'),
        name: 'should fail for ripemd160 for non 20-byte value (again)',
      },
      {
        fileHash: { algorithm: 'sha256', value: uint8ArrayFromHex('') },
        error: new Error('Expected 32 byte hash'),
        name: 'should fail for sha256 for non 20-byte value',
      },
      {
        fileHash: {
          algorithm: 'sha256',
          value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
        },
        error: null,
        name: 'should pass for sha256 for 32-byte value',
      },
      {
        fileHash: {
          algorithm: 'sha256',
          value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'),
        },
        error: new Error('Expected 32 byte hash'),
        name: 'should fail for sha256 for non 32-byte value (again)',
      },
      {
        fileHash: { algorithm: 'keccak256', value: uint8ArrayFromHex('') },
        error: new Error('Expected 32 byte hash'),
        name: 'should fail for keccak256 for non 32-byte value',
      },
      {
        fileHash: {
          algorithm: 'keccak256',
          value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
        },
        error: null,
        name: 'should pass for keccak256 for 32-byte value',
      },
      {
        fileHash: {
          algorithm: 'keccak256',
          value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'),
        },
        error: new Error('Expected 32 byte hash'),
        name: 'should fail for keccak256 for non 32-byte value (again)',
      },
    ])('$name', ({ fileHash, error }: { fileHash: unknown; error: Error | null }) => {
      if (null === error) {
        expect(validateFileHash(fileHash)).toBe(fileHash);
      } else {
        expect(() => validateFileHash(fileHash)).toThrow(error);
      }
    });
  });

  describe('validateVersion()', () => {
    it.each([
      {
        version: null,
        error: new Error('Expected number'),
        name: 'should fail when version is not a number',
      },
      {
        version: 123,
        error: new Error('Expected .version to be 1'),
        name: 'should fail when .version is not recognized',
      },
      {
        version: 1,
        error: null,
        name: 'should pass when well-formed .version given',
      },
    ])('$name', ({ version, error }: { version: unknown; error: Error | null }) => {
      if (null === error) {
        expect(validateVersion(version)).toBe(version);
      } else {
        expect(() => validateVersion(version)).toThrow(error);
      }
    });
  });

  describe('validateTimestamp()', () => {
    it.each([
      {
        obj: 123,
        error: new Error('Expected non-null object'),
        name: 'should fail when input is not a non-null object',
      },
      {
        obj: {},
        error: new Error('Expected key .version'),
        name: 'should fail when input has no .version key',
      },
      {
        obj: { version: null },
        error: new Error('Expected key .fileHash'),
        name: 'should fail when input has no .fileHash key',
      },
      {
        obj: { version: null, fileHash: null },
        error: new Error('Expected key .tree'),
        name: 'should fail when input has no .tree key',
      },
      {
        obj: { version: null, fileHash: null, tree: null },
        error: new Error('Expected number'),
        name: 'should fail when input has malformed .version',
      },
      {
        obj: { version: 1, fileHash: null, tree: null },
        error: new Error('Expected non-null object'),
        name: 'should fail when input has malformed .fileHash',
      },
      {
        obj: {
          version: 1,
          fileHash: {
            algorithm: 'sha256',
            value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
          },
          tree: null,
        },
        error: new Error('Expected non-null object'),
        name: 'should fail when input has malformed .tree',
      },
      {
        obj: {
          version: 1,
          fileHash: {
            algorithm: 'sha256',
            value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
          },
          tree: {
            leaves: new MergeSet<Leaf>(
              (_key: Leaf) => '',
              (_left: Leaf, _right: Leaf): Leaf => {
                return { type: 'unknown', header: Uint8Array.of(), payload: Uint8Array.of() };
              },
            ),
            edges: new MergeMap<Op, Tree>(
              (_key: Op) => '',
              (left: Tree, right: Tree): Tree => {
                return incorporateTreeToTree(left, right);
              },
            ),
          },
        },
        error: null,
        name: 'should pass for well-formed timestamp',
      },
    ])('$name', ({ obj, error }: { obj: unknown; error: Error | null }) => {
      if (null === error) {
        expect(validateTimestamp(obj)).toBe(obj);
      } else {
        expect(() => validateTimestamp(obj)).toThrow(error);
      }
    });
  });

  describe('isTimestamp()', () => {
    it.each([
      {
        obj: 123,
        expected: false,
        name: 'should fail when input is not a non-null object',
      },
      {
        obj: {},
        expected: false,
        name: 'should fail when input has no .version key',
      },
      {
        obj: { version: null },
        expected: false,
        name: 'should fail when input has no .fileHash key',
      },
      {
        obj: { version: null, fileHash: null },
        expected: false,
        name: 'should fail when input has no .tree key',
      },
      {
        obj: { version: null, fileHash: null, tree: null },
        expected: false,
        name: 'should fail when input has malformed .version',
      },
      {
        obj: { version: 1, fileHash: null, tree: null },
        expected: false,
        name: 'should fail when input has malformed .fileHash',
      },
      {
        obj: {
          version: 1,
          fileHash: {
            algorithm: 'sha256',
            value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
          },
          tree: null,
        },
        expected: false,
        name: 'should fail when input has malformed .tree',
      },
      {
        obj: {
          version: 1,
          fileHash: {
            algorithm: 'sha256',
            value: uint8ArrayFromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
          },
          tree: {
            leaves: new MergeSet<Leaf>(
              (_key: Leaf) => '',
              (_left: Leaf, _right: Leaf): Leaf => {
                return { type: 'unknown', header: Uint8Array.of(), payload: Uint8Array.of() };
              },
            ),
            edges: new MergeMap<Op, Tree>(
              (_key: Op) => '',
              (left: Tree, right: Tree): Tree => {
                return incorporateTreeToTree(left, right);
              },
            ),
          },
        },
        expected: true,
        name: 'should pass for well-formed timestamp',
      },
    ])('$name', ({ obj, expected }: { obj: unknown; expected: boolean }) => {
      expect(isTimestamp(obj)).toStrictEqual(expected);
    });
  });
});