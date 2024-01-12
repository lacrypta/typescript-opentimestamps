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

import {
  uint8ArrayToHex,
  uint8ArrayFromHex,
  uint8ArrayEquals,
  uint8ArrayCompare,
  uint8ArrayConcat,
  MergeSet,
} from '../src/utils';

describe('Utils', () => {
  describe('uint8ArrayToHex()', () => {
    it.each([
      {
        array: Uint8Array.of(),
        expected: '',
        name: 'should return empty string for empty input',
      },
      {
        array: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21),
        expected: '0102030405060708090a0b0c0d0e0f101112131415',
        name: 'should correctly convert to hex',
      },
    ])('$name', ({ array, expected }: { array: Uint8Array; expected: string }) => {
      expect(uint8ArrayToHex(array)).toEqual(expected);
    });
  });

  describe('uint8ArrayFromHex()', () => {
    it.each([
      {
        hex: '',
        expected: Uint8Array.of(),
        error: null,
        name: 'should return empty array for empty string',
      },
      {
        hex: '1',
        expected: null,
        error: 'Hex value should be of even length',
        name: 'should fail for odd length',
      },
      {
        hex: '12345',
        expected: null,
        error: 'Hex value should be of even length',
        name: 'should fail for odd length (again)',
      },
      {
        hex: '0z',
        expected: null,
        error: 'Malformed hex string',
        name: 'should fail for non-hexadecimal string',
      },
    ])(
      '$name',
      ({
        hex,
        expected,
        error,
      }: { hex: string; expected: Uint8Array; error: null } | { hex: string; expected: null; error: string }) => {
        if (null !== error) {
          expect(() => uint8ArrayFromHex(hex)).toThrow(new Error(error));
        } else {
          expect(uint8ArrayFromHex(hex)).toStrictEqual(expected);
        }
      },
    );
  });

  describe('uint8ArrayEquals()', () => {
    it.each([
      {
        left: Uint8Array.of(),
        right: Uint8Array.of(),
        expected: true,
        name: 'should return true for empty arrays',
      },
      {
        left: Uint8Array.of(1),
        right: Uint8Array.of(),
        expected: false,
        name: 'should return false for arrays of differing length',
      },
      {
        left: Uint8Array.of(1),
        right: Uint8Array.of(2),
        expected: false,
        name: 'should return false for arrays of differing contents',
      },
      {
        left: Uint8Array.of(1),
        right: Uint8Array.of(1),
        expected: true,
        name: 'should return true for equal arrays',
      },
    ])('$name', ({ left, right, expected }: { left: Uint8Array; right: Uint8Array; expected: boolean }) => {
      expect(uint8ArrayEquals(left, right)).toEqual(expected);
    });
  });

  describe('uint8ArrayCompare()', () => {
    it.each([
      {
        left: Uint8Array.of(),
        right: Uint8Array.of(),
        expected: 0,
        name: 'should return 0 for equal arrays',
      },
      {
        left: Uint8Array.of(1, 2, 3),
        right: Uint8Array.of(1, 2, 3),
        expected: 0,
        name: 'should return 0 for equal arrays (again',
      },
      {
        left: Uint8Array.of(1, 2, 3),
        right: Uint8Array.of(),
        expected: 3,
        name: 'should return positive for longer left array',
      },
      {
        left: Uint8Array.of(),
        right: Uint8Array.of(1, 2, 3),
        expected: -3,
        name: 'should return negative for longer right array',
      },
      {
        left: Uint8Array.of(1, 2, 3),
        right: Uint8Array.of(1, 2, 2),
        expected: 1,
        name: 'should return positive for bigger left array of the same length',
      },
      {
        left: Uint8Array.of(1, 2, 2),
        right: Uint8Array.of(1, 2, 3),
        expected: -1,
        name: 'should return negative for bigger right array of the same length',
      },
      {
        left: Uint8Array.of(1, 2, 3, 4),
        right: Uint8Array.of(1, 2, 2),
        expected: 1,
        name: 'should return positive for bigger left array of different length',
      },
      {
        left: Uint8Array.of(1, 2, 2, 4),
        right: Uint8Array.of(1, 2, 3),
        expected: -1,
        name: 'should return negative for bigger right array of different length',
      },
    ])('$name', ({ left, right, expected }: { left: Uint8Array; right: Uint8Array; expected: number }) => {
      expect(uint8ArrayCompare(left, right)).toEqual(expected);
    });
  });

  describe('uint8ArrayToHex()', () => {
    it.each([
      {
        arrays: [] as Uint8Array[],
        expected: Uint8Array.of(),
        name: 'should return empty for empty input',
      },
      {
        arrays: [Uint8Array.of(1, 2, 3)],
        expected: Uint8Array.of(1, 2, 3),
        name: 'should return its input for singular input',
      },
      {
        arrays: [Uint8Array.of(1, 2, 3), Uint8Array.of()],
        expected: Uint8Array.of(1, 2, 3),
        name: 'should return its input for singular input and empty array',
      },
      {
        arrays: [Uint8Array.of(1, 2, 3), Uint8Array.of(), Uint8Array.of(4, 5, 6)],
        expected: Uint8Array.of(1, 2, 3, 4, 5, 6),
        name: 'should treat empty arrays as non-existing',
      },
    ])('$name', ({ arrays, expected }: { arrays: Uint8Array[]; expected: Uint8Array }) => {
      expect(uint8ArrayConcat(arrays)).toEqual(expected);
    });
  });

  describe('MergeSet<V>', () => {
    const theToKey: (key: number) => number | string | symbol = (key: number) => key.toString();
    const theCombine: (left: number, right: number) => number = (left: number, right: number) =>
      (left % 100) * 100 + right;

    const theEmptyMergeSet: MergeSet<number> = new MergeSet<number>(theToKey, theCombine);

    describe('constructor', () => {
      it.each([
        {
          toKey: theToKey,
          combine: theCombine,
          expected: theEmptyMergeSet,
          name: 'should correctly construct',
        },
      ])(
        '$name',
        ({
          toKey,
          combine,
          expected,
        }: {
          toKey: (key: number) => number | string | symbol;
          combine: (left: number, right: number) => number;
          expected: MergeSet<number>;
        }) => {
          expect(new MergeSet<number>(toKey, combine)).toEqual(expected);
        },
      );
    });

    describe('size()', () => {
      it.each([
        {
          mergeSet: theEmptyMergeSet,
          expected: 0,
          name: 'should return 0 for empty MergeSet',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1),
          expected: 1,
          name: 'should return 1 for singleton MergeSet',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1).add(1),
          expected: 1,
          name: 'should return 1 for singleton MergeSet (again)',
        },
      ])('$name', ({ mergeSet, expected }: { mergeSet: MergeSet<number>; expected: number }) => {
        expect(mergeSet.size()).toEqual(expected);
      });
    });

    describe('values()', () => {
      it.each([
        {
          mergeSet: theEmptyMergeSet,
          expected: [],
          name: 'should return empty for empty MergeSet',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1),
          expected: [1],
          name: 'should return singleton for singleton MergeSet',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1).add(1),
          expected: [101],
          name: 'should return singleton for singleton MergeSet (again)',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1).add(1).add(2),
          expected: [101, 2],
          name: 'should return non-singleton for non-singleton MergeSet',
        },
      ])('$name', ({ mergeSet, expected }: { mergeSet: MergeSet<number>; expected: number[] }) => {
        expect(mergeSet.values()).toEqual(expected);
      });
    });

    describe('remove()', () => {
      it.each([
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine),
          item: 0,
          expected: new MergeSet<number>(theToKey, theCombine),
          name: 'should not alter empty MergeSet',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1),
          item: 1,
          expected: new MergeSet<number>(theToKey, theCombine),
          name: 'should return empty MergeSet when removing last element',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1).add(2),
          item: 1,
          expected: new MergeSet<number>(theToKey, theCombine).add(2),
          name: 'should remove non-combined element',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1).add(2).add(1),
          item: 1,
          expected: new MergeSet<number>(theToKey, theCombine).add(2),
          name: 'should remove combined element',
        },
      ])(
        '$name',
        ({ mergeSet, item, expected }: { mergeSet: MergeSet<number>; item: number; expected: MergeSet<number> }) => {
          expect(mergeSet.remove(item)).toEqual(expected);
        },
      );
    });

    describe('add()', () => {
      it.each([
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine),
          item: 1,
          expected: new MergeSet<number>(theToKey, theCombine).add(1),
          name: 'should add single item',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1),
          item: 1,
          expected: new MergeSet<number>(theToKey, theCombine).add(1).add(1),
          name: 'should add item and combine it',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1).add(2),
          item: 1,
          expected: new MergeSet<number>(theToKey, theCombine).add(2).add(1).add(1),
          name: 'should add item and combine it regardless of order',
        },
      ])(
        '$name',
        ({ mergeSet, item, expected }: { mergeSet: MergeSet<number>; item: number; expected: MergeSet<number> }) => {
          expect(mergeSet.add(item)).toEqual(expected);
        },
      );
    });

    describe('incorporate()', () => {
      it.each([
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine),
          other: new MergeSet<number>(theToKey, theCombine),
          expected: new MergeSet<number>(theToKey, theCombine),
          name: 'should return empty MergeSet when combining empty MergeSets',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine),
          other: new MergeSet<number>(theToKey, theCombine).add(1),
          expected: new MergeSet<number>(theToKey, theCombine).add(1),
          name: 'should ignore empty MergeSet left',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1),
          other: new MergeSet<number>(theToKey, theCombine),
          expected: new MergeSet<number>(theToKey, theCombine).add(1),
          name: 'should ignore empty MergeSet right',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1),
          other: new MergeSet<number>(theToKey, theCombine).add(1),
          expected: new MergeSet<number>(theToKey, theCombine).add(1).add(1),
          name: 'should return combined MergeSet when incorporating no new elements',
        },
      ])(
        '$name',
        ({
          mergeSet,
          other,
          expected,
        }: {
          mergeSet: MergeSet<number>;
          other: MergeSet<number>;
          expected: MergeSet<number>;
        }) => {
          expect(mergeSet.incorporate(other)).toEqual(expected);
        },
      );
    });

    describe('clone()', () => {
      it.each([
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine),
          expected: new MergeSet<number>(theToKey, theCombine),
          name: 'should return empty MergeSet when cloning empty MergeSet',
        },
        {
          mergeSet: new MergeSet<number>(theToKey, theCombine).add(1).add(2).add(1),
          expected: new MergeSet<number>(theToKey, theCombine).add(1).add(1).add(2),
          name: 'should return same MergeSet when cloning non-empty MergeSet',
        },
      ])('$name', ({ mergeSet, expected }: { mergeSet: MergeSet<number>; expected: MergeSet<number> }) => {
        expect(mergeSet.clone()).toEqual(expected);
      });
    });
  });
});
