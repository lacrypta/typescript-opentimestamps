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

import { uint8ArrayToHex } from '../src/utils';

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
});
