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

import { LeafHeader, RLeafHeader, Tag, magicHeader, nonFinal } from '../src/types';

import { uint8ArrayToHex } from '../src/utils';

describe('Types', () => {
  describe('Tag', () => {
    it.each([
      {
        element: 'attestation',
        expected: 0x00,
        name: 'should have correct attestation value',
      },
      {
        element: 'sha1',
        expected: 0x02,
        name: 'should have correct sha1 value',
      },
      {
        element: 'ripemd160',
        expected: 0x03,
        name: 'should have correct ripemd160 value',
      },
      {
        element: 'sha256',
        expected: 0x08,
        name: 'should have correct sha256 value',
      },
      {
        element: 'keccak256',
        expected: 0x67,
        name: 'should have correct keccak256 value',
      },
      {
        element: 'append',
        expected: 0xf0,
        name: 'should have correct append value',
      },
      {
        element: 'prepend',
        expected: 0xf1,
        name: 'should have correct prepend value',
      },
      {
        element: 'reverse',
        expected: 0xf2,
        name: 'should have correct reverse value',
      },
      {
        element: 'hexlify',
        expected: 0xf3,
        name: 'should have correct hexlify value',
      },
    ])('$name', ({ element, expected }: { element: string; expected: number }) => {
      expect(Tag[element as keyof typeof Tag]).toStrictEqual(expected);
    });
  });

  describe('LeafHeader', () => {
    it.each([
      {
        element: 'bitcoin',
        expected: '0588960d73d71901',
        name: 'should have correct bitcoin value',
      },
      {
        element: 'litecoin',
        expected: '06869a0d73d71b45',
        name: 'should have correct litecoin value',
      },
      {
        element: 'ethereum',
        expected: '30fe8087b5c7ead7',
        name: 'should have correct ethereum value',
      },
      {
        element: 'pending',
        expected: '83dfe30d2ef90c8e',
        name: 'should have correct pending value',
      },
    ])('$name', ({ element, expected }: { element: string; expected: string }) => {
      expect(LeafHeader[element as keyof typeof LeafHeader]).toStrictEqual(expected);
    });
  });

  describe('RLeafHeader', () => {
    it.each([
      {
        element: '0588960d73d71901',
        expected: 'bitcoin',
        name: 'should have correct bitcoin value',
      },
      {
        element: '06869a0d73d71b45',
        expected: 'litecoin',
        name: 'should have correct litecoin value',
      },
      {
        element: '30fe8087b5c7ead7',
        expected: 'ethereum',
        name: 'should have correct ethereum value',
      },
      {
        element: '83dfe30d2ef90c8e',
        expected: 'pending',
        name: 'should have correct pending value',
      },
    ])('$name', ({ element, expected }: { element: string; expected: string }) => {
      expect(RLeafHeader[element as keyof typeof RLeafHeader]).toStrictEqual(expected);
    });
  });

  describe('magicHeader', () => {
    test('should have correct value', () => {
      expect(uint8ArrayToHex(magicHeader)).toStrictEqual(
        '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294',
      );
    });
  });

  describe('nonFinal', () => {
    test('should have correct value', () => {
      expect(nonFinal).toStrictEqual(255);
    });
  });
});
