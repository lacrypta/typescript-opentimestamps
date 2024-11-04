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

import type { Timestamp } from '../../src/types';

import { EdgeMap, LeafSet } from '../../src/internals';
import { canShrink, canUpgrade, canVerify } from '../../src/predicates';
import { uint8ArrayFromHex } from '../../src/utils';

describe('Predicates', (): void => {
  describe('canShrink()', (): void => {
    it.each([
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 456 }),
          },
        } as Timestamp,
        expected: true,
        name: 'should return true when shrinking is possible',
      },
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet()
              .add({ type: 'litecoin', height: 123 })
              .add({ type: 'pending', url: new URL('http://www.example.com') }),
          },
        } as Timestamp,
        expected: false,
        name: 'should return false with no leaves of given chain',
      },
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          },
        } as Timestamp,
        expected: false,
        name: 'should return false when already shrunken',
      },
    ])('$name', ({ timestamp, expected }: { timestamp: Timestamp; expected: boolean }): void => {
      expect(canShrink(timestamp, 'bitcoin')).toStrictEqual(expected);
    });
  });

  describe('canUpgrade()', (): void => {
    it.each([
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          },
        } as Timestamp,
        expected: false,
        name: 'should return false when complete',
      },
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet()
              .add({ type: 'litecoin', height: 123 })
              .add({ type: 'pending', url: new URL('http://www.example.com') }),
          },
        } as Timestamp,
        expected: true,
        name: 'should return true when at least one pending',
      },
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet()
              .add({ type: 'pending', url: new URL('http://www.example.com/a') })
              .add({ type: 'pending', url: new URL('http://www.example.com/b') }),
          },
        } as Timestamp,
        expected: true,
        name: 'should return true when multiple pending',
      },
    ])('$name', ({ timestamp, expected }: { timestamp: Timestamp; expected: boolean }): void => {
      expect(canUpgrade(timestamp)).toStrictEqual(expected);
    });
  });

  describe('canVerify()', (): void => {
    it.each([
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          },
        } as Timestamp,
        expected: true,
        name: 'should return true when complete',
      },
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet()
              .add({ type: 'litecoin', height: 123 })
              .add({ type: 'pending', url: new URL('http://www.example.com') }),
          },
        } as Timestamp,
        expected: true,
        name: 'should return true when at least one attestation',
      },
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet()
              .add({ type: 'pending', url: new URL('http://www.example.com/a') })
              .add({ type: 'pending', url: new URL('http://www.example.com/b') }),
          },
        } as Timestamp,
        expected: false,
        name: 'should return false when only pending',
      },
    ])('$name', ({ timestamp, expected }: { timestamp: Timestamp; expected: boolean }): void => {
      expect(canVerify(timestamp)).toStrictEqual(expected);
    });
  });
});
