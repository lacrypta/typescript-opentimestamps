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
import { shrink } from '../../src/shrink';
import { uint8ArrayFromHex } from '../../src/utils';

import { timestampToString } from '../helpers';

describe('Shrink', (): void => {
  describe('shrink()', (): void => {
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
        expected: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          },
        } as Timestamp,
        name: 'should shrink to lowest height',
      },
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 789 }).add({ type: 'bitcoin', height: 456 }),
          },
        } as Timestamp,
        expected: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 456 }),
          },
        } as Timestamp,
        name: 'should shrink to lowest height (again)',
      },
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet()
              .add({ type: 'pending', url: new URL('http://www.example.com') })
              .add({ type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() }),
          },
        } as Timestamp,
        expected: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet()
              .add({ type: 'pending', url: new URL('http://www.example.com') })
              .add({ type: 'unknown', header: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8), payload: Uint8Array.of() }),
          },
        } as Timestamp,
        name: 'should return timestamp unchanged if no shrinking possible',
      },
    ])('$name', ({ timestamp, expected }: { timestamp: Timestamp; expected: Timestamp }): void => {
      expect(timestampToString(shrink(timestamp, 'bitcoin'))).toStrictEqual(timestampToString(expected));
    });
  });
});
