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

import type { Timestamp } from '../src';

import { newEdges, newLeaves } from '../src/internals';
import { canShrinkTimestamp, canUpgradeTimestamp, canVerifyTimestamp } from '../src/predicates';
import { uint8ArrayFromHex } from '../src/utils';

describe('Predicates', () => {
  describe('canShrinkTimestamp()', () => {
    it.each([
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: newEdges(),
            leaves: newLeaves().add({ type: 'bitcoin', height: 123 }).add({ type: 'bitcoin', height: 456 }),
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
            edges: newEdges(),
            leaves: newLeaves()
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
            edges: newEdges(),
            leaves: newLeaves().add({ type: 'bitcoin', height: 123 }),
          },
        } as Timestamp,
        expected: false,
        name: 'should return false when already shrunken',
      },
    ])('$name', ({ timestamp, expected }: { timestamp: Timestamp; expected: boolean }) => {
      expect(canShrinkTimestamp(timestamp, 'bitcoin')).toStrictEqual(expected);
    });
  });

  describe('canUpgradeTimestamp()', () => {
    it.each([
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: newEdges(),
            leaves: newLeaves().add({ type: 'bitcoin', height: 123 }),
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
            edges: newEdges(),
            leaves: newLeaves()
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
            edges: newEdges(),
            leaves: newLeaves()
              .add({ type: 'pending', url: new URL('http://www.example.com/a') })
              .add({ type: 'pending', url: new URL('http://www.example.com/b') }),
          },
        } as Timestamp,
        expected: true,
        name: 'should return true when multiple pending',
      },
    ])('$name', ({ timestamp, expected }: { timestamp: Timestamp; expected: boolean }) => {
      expect(canUpgradeTimestamp(timestamp)).toStrictEqual(expected);
    });
  });

  describe('canVerifyTimestamp()', () => {
    it.each([
      {
        timestamp: {
          version: 1,
          fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
          tree: {
            edges: newEdges(),
            leaves: newLeaves().add({ type: 'bitcoin', height: 123 }),
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
            edges: newEdges(),
            leaves: newLeaves()
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
            edges: newEdges(),
            leaves: newLeaves()
              .add({ type: 'pending', url: new URL('http://www.example.com/a') })
              .add({ type: 'pending', url: new URL('http://www.example.com/b') }),
          },
        } as Timestamp,
        expected: false,
        name: 'should return false when only pending',
      },
    ])('$name', ({ timestamp, expected }: { timestamp: Timestamp; expected: boolean }) => {
      expect(canVerifyTimestamp(timestamp)).toStrictEqual(expected);
    });
  });
});
