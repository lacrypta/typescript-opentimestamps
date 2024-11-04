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

import type { Leaf } from '../../src/types';

import { EdgeMap, LeafSet } from '../../src/internals';
import { uint8ArrayFromHex } from '../../src/utils';
import { verify } from '../../src/verify';

describe('Verify', (): void => {
  describe('verify()', (): void => {
    it.each([
      {
        bitcoinVerifierResponse: null,
        litecoinVerifierResponse: null,
        bitcoinVerifierError: 'something',
        litecoinVerifierError: 'else',
        expected: {
          attestations: {},
          errors: {
            bitcoinVerifier: [new Error('Error (bitcoinVerifier): unknown error in verifier')],
            litecoinVerifier: [new Error('Error (litecoinVerifier): unknown error in verifier')],
          },
        },
        name: 'should accumulate unknown errors per verifier',
      },
      {
        bitcoinVerifierResponse: null,
        litecoinVerifierResponse: null,
        bitcoinVerifierError: new Error('something'),
        litecoinVerifierError: new Error('else'),
        expected: {
          attestations: {},
          errors: {
            bitcoinVerifier: [new Error('Error (bitcoinVerifier): something')],
            litecoinVerifier: [new Error('Error (litecoinVerifier): else')],
          },
        },
        name: 'should accumulate errors per verifier',
      },
      {
        bitcoinVerifierResponse: 123456,
        litecoinVerifierResponse: 789012,
        bitcoinVerifierError: null,
        litecoinVerifierError: null,
        expected: {
          attestations: {
            123456: ['bitcoinVerifier'],
            789012: ['litecoinVerifier'],
          },
          errors: {},
        },
        name: 'should accumulate attestations per time',
      },
    ])(
      '$name',
      ({
        bitcoinVerifierResponse,
        litecoinVerifierResponse,
        bitcoinVerifierError,
        litecoinVerifierError,
        expected,
      }:
        | {
            bitcoinVerifierResponse: number | undefined;
            litecoinVerifierResponse: number | undefined;
            bitcoinVerifierError: null;
            litecoinVerifierError: null;
            expected: { attestations: Record<number, string[]>; errors: Record<string, Error[]> };
          }
        | {
            bitcoinVerifierResponse: null;
            litecoinVerifierResponse: null;
            bitcoinVerifierError: Error | string;
            litecoinVerifierError: Error | string;
            expected: { attestations: Record<number, string[]>; errors: Record<string, Error[]> };
          }): void => {
        void expect(
          verify(
            {
              version: 1,
              fileHash: {
                algorithm: 'sha1',
                value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
              },
              tree: {
                edges: new EdgeMap(),
                leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }).add({ type: 'litecoin', height: 123 }),
              },
            },
            {
              bitcoinVerifier: (_msg: Uint8Array, leaf: Leaf): Promise<number | undefined> => {
                if ('bitcoin' !== leaf.type) {
                  return Promise.resolve(undefined);
                }
                if (null !== bitcoinVerifierError) {
                  // eslint-disable-next-line @typescript-eslint/no-throw-literal
                  throw bitcoinVerifierError;
                }
                return Promise.resolve(bitcoinVerifierResponse);
              },
              litecoinVerifier: (_msg: Uint8Array, leaf: Leaf): Promise<number | undefined> => {
                if ('litecoin' !== leaf.type) {
                  return Promise.resolve(undefined);
                }
                if (null !== litecoinVerifierError) {
                  // eslint-disable-next-line @typescript-eslint/no-throw-literal
                  throw litecoinVerifierError;
                }
                return Promise.resolve(litecoinVerifierResponse);
              },
            },
          ),
        ).resolves.toStrictEqual(expected);
      },
    );
  });
});
