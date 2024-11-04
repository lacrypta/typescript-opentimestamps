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

import { newTree, EdgeMap, LeafSet } from '../../src/internals';
import { defaultCalendarUrls, submit } from '../../src/submit';
import { uint8ArrayFromHex } from '../../src/utils';

import { timestampToString } from '../helpers';

describe('Submit', (): void => {
  describe('defaultCalendarUrls', (): void => {
    it.each([
      {
        input: new URL('https://alice.btc.calendar.opentimestamps.org'),
        expected: true,
        name: 'should contain Alice',
      },
      {
        input: new URL('https://bob.btc.calendar.opentimestamps.org'),
        expected: true,
        name: 'should contain Bob',
      },
      {
        input: new URL('https://finney.calendar.eternitywall.com'),
        expected: true,
        name: 'should contain Finney',
      },
      {
        input: new URL('https://btc.calendar.catallaxy.com'),
        expected: true,
        name: 'should contain Catallaxy',
      },
    ])('$name', ({ input, expected }: { input: URL; expected: boolean }): void => {
      const sInput: string = input.toString();
      expect(defaultCalendarUrls.some((url: URL): boolean => url.toString() === sInput)).toStrictEqual(expected);
    });
  });

  describe('submit()', (): void => {
    const theNonFudgedTimestamp: Timestamp = {
      version: 1,
      fileHash: {
        algorithm: 'sha1',
        value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
      },
      tree: {
        edges: new EdgeMap().add({ type: 'sha256' }, newTree()),
        leaves: new LeafSet(),
      },
    };
    it.each([
      {
        responseBody: null,
        responseError: 'something',
        expected: {
          timestamp: theNonFudgedTimestamp,
          errors: [new Error('Error (https://www.example.com/): Unknown fetch() error')],
        },
        name: 'should accumulate unknown fetch errors (no fudge)',
      },
      {
        responseBody: null,
        responseError: new Error('something'),
        expected: {
          timestamp: theNonFudgedTimestamp,
          errors: [new Error('Error (https://www.example.com/): something')],
        },
        name: 'should accumulate fetch errors (no fudge)',
      },
      {
        responseBody: Uint8Array.of(0x00, ...uint8ArrayFromHex('0588960d73d71901'), 1, 123, 456),
        responseError: null,
        expected: {
          timestamp: theNonFudgedTimestamp,
          errors: [new Error('Error (https://www.example.com/): Garbage at end of calendar response')],
        },
        name: 'should accumulate body errors (no fudge)',
      },
      {
        responseBody: Uint8Array.of(0x00, ...uint8ArrayFromHex('0588960d73d71901'), 1, 123),
        responseError: null,
        expected: {
          timestamp: {
            version: 1,
            fileHash: {
              algorithm: 'sha1',
              value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
            },
            tree: {
              edges: new EdgeMap().add(
                { type: 'sha256' },
                { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
              ),
              leaves: new LeafSet(),
            },
          } as Timestamp,
          errors: [],
        },
        name: 'should return merged timestamp (no fudge)',
      },
    ])(
      '$name',
      ({
        responseBody,
        responseError,
        expected,
      }:
        | {
            responseBody: Uint8Array;
            responseError: null;
            expected: { timestamp: Timestamp | undefined; errors: Error[] };
          }
        | {
            responseBody: null;
            responseError: Error | string;
            expected: { timestamp: Timestamp | undefined; errors: Error[] };
          }): void => {
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation((_input: string | URL | globalThis.Request, _init?: RequestInit): Promise<Response> => {
            if (null === responseError) {
              return Promise.resolve(new Response(responseBody, { status: 200 }));
            } else {
              // eslint-disable-next-line @typescript-eslint/no-throw-literal
              throw responseError;
            }
          });

        void expect(
          submit('sha1', uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'), Uint8Array.of(), [
            new URL('https://www.example.com'),
          ]).then(
            ({
              timestamp,
              errors,
            }: {
              timestamp: Timestamp | undefined;
              errors: Error[];
            }): { timestamp: string | undefined; errors: Error[] } => {
              return { timestamp: undefined === timestamp ? undefined : timestampToString(timestamp), errors };
            },
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (_reason: any): void => {
              throw new Error('unexpected');
            },
          ),
        ).resolves.toStrictEqual({
          timestamp: undefined === expected.timestamp ? undefined : timestampToString(expected.timestamp),
          errors: expected.errors,
        });
      },
    );

    const theFudgedTimestamp: Timestamp = {
      version: 1,
      fileHash: { algorithm: 'sha1', value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233') },
      tree: {
        leaves: new LeafSet(),
        edges: new EdgeMap().add(
          { type: 'append', operand: Uint8Array.of(1, 2, 3, 4, 5, 6) },
          { leaves: new LeafSet(), edges: new EdgeMap().add({ type: 'sha256' }, newTree()) },
        ),
      },
    };

    it.each([
      {
        responseBody: null,
        responseError: 'something',
        expected: {
          timestamp: theFudgedTimestamp,
          errors: [new Error('Error (https://www.example.com/): Unknown fetch() error')],
        },
        name: 'should accumulate unknown fetch errors',
      },
      {
        responseBody: null,
        responseError: new Error('something'),
        expected: {
          timestamp: theFudgedTimestamp,
          errors: [new Error('Error (https://www.example.com/): something')],
        },
        name: 'should accumulate fetch errors',
      },
      {
        responseBody: Uint8Array.of(0x00, ...uint8ArrayFromHex('0588960d73d71901'), 1, 123, 456),
        responseError: null,
        expected: {
          timestamp: theFudgedTimestamp,
          errors: [new Error('Error (https://www.example.com/): Garbage at end of calendar response')],
        },
        name: 'should accumulate body errors',
      },
      {
        responseBody: Uint8Array.of(0x00, ...uint8ArrayFromHex('0588960d73d71901'), 1, 123),
        responseError: null,
        expected: {
          timestamp: {
            version: 1,
            fileHash: {
              algorithm: 'sha1',
              value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
            },
            tree: {
              edges: new EdgeMap().add(
                { type: 'append', operand: Uint8Array.of(1, 2, 3, 4, 5, 6) },
                {
                  leaves: new LeafSet(),
                  edges: new EdgeMap().add(
                    { type: 'sha256' },
                    { edges: new EdgeMap(), leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }) },
                  ),
                },
              ),
              leaves: new LeafSet(),
            },
          } as Timestamp,
          errors: [],
        },
        name: 'should return merged timestamp',
      },
    ])(
      '$name',
      ({
        responseBody,
        responseError,
        expected,
      }:
        | {
            responseBody: Uint8Array;
            responseError: null;
            expected: { timestamp: Timestamp; errors: Error[] };
          }
        | {
            responseBody: null;
            responseError: Error | string;
            expected: { timestamp: Timestamp; errors: Error[] };
          }): void => {
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation((_input: string | URL | globalThis.Request, _init?: RequestInit): Promise<Response> => {
            if (null === responseError) {
              return Promise.resolve(new Response(responseBody, { status: 200 }));
            } else {
              // eslint-disable-next-line @typescript-eslint/no-throw-literal
              throw responseError;
            }
          });

        void expect(
          submit(
            'sha1',
            uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
            Uint8Array.of(1, 2, 3, 4, 5, 6),
            [new URL('https://www.example.com')],
          ).then(
            ({
              timestamp,
              errors,
            }: {
              timestamp: Timestamp | undefined;
              errors: Error[];
            }): { timestamp: string | undefined; errors: Error[] } => {
              return { timestamp: undefined === timestamp ? undefined : timestampToString(timestamp), errors };
            },
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (_reason: any): void => {
              throw new Error('unexpected');
            },
          ),
        ).resolves.toStrictEqual({
          timestamp: timestampToString(expected.timestamp),
          errors: expected.errors,
        });
      },
    );
  });
});
