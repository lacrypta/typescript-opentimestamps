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

import type { Timestamp, Tree } from '../../src/types';

import { EdgeMap, LeafSet } from '../../src/internals';
import { upgrade, upgradeFromCalendar, upgradeTree } from '../../src/upgrade';
import { uint8ArrayFromHex } from '../../src/utils';

import { timestampToString, treeToString } from '../helpers';

describe('Upgrade', (): void => {
  describe('upgradeFromCalendar()', (): void => {
    it.each([
      {
        calendarResponse: uint8ArrayFromHex('000588960d73d71901017b'),
        result: { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
        error: null,
        name: 'should deal with simple tree',
      },
      {
        calendarResponse: uint8ArrayFromHex('000588960d73d71901017b012345'),
        result: null,
        error: new Error(`Garbage at end of calendar response`),
        name: 'should fail with garbage at EOF',
      },
    ])(
      '$name',
      ({
        calendarResponse,
        result,
        error,
      }:
        | { calendarResponse: Uint8Array; result: Tree; error: null }
        | { calendarResponse: Uint8Array; result: null; error: Error }): void => {
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation((_input: string | URL | globalThis.Request, _init?: RequestInit): Promise<Response> => {
            return Promise.resolve(new Response(calendarResponse, { status: 200 }));
          });

        if (null === error) {
          void expect(
            upgradeFromCalendar(new URL('https://www.example.com'), Uint8Array.of()).then(treeToString),
          ).resolves.toStrictEqual(treeToString(result));
        } else {
          void expect(upgradeFromCalendar(new URL('https://www.example.com'), Uint8Array.of())).rejects.toStrictEqual(
            error,
          );
        }
      },
    );
  });

  describe('upgradeTree()', (): void => {
    it.each([
      {
        tree: {
          edges: new EdgeMap(),
          leaves: new LeafSet().add({ type: 'pending', url: new URL('http://www.example.com') }),
        },
        calendarResponse: uint8ArrayFromHex('000588960d73d71901017b'),
        expected: [{ leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() }, []] as [
          Tree,
          Error[],
        ],
        name: 'should deal with simple tree',
      },
      {
        tree: {
          edges: new EdgeMap(),
          leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
        },
        calendarResponse: uint8ArrayFromHex('000588960d73d71901017b'),
        expected: [
          {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          },
          [],
        ] as [Tree, Error[]],
        name: 'should deal with complete tree',
      },
      {
        tree: {
          edges: new EdgeMap(),
          leaves: new LeafSet().add({ type: 'pending', url: new URL('http://www.example.com') }),
        },
        calendarResponse: uint8ArrayFromHex('000588960d73d71901017b012345'),
        expected: [
          {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'pending', url: new URL('http://www.example.com') }),
          },
          [new Error('Error (http://www.example.com/): Garbage at end of calendar response')],
        ] as [Tree, Error[]],
        name: 'should fail with garbage at EOF',
      },
    ])(
      '$name',
      ({
        tree,
        calendarResponse,
        expected,
      }: {
        tree: Tree;
        calendarResponse: Uint8Array;
        expected: [Tree, Error[]];
      }): void => {
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation((_input: string | URL | globalThis.Request, _init?: RequestInit): Promise<Response> => {
            return Promise.resolve(new Response(calendarResponse, { status: 200 }));
          });

        void expect(
          upgradeTree(tree, Uint8Array.of()).then(
            ({ tree: resultTree, errors: resultErrors }: { tree: Tree; errors: Error[] }): [string, Error[]] => {
              return [treeToString(resultTree), resultErrors];
            },
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (_reason: any): void => {
              throw new Error('unexpected');
            },
          ),
        ).resolves.toStrictEqual([treeToString(expected[0]), expected[1]]);
      },
    );
  });

  describe('upgrade()', (): void => {
    it.each([
      {
        timestamp: {
          version: 1,
          fileHash: {
            algorithm: 'sha1',
            value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
          },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'pending', url: new URL('http://www.example.com') }),
          },
        } as Timestamp,
        calendarResponse: uint8ArrayFromHex('000588960d73d71901017b'),
        expected: {
          timestamp: {
            version: 1,
            fileHash: {
              algorithm: 'sha1',
              value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
            },
            tree: { leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }), edges: new EdgeMap() },
          },
          errors: [],
        } as { timestamp: Timestamp; errors: Error[] },
        name: 'should deal with simple timestamp',
      },
      {
        timestamp: {
          version: 1,
          fileHash: {
            algorithm: 'sha1',
            value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
          },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
          },
        } as Timestamp,
        calendarResponse: uint8ArrayFromHex('000588960d73d71901017b'),
        expected: {
          timestamp: {
            version: 1,
            fileHash: {
              algorithm: 'sha1',
              value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
            },
            tree: {
              edges: new EdgeMap(),
              leaves: new LeafSet().add({ type: 'bitcoin', height: 123 }),
            },
          },
          errors: [],
        } as { timestamp: Timestamp; errors: Error[] },
        name: 'should deal with complete timestamp',
      },
      {
        timestamp: {
          version: 1,
          fileHash: {
            algorithm: 'sha1',
            value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
          },
          tree: {
            edges: new EdgeMap(),
            leaves: new LeafSet().add({ type: 'pending', url: new URL('http://www.example.com') }),
          },
        } as Timestamp,
        calendarResponse: uint8ArrayFromHex('000588960d73d71901017b012345'),
        expected: {
          timestamp: {
            version: 1,
            fileHash: {
              algorithm: 'sha1',
              value: uint8ArrayFromHex('00112233445566778899aabbccddeeff00112233'),
            },
            tree: {
              edges: new EdgeMap(),
              leaves: new LeafSet().add({ type: 'pending', url: new URL('http://www.example.com') }),
            },
          },
          errors: [new Error('Error (http://www.example.com/): Garbage at end of calendar response')],
        } as { timestamp: Timestamp; errors: Error[] },
        name: 'should fail with garbage at EOF',
      },
    ])(
      '$name',
      ({
        timestamp,
        calendarResponse,
        expected,
      }: {
        timestamp: Timestamp;
        calendarResponse: Uint8Array;
        expected: { timestamp: Timestamp; errors: Error[] };
      }): void => {
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation((_input: string | URL | globalThis.Request, _init?: RequestInit): Promise<Response> => {
            return Promise.resolve(new Response(calendarResponse, { status: 200 }));
          });

        void expect(
          upgrade(timestamp).then(
            ({
              timestamp: resultTimestamp,
              errors: resultErrors,
            }: {
              timestamp: Timestamp;
              errors: Error[];
            }): { timestamp: string; errors: Error[] } => {
              return { timestamp: timestampToString(resultTimestamp), errors: resultErrors };
            },
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (_reason: any): void => {
              throw new Error('unexpected');
            },
          ),
        ).resolves.toStrictEqual({ timestamp: timestampToString(expected.timestamp), errors: expected.errors });
      },
    );
  });
});
