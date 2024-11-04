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

import type { Leaf } from '../../../src/types';

import { uint8ArrayFromHex, uint8ArrayReversed } from '../../../src/utils';
import { default as verify } from '../../../src/verifiers/blockstream';

const textEncoder: TextEncoder = new TextEncoder();

describe('blockstream', (): void => {
  describe('verify()', (): void => {
    it.each([
      {
        msg: Uint8Array.of(),
        leaf: { type: 'pending', url: new URL('http://www.example.com') } as Leaf,
        blockHashBody: Uint8Array.of(),
        blockBody: Uint8Array.of(),
        status: 200,
        expected: undefined,
        error: null,
        name: 'should ignore non-bitcoin leaves',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('something'),
        blockBody: Uint8Array.of(),
        status: 200,
        expected: null,
        error: new Error('Malformed block hash'),
        name: 'should fail for non-hex blockHash',
      },

      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode('123'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on non-object response',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode('null'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on null response',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode('{}'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on missing .merkle_root key',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode('{"merkle_root":123}'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on non-string .merkle_root',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode('{"merkle_root":"something"}'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on non-hex .merkle_root',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode(
          '{"merkle_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}',
        ),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on missing .timestamp key',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode(
          '{"merkle_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","timestamp":"something"}',
        ),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on non-numeric .timestamp key',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode(
          '{"merkle_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","timestamp":-123}',
        ),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on negative .timestamp key',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode(
          '{"merkle_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","timestamp":12345678901234567890}',
        ),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on non-safe integer .timestamp key',
      },
      {
        msg: Uint8Array.of(4, 5, 6),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode(
          '{"merkle_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","timestamp":123}',
        ),
        expected: null,
        error: new Error(
          'Merkle root mismatch (expected 060504 but found 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)',
        ),
        name: 'should fail for non-matching message',
      },
      {
        msg: uint8ArrayReversed(uint8ArrayFromHex('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        blockHashBody: textEncoder.encode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
        blockBody: textEncoder.encode(
          '{"merkle_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","timestamp":123}',
        ),
        expected: 123,
        error: null,
        name: 'should pass for matching message',
      },
    ])(
      '$name',
      ({
        msg,
        leaf,
        blockHashBody,
        blockBody,
        expected,
        error,
      }:
        | {
            msg: Uint8Array;
            leaf: Leaf;
            blockHashBody: Uint8Array;
            blockBody: Uint8Array;
            expected: number | undefined;
            error: null;
          }
        | {
            msg: Uint8Array;
            leaf: Leaf;
            blockHashBody: Uint8Array;
            blockBody: Uint8Array;
            expected: null;
            error: Error;
          }): void => {
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation((input: string | URL | globalThis.Request, _init?: RequestInit): Promise<Response> => {
            const url: string = 'object' === typeof input && 'url' in input ? input.url : input.toString();
            if (url.startsWith('https://blockstream.info/api/block-height/')) {
              return Promise.resolve(new Response(blockHashBody, { status: 200 }));
            } else {
              return Promise.resolve(new Response(blockBody, { status: 200 }));
            }
          });
        if (null !== error) {
          void expect(verify(msg, leaf)).rejects.toStrictEqual(error);
        } else {
          void expect(verify(msg, leaf)).resolves.toStrictEqual(expected);
        }
      },
    );
  });
});
