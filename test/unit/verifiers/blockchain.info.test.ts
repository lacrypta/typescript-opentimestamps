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
import { default as verify } from '../../../src/verifiers/blockchain.info';

const textEncoder: TextEncoder = new TextEncoder();

describe('blockchain.info', (): void => {
  describe('verify()', (): void => {
    it.each([
      {
        msg: Uint8Array.of(),
        leaf: { type: 'pending', url: new URL('http://www.example.com') } as Leaf,
        body: Uint8Array.of(),
        expected: undefined,
        error: null,
        name: 'should ignore non-bitcoin leaves',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        body: textEncoder.encode('123'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on non-object response',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        body: textEncoder.encode('null'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on null response',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        body: textEncoder.encode('{}'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on missing .mrkl_root key',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        body: textEncoder.encode('{"mrkl_root":123}'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on non-string .mrkl_root',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        body: textEncoder.encode('{"mrkl_root":"something"}'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on non-hex .mrkl_root',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        body: textEncoder.encode('{"mrkl_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}'),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on missing .time key',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        body: textEncoder.encode(
          '{"mrkl_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","time":"something"}',
        ),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on non-numeric .time key',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        body: textEncoder.encode(
          '{"mrkl_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","time":-123}',
        ),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on negative .time key',
      },
      {
        msg: Uint8Array.of(),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        body: textEncoder.encode(
          '{"mrkl_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","time":12345678901234567890}',
        ),
        expected: null,
        error: new Error('Malformed response'),
        name: 'should fail on non-safe integer .time key',
      },
      {
        msg: Uint8Array.of(4, 5, 6),
        leaf: { type: 'bitcoin', height: 123 } as Leaf,
        body: textEncoder.encode(
          '{"mrkl_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","time":123}',
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
        body: textEncoder.encode(
          '{"mrkl_root":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","time":123}',
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
        body,
        expected,
        error,
      }:
        | {
            msg: Uint8Array;
            leaf: Leaf;
            body: Uint8Array;
            expected: number | undefined;
            error: null;
          }
        | {
            msg: Uint8Array;
            leaf: Leaf;
            body: Uint8Array;
            expected: null;
            error: Error;
          }): void => {
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation((_input: string | URL | globalThis.Request, _init?: RequestInit): Promise<Response> => {
            return Promise.resolve(new Response(body, { status: 200 }));
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
