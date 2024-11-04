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

import {
  fetchBody,
  retrieveGetBody,
  retrievePostBody,
  textDecoder as textDecoderUnderTest,
  textEncoder as textEncoderUnderTest,
  uint8ArrayCompare,
  uint8ArrayConcat,
  uint8ArrayEquals,
  uint8ArrayFromBase64,
  uint8ArrayFromHex,
  uint8ArrayReversed,
  uint8ArrayToBase64,
  uint8ArrayToHex,
} from '../../src/utils';

const textEncoder: TextEncoder = new TextEncoder();

describe('Utils', (): void => {
  describe('uint8ArrayToHex()', (): void => {
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
    ])('$name', ({ array, expected }: { array: Uint8Array; expected: string }): void => {
      expect(uint8ArrayToHex(array)).toEqual(expected);
    });
  });

  describe('uint8ArrayFromHex()', (): void => {
    it.each([
      {
        hex: '',
        expected: Uint8Array.of(),
        error: null,
        name: 'should return empty array for empty string',
      },
      {
        hex: '1',
        expected: null,
        error: new Error('Hex value should be of even length, found 1'),
        name: 'should fail for odd length',
      },
      {
        hex: '12345',
        expected: null,
        error: new Error('Hex value should be of even length, found 5'),
        name: 'should fail for odd length (again)',
      },
      {
        hex: '0z',
        expected: null,
        error: new Error('Malformed hex string'),
        name: 'should fail for non-hexadecimal string',
      },
    ])(
      '$name',
      ({
        hex,
        expected,
        error,
      }: { hex: string; expected: Uint8Array; error: null } | { hex: string; expected: null; error: Error }): void => {
        if (null === error) {
          expect(uint8ArrayFromHex(hex)).toStrictEqual(expected);
        } else {
          expect((): void => {
            uint8ArrayFromHex(hex);
          }).toThrow(error);
        }
      },
    );
  });

  describe('uint8ArrayToBase64()', (): void => {
    it.each([
      {
        array: Uint8Array.of(),
        expected: '',
        name: 'should return empty string for empty input',
      },
      {
        array: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21),
        expected: 'AQIDBAUGBwgJCgsMDQ4PEBESExQV',
        name: 'should correctly convert to base64',
      },
    ])('$name', ({ array, expected }: { array: Uint8Array; expected: string }): void => {
      expect(uint8ArrayToBase64(array)).toEqual(expected);
    });
  });

  describe('uint8ArrayFromBase64()', (): void => {
    it.each([
      {
        base64: '',
        expected: Uint8Array.of(),
        error: null,
        name: 'should return empty array for empty string',
      },
      {
        base64: 'abcde',
        expected: null,
        error: new DOMException('The string to be decoded is not correctly encoded.'),
        name: 'should fail for mis-encoded string',
      },
      {
        base64: 'abc[',
        expected: null,
        error: new DOMException('Invalid character'),
        name: 'should fail for non-base64 string',
      },
      {
        base64: 'AQIDBAUGBwgJCgsMDQ4PEBESExQV',
        expected: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21),
        error: null,
        name: 'should correctly convert from base64',
      },
    ])(
      '$name',
      ({
        base64,
        expected,
        error,
      }:
        | { base64: string; expected: Uint8Array; error: null }
        | { base64: string; expected: null; error: DOMException }): void => {
        if (null === error) {
          expect(uint8ArrayFromBase64(base64)).toStrictEqual(expected);
        } else {
          expect((): void => {
            uint8ArrayFromBase64(base64);
          }).toThrow(error);
        }
      },
    );
  });

  describe('uint8ArrayEquals()', (): void => {
    it.each([
      {
        left: Uint8Array.of(),
        right: Uint8Array.of(),
        expected: true,
        name: 'should return true for empty arrays',
      },
      {
        left: Uint8Array.of(1),
        right: Uint8Array.of(),
        expected: false,
        name: 'should return false for arrays of differing length',
      },
      {
        left: Uint8Array.of(1),
        right: Uint8Array.of(2),
        expected: false,
        name: 'should return false for arrays of differing contents',
      },
      {
        left: Uint8Array.of(1),
        right: Uint8Array.of(1),
        expected: true,
        name: 'should return true for equal arrays',
      },
    ])('$name', ({ left, right, expected }: { left: Uint8Array; right: Uint8Array; expected: boolean }): void => {
      expect(uint8ArrayEquals(left, right)).toEqual(expected);
    });
  });

  describe('uint8ArrayCompare()', (): void => {
    it.each([
      {
        left: Uint8Array.of(),
        right: Uint8Array.of(),
        expected: 0,
        name: 'should return 0 for equal arrays',
      },
      {
        left: Uint8Array.of(1, 2, 3),
        right: Uint8Array.of(1, 2, 3),
        expected: 0,
        name: 'should return 0 for equal arrays (again',
      },
      {
        left: Uint8Array.of(1, 2, 3),
        right: Uint8Array.of(),
        expected: 3,
        name: 'should return positive for longer left array',
      },
      {
        left: Uint8Array.of(),
        right: Uint8Array.of(1, 2, 3),
        expected: -3,
        name: 'should return negative for longer right array',
      },
      {
        left: Uint8Array.of(1, 2, 3),
        right: Uint8Array.of(1, 2, 2),
        expected: 1,
        name: 'should return positive for bigger left array of the same length',
      },
      {
        left: Uint8Array.of(1, 2, 2),
        right: Uint8Array.of(1, 2, 3),
        expected: -1,
        name: 'should return negative for bigger right array of the same length',
      },
      {
        left: Uint8Array.of(1, 2, 3, 4),
        right: Uint8Array.of(1, 2, 2),
        expected: 1,
        name: 'should return positive for bigger left array of different length',
      },
      {
        left: Uint8Array.of(1, 2, 2, 4),
        right: Uint8Array.of(1, 2, 3),
        expected: -1,
        name: 'should return negative for bigger right array of different length',
      },
    ])('$name', ({ left, right, expected }: { left: Uint8Array; right: Uint8Array; expected: number }): void => {
      expect(uint8ArrayCompare(left, right)).toEqual(expected);
    });
  });

  describe('uint8ArrayConcat()', (): void => {
    it.each([
      {
        arrays: [],
        expected: Uint8Array.of(),
        name: 'should return empty for empty input',
      },
      {
        arrays: [Uint8Array.of(1, 2, 3)],
        expected: Uint8Array.of(1, 2, 3),
        name: 'should return its input for singular input',
      },
      {
        arrays: [Uint8Array.of(1, 2, 3), Uint8Array.of()],
        expected: Uint8Array.of(1, 2, 3),
        name: 'should return its input for singular input and empty array',
      },
      {
        arrays: [Uint8Array.of(1, 2, 3), Uint8Array.of(), Uint8Array.of(4, 5, 6)],
        expected: Uint8Array.of(1, 2, 3, 4, 5, 6),
        name: 'should treat empty arrays as non-existing',
      },
    ])('$name', ({ arrays, expected }: { arrays: Uint8Array[]; expected: Uint8Array }): void => {
      expect(uint8ArrayConcat(...arrays)).toEqual(expected);
    });
  });

  describe('uint8ArrayReversed()', (): void => {
    it.each([
      {
        array: Uint8Array.of(),
        expected: Uint8Array.of(),
        name: 'should return empty for empty array',
      },
      {
        array: Uint8Array.of(1, 2, 3),
        expected: Uint8Array.of(3, 2, 1),
        name: 'should reverse non-return array',
      },
    ])('$name', ({ array, expected }: { array: Uint8Array; expected: Uint8Array }): void => {
      expect(uint8ArrayReversed(array)).toEqual(expected);
    });
  });

  describe('fetchBody()', (): void => {
    it.each([
      {
        response: uint8ArrayFromHex('123abc'),
        responseCode: 200,
        responseError: null,
        expected: uint8ArrayFromHex('123abc'),
        error: null,
        name: 'should correctly return on 2xx and non-empty body',
      },
      {
        response: uint8ArrayFromHex('123abc'),
        responseCode: 300,
        responseError: null,
        expected: null,
        error: new Error('Error retrieving response body'),
        name: 'should fail on 3xx status',
      },
      {
        response: uint8ArrayFromHex('123abc'),
        responseCode: 400,
        responseError: null,
        expected: null,
        error: new Error('Error retrieving response body'),
        name: 'should fail on 4xx status',
      },
      {
        response: uint8ArrayFromHex('123abc'),
        responseCode: 500,
        responseError: null,
        expected: null,
        error: new Error('Error retrieving response body'),
        name: 'should fail on 5xx status',
      },
      {
        response: null,
        responseCode: 200,
        responseError: null,
        expected: null,
        error: new Error('Error retrieving response body'),
        name: 'should fail on 2xx status and null body',
      },
      {
        response: uint8ArrayFromHex(''),
        responseCode: 0,
        responseError: new Error('Some fetch() error you may encounter'),
        expected: null,
        error: new Error('Some fetch() error you may encounter'),
        name: 'should fail on fetch() throwing an Error',
      },
      {
        response: uint8ArrayFromHex(''),
        responseCode: 0,
        responseError: 'Something else entirely',
        expected: null,
        error: new Error('Unknown fetch() error'),
        name: 'should fail on fetch() throwing anything else',
      },
    ])(
      '$name',
      ({
        response,
        responseCode,
        responseError,
        expected,
        error,
      }:
        | {
            response: Uint8Array | null;
            responseCode: number;
            responseError: string | Error | null;
            expected: Uint8Array;
            error: null;
          }
        | {
            response: Uint8Array | null;
            responseCode: number;
            responseError: string | Error | null;
            expected: null;
            error: Error;
          }): void => {
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation((_input: string | URL | globalThis.Request, _init?: RequestInit): Promise<Response> => {
            if (null !== responseError) {
              // eslint-disable-next-line @typescript-eslint/no-throw-literal
              throw responseError;
            }
            return Promise.resolve(new Response(response, { status: responseCode }));
          });
        if (null !== error) {
          void expect(fetchBody(new URL('http://www.example.com'))).rejects.toStrictEqual(error);
        } else {
          void expect(fetchBody(new URL('http://www.example.com'))).resolves.toStrictEqual(expected);
        }
      },
    );
  });

  describe('retrieveGetBody()', (): void => {
    test('should use GET method', (): void => {
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation((_input: string | URL | globalThis.Request, init?: RequestInit): Promise<Response> => {
          return Promise.resolve(new Response(`method:${init?.method}`));
        });
      expect(retrieveGetBody(new URL('http://www.example.com'))).toStrictEqual(
        Promise.resolve(textEncoder.encode('method:GET')),
      );
    });
  });

  describe('retrievePostBody()', (): void => {
    it.each([
      {
        body: Uint8Array.of(),
        expected: 'method:POST;body:',
        name: 'should post when empty body',
      },
      {
        body: Uint8Array.of(1, 2, 3),
        expected: 'method:POST;body:010203',
        name: 'should post when non-empty body',
      },
    ])('$name', ({ body, expected }: { body: Uint8Array; expected: string }): void => {
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(
          async (_input: string | URL | globalThis.Request, init?: RequestInit): Promise<Response> => {
            return new Response(
              textEncoder.encode(
                `method:${init?.method};body:${uint8ArrayToHex(
                  new Uint8Array(await new Response(init?.body).arrayBuffer()),
                )}`,
              ),
            );
          },
        );
      void expect(retrievePostBody(new URL('http://www.example.com'), body)).resolves.toStrictEqual(
        textEncoder.encode(expected),
      );
    });
  });

  describe('textEncoder', (): void => {
    test('should be of TextEncoder class', (): void => {
      expect(textEncoderUnderTest.constructor.name).toStrictEqual(new TextEncoder().constructor.name);
    });
  });

  describe('textDecoder', (): void => {
    test('should be of TextDecoder class', (): void => {
      expect(textDecoderUnderTest.constructor.name).toStrictEqual(new TextDecoder().constructor.name);
    });
  });
});
