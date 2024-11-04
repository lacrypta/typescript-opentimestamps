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
import type { Path } from '../../src/internals';

import { callOps, treeToPaths } from '../../src/internals';
import { read } from '../../src/read';
import { uint8ArrayConcat, uint8ArrayFromBase64, uint8ArrayFromHex } from '../../src/utils';
import { writeLeaf } from '../../src/write';

describe('javascript-opentimestamps', (): void => {
  it.each([
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEIfjcXu+Ag9TzcbEAVShqOVb3cE6KMi7PILp7mS4G0SHID8cgBAQAAAAHkgvnTLsw7ple2nYmAEIV7
        VEV6kEl5gv9W+XxOxY5vmAEAAABrSDBFAiEAslOt0dHPkIRDOKR1oE/xP8nnvSQrB3Yt6gf1YIst42cCIACyaMqcM0KzdpzdBiiRMXzc74eqwxC2hV6dk4mO
        u+jsASECDY5NEH0rM5sAUO/dS0oJJFqgVgSPElOWN06moqsHCcb/////AmUz5gUAAAAAGXapFAvwV9QPu6Z0SGJRX1tVojEN5XcviKyghgEAAAAAABl2qRTw
        BoisAAAAAAgI8SCph/cWxTORPDFMeONdNYhMrJQ/pCysSdKyxp9AA/hfiAgI8SDexVs0h+Hj9yKkm1WneDIVhieF9KOss5KEYBn3HcZKnQgI8SCyyhj0heCA
        R44CXas9RktBbA4ey2Ypya786MghTQQkMggI8CARsOkGYRlv9LCBPD7aFBurXpFgSDe996DJ3zfbDjoRmAgI8CDDS8GkoQk//RSMAWseZkdCkU6Tnvq+TT01
        ZRWRSybZ4ggI8CDD5ufDjGn2ryTCvjTrrEglft5h7AohuVNeREMne+MGRggI8SAHmL+GBuAAJOXV1UvwyWD2Kd+52taRV0VbbyZSwOjegQgI8CA/mtptYLqi
        RABrsKrVFEitL6+51LZIegmZz/JrkfD1NggI8SDHAwGelZqN0/rvdIm7MoukhVdHWOcJHwFGTrZYcsl1yAgI8CDL/v/1E/+EuRXj/tb515lnZjD4Nk6ipsdV
        f62UpbXXiAgI8SAL4jcJhZkTur1EYLvd+O0hPnyHc6Sx+s4w+Kz98JO3BQgIAAWIlg1z1xkBA/fvFQ==
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('921f81b9147c9aebe712d7805d810cf0f762479967e4c26008178277b89db41b'),
          writeLeaf({ type: 'bitcoin', height: 358391 }),
        ),
      ]),
      name: 'Bad stamp',
    },
    {
      input: uint8ArrayFromBase64(`
        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
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('715b7e36276a66d842e56dd102c9d9eddfe4d9f2dfa908ae31157ac2c2fd29db'),
          writeLeaf({ type: 'bitcoin', height: 129405 }),
        ),
      ]),
      name: 'Empty',
    },
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEIA7ogTlDRJuRnTABeBNguhMITZngK8fQ71Uo3gWtqs0AD8cgBAQAAAAHkgvnTLsw7ple2nYmAEIV7
        VEV6kEl5gv9W+XxOxY5vmAEAAABrSDBFAiEAslOt0dHPkIRDOKR1oE/xP8nnvSQrB3Yt6gf1YIst42cCIACyaMqcM0KzdpzdBiiRMXzc74eqwxC2hV6dk4mO
        u+jsASECDY5NEH0rM5sAUO/dS0oJJFqgVgSPElOWN06moqsHCcb/////AmUz5gUAAAAAGXapFAvwV9QPu6Z0SGJRX1tVojEN5XcviKyghgEAAAAAABl2qRTw
        BoisAAAAAAgI8SCph/cWxTORPDFMeONdNYhMrJQ/pCysSdKyxp9AA/hfiAgI8SDexVs0h+Hj9yKkm1WneDIVhieF9KOss5KEYBn3HcZKnQgI8SCyyhj0heCA
        R44CXas9RktBbA4ey2Ypya786MghTQQkMggI8CARsOkGYRlv9LCBPD7aFBurXpFgSDe996DJ3zfbDjoRmAgI8CDDS8GkoQk//RSMAWseZkdCkU6Tnvq+TT01
        ZRWRSybZ4ggI8CDD5ufDjGn2ryTCvjTrrEglft5h7AohuVNeREMne+MGRggI8SAHmL+GBuAAJOXV1UvwyWD2Kd+52taRV0VbbyZSwOjegQgI8CA/mtptYLqi
        RABrsKrVFEitL6+51LZIegmZz/JrkfD1NggI8SDHAwGelZqN0/rvdIm7MoukhVdHWOcJHwFGTrZYcsl1yAgI8CDL/v/1E/+EuRXj/tb515lnZjD4Nk6ipsdV
        f62UpbXXiAgI8SAL4jcJhZkTur1EYLvd+O0hPnyHc6Sx+s4w+Kz98JO3BQgIAAWIlg1z1xkBA/fvFQ==
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a'),
          writeLeaf({ type: 'bitcoin', height: 358391 }),
        ),
      ]),
      name: 'Hello world',
    },
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEIBcT2FqjlMQ0Z2TjP12mGTX9MzcLKi0ebEK+DVksJevnwEOdUv5OAan66poDve9ARS/QI8BC1c+iF
        DP2eY9HwQ/u2/CUOCPEEV8+lxPAIb7GsjU5OsOcAg9/jDS75DI4uLWh0dHBzOi8vYWxpY2UuYnRjLmNhbGVuZGFyLm9wZW50aW1lc3RhbXBzLm9yZw==
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('57cfa5c46716df9bd9e83595bce439c58108d8fcc1678f30d4c6731c3f1fa6c79ed712c66fb1ac8d4e4eb0e7'),
          writeLeaf({ type: 'pending', url: new URL('https://alice.btc.calendar.opentimestamps.org') }),
        ),
      ]),
      name: 'Incomplete',
    },
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEI0oiy7iErAePl9tMz3zpNU/KSzD8HsJATwLQMjn3LnAPwEEbYQr1dg3fg9CBBvsm9pmcI//AQMyxX
        L5xLjV252ZdY1I//NAjxBFfonzjwCHPG3E0MvCnwAIPf4w0u+QyOLCtodHRwczovL2JvYi5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn8BDnrSkH
        bxiAM9IHZ2Aso6jgCPEEV+ifN/AIYt9WNxriPY0AAQIDBAUGBwgueHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('57e89f38173f127e0e8832929232858ca0b7241229d535b22073144a1a433b5aaa5d6cf473c6dc4d0cbc29f0'),
          writeLeaf({ type: 'pending', url: new URL('https://bob.btc.calendar.opentimestamps.org') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('57e89f37c0b849c680f7c6e13c719a3bfa96ce53c83095eca7c5a244ca991aeebbc87a4e62df56371ae23d8d'),
          writeLeaf({
            type: 'unknown',
            header: uint8ArrayFromHex('0102030405060708'),
            payload: uint8ArrayFromHex(
              '78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878',
            ),
          }),
        ),
      ]),
      name: 'Known and unknown notary',
    },
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEI0y/umoJ/Wg1YD4C+t+3OZi3Zn81lkeTvimJEQD3wt8nwEAIBo2rAxzaS0c7cq/8GCesI8CCfQphM
        zblq3beYhOcUzGtrBZxo8qw6LgfFGYwi2QTeFAjwIAJjVueXLwI5MOyEwhOt7cQFBGCXOTW70vTfPXvV3sVfCP/wEC4SBQr9ehDqT1ke1xfTXeYI8QRX2YLf
        8Aix8m4uVVkEdwCD3+MNLvkMji4taHR0cHM6Ly9hbGljZS5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn8BBKqt6cL/uFPM/5wHaB0Bn9CPEEV9mC
        4PAIZkTvcTBxdioAg9/jDS75DI4sK2h0dHBzOi8vYm9iLmJ0Yy5jYWxlbmRhci5vcGVudGltZXN0YW1wcy5vcmc=
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('57d982df8b35bc0a91a93d6d17e0162868dc123bc8b1bbfab22af9268f7fea70376b5cb0b1f26e2e55590477'),
          writeLeaf({ type: 'pending', url: new URL('https://alice.btc.calendar.opentimestamps.org') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('57d982e0a2181eb7fd470600d82119b73d7ae5da2d8c84db7d55fd45b568fac036d86f906644ef713071762a'),
          writeLeaf({ type: 'pending', url: new URL('https://bob.btc.calendar.opentimestamps.org') }),
        ),
      ]),
      name: 'Merkle 1/3',
    },
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEIi9Wl8HtEUcKXVt9etR0ZT7WyDH6JgS2He7rTDYccWC/wELY9jyE9BHKYuKtFlazY5dAI8SCuWdLA
        0vXvqX3488yn6FhFiAwQIjfxpqGwtMalq3f0lAjwIAJjVueXLwI5MOyEwhOt7cQFBGCXOTW70vTfPXvV3sVfCP/wEC4SBQr9ehDqT1ke1xfTXeYI8QRX2YLf
        8Aix8m4uVVkEdwCD3+MNLvkMji4taHR0cHM6Ly9hbGljZS5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn8BBKqt6cL/uFPM/5wHaB0Bn9CPEEV9mC
        4PAIZkTvcTBxdioAg9/jDS75DI4sK2h0dHBzOi8vYm9iLmJ0Yy5jYWxlbmRhci5vcGVudGltZXN0YW1wcy5vcmc=
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('57d982df8b35bc0a91a93d6d17e0162868dc123bc8b1bbfab22af9268f7fea70376b5cb0b1f26e2e55590477'),
          writeLeaf({ type: 'pending', url: new URL('https://alice.btc.calendar.opentimestamps.org') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('57d982e0a2181eb7fd470600d82119b73d7ae5da2d8c84db7d55fd45b568fac036d86f906644ef713071762a'),
          writeLeaf({ type: 'pending', url: new URL('https://bob.btc.calendar.opentimestamps.org') }),
        ),
      ]),
      name: 'Merkle 2/3',
    },
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEIOWamn8NEEHu08wxXQwXZtFCN8suOZd1GAHos+xFrlXnwEA6bSasBNFCANc4ml/GtCYUI8SALyh7R
        cYxxkpEwpjnwp7gu65Go+kWxZRDJ7hX+xKC/FQj/8BAuEgUK/XoQ6k9ZHtcX013mCPEEV9mC3/AIsfJuLlVZBHcAg9/jDS75DI4uLWh0dHBzOi8vYWxpY2Uu
        YnRjLmNhbGVuZGFyLm9wZW50aW1lc3RhbXBzLm9yZ/AQSqrenC/7hTzP+cB2gdAZ/QjxBFfZguDwCGZE73EwcXYqAIPf4w0u+QyOLCtodHRwczovL2JvYi5i
        dGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('57d982df8b35bc0a91a93d6d17e0162868dc123bc8b1bbfab22af9268f7fea70376b5cb0b1f26e2e55590477'),
          writeLeaf({ type: 'pending', url: new URL('https://alice.btc.calendar.opentimestamps.org') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('57d982e0a2181eb7fd470600d82119b73d7ae5da2d8c84db7d55fd45b568fac036d86f906644ef713071762a'),
          writeLeaf({ type: 'pending', url: new URL('https://bob.btc.calendar.opentimestamps.org') }),
        ),
      ]),
      name: 'Merkle 3/3',
    },
    {
      input: uint8ArrayFromBase64(`
        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
        LmV0ZXJuaXR5d2FsbC5jb20=
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('5affdc4e1090e6e90a30a2d885b01001ad6f402c84a3445a07507f9813513c1a37132208f6548d220342e113'),
          writeLeaf({ type: 'pending', url: new URL('https://bob.btc.calendar.opentimestamps.org') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('5affdc4e94e9623d7404a796c6ffc2664f27932c5f04cf7fa85001daa26f3c69bd5e03e6b93040fd06355849'),
          writeLeaf({ type: 'pending', url: new URL('https://alice.btc.calendar.opentimestamps.org') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('5affdc4f6bf0251bebfceb86f6c2e06ce715a06a65362e34a587f1808b4bab7ff625f646447dd8439ad3a8f6'),
          writeLeaf({ type: 'pending', url: new URL('https://btc.calendar.catallaxy.com') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('39780753a0e7785eea0fabafa8fbef1ef2539d26f6cbf3beac738a1de0e74f3c'),
          writeLeaf({ type: 'bitcoin', height: 523364 }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('5affdc4e9ca8db900367fd8d74967d67d57dbad0f3cdc715d217dfd5d07a4dbb1eacec03384e62331c930912'),
          writeLeaf({ type: 'pending', url: new URL('https://finney.calendar.eternitywall.com') }),
        ),
      ]),
      name: 'OSDSP',
    },
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEI76oXT2jllwV1dGD099IEvStTXP0ZTZ2UVBhzISlATdvwEIOQN+70Sd7G2sMiypc0fEUI//AQa0Aj
        tu3ToO7rCeXXGHI7ngjxBFfUZRXwCOrdZrFojVV0AIPf4w0u+QyOLi1odHRwczovL2FsaWNlLmJ0Yy5jYWxlbmRhci5vcGVudGltZXN0YW1wcy5vcmfwEKOt
        cB758QU1qElotamdhYAI8QRX1GUW8Ahke5DqGycKlwCD3+MNLvkMjiwraHR0cHM6Ly9ib2IuYnRjLmNhbGVuZGFyLm9wZW50aW1lc3RhbXBzLm9yZw==
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('57d46515fdd8c2334c77b1f204338bb2178d73e523988d7dcda13259d3a099f31623755deadd66b1688d5574'),
          writeLeaf({ type: 'pending', url: new URL('https://alice.btc.calendar.opentimestamps.org') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('57d4651676e9ac3b3b57c1584828ea5162979c96483a03c87c69a1b8614d1cbaf387e0f5647b90ea1b270a97'),
          writeLeaf({ type: 'pending', url: new URL('https://bob.btc.calendar.opentimestamps.org') }),
        ),
      ]),
      name: 'Two calendars',
    },
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEI3MIdHR9CpDaioH/JFd7ATbQbg8iYhFlIw9ZktmYPT5HwEF3ewMmaoL/ncAkGFX3XZbsI8BCevS1d
        31iE2elX6k4fdG/qCPEEV+idKPAI/SjWICYzGFwAAQIDBAUGBwgueHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('57e89d286d747eb37844e2f7a3e47f883487015a068004e8763af2e68e22f5bc558c3b72fd28d6202633185c'),
          writeLeaf({
            type: 'unknown',
            header: uint8ArrayFromHex('0102030405060708'),
            payload: uint8ArrayFromHex(
              '78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878',
            ),
          }),
        ),
      ]),
      name: 'Unknown notary',
    },
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEDBCPO1JFLxeR67aMUtZk7e9eW/gDwEGPNWQA4UzL5tNGib8gwjRAI//AQrgwIsfd2dfvFCx6L5HBF
        9wjwIBaSNqA2cpaenyG8eByLFhV2hxT1Rj1mbF8zqZqUdtxmCPAgfIjvdhZsGEc314nu6wktobksd+8xG13RFRlPdRspDmAI8QRaqlI98AhGZOdbaV8yKwCD
        3+MNLvkMji4taHR0cHM6Ly9hbGljZS5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn//AQhNq8jJjJJaO0u/bc6DKSIAjxBFqqUj3wCG4zXZAi+45N
        AIPf4w0u+QyOLCtodHRwczovL2JvYi5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn8BDEBzhUXRZz/8f2mr+gJ+UvCPEgya8q+bXOGIQwM3D3O9FR
        seJeBGRmDOVqAti5j8Do3KQI8QRaqlI98AjWw1fN+R5LFgCD3+MNLvkMjikoaHR0cHM6Ly9maW5uZXkuY2FsZW5kYXIuZXRlcm5pdHl3YWxsLmNvbQ==
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('5aaa523d23d28b7c856f513256db6f54780a5a3916e47e1a905344ce99dc7d643edf837d4664e75b695f322b'),
          writeLeaf({ type: 'pending', url: new URL('https://alice.btc.calendar.opentimestamps.org') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('5aaa523d98e7749616be9cc9dd920bed3b8704df9b3200a3ad0f6bda5866cdcbb920d64e6e335d9022fb8e4d'),
          writeLeaf({ type: 'pending', url: new URL('https://bob.btc.calendar.opentimestamps.org') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('5aaa523d66581cf4aa250590a66df884013284c19be941ea2381d0a381a6537020ab8100d6c357cdf91e4b16'),
          writeLeaf({ type: 'pending', url: new URL('https://finney.calendar.eternitywall.com') }),
        ),
      ]),
      name: 'ripemd160 - Readme',
    },
    {
      input: uint8ArrayFromBase64(`
        AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEC+S1044dFh6r0Q9Hblh1OJt3hPpzwED4Imsf4D7MbnNRMk6apF9wI//AQSlHXJ1hyYKPjrdTHUUqv
        OwjxBFkcXHnwCP/m10PYq3ya/wCD3+MNLvkMjikoaHR0cHM6Ly9maW5uZXkuY2FsZW5kYXIuZXRlcm5pdHl3YWxsLmNvbQjxIOjLqJkDtLSDf17GCnOyrl5Z
        EBwFc6AV5ys9YKBXFnGaCPAg7AMu2hT6dMHt08bF/yDDlZ6H5QBMvfudFxg8LKp4+zoI8CAVTngQ6vHKEEk9J3Pwb1GRdidy3u5Lita02j8l3XicDQjwIEYl
        jSRLV84K4jQI1sm0a5eOZ4rQaKzd3qcFBFguU+qDCPAg/sTzTRcTDJo5uxwzCwiGRFUDCuZ7dJZwSZNLEfzxGMsI8SA6KmnQ3EgY0MidLpCH7tsvEnKe1w3R
        M9Kk0+qdLclYQQjwIFau325aLj4fZ1uuIs/1J7rqgqspY5S8bFNbMOBmAxjaCPEgeabaXkS9y4zw4epu5mjIyx6lL4x/j+2fKcRJrx/mqfoI8CDi3fPiM5/7
        BiuPSC72Nk6lX9Lld1zWBv+LcbX3bObxzQjxrgEBAAAAAfc2/olit0U94KlYshfHooQKMPYkMqeM/1ePh5gdAgISAAAAAEhHMEQCIA8OliC7yhLsXyd9W0vn
        lsCr6FQaOFEU67Ge5mfIToIzAiBDBmcvTGMmcNlXhlPcxEnCkGcggnD+pIi/YHa+heZLdQH9////AnxOCQAAAAAAIyEDKk6TladD2IyOt1/pTwxFrmCCXh7e
        vk7f4dcKBu73lqWsAAAAAAAAAAAiaiDwBNkfBwAICPAgEVoOXyBzMEM/lrsk+MXRAP9RWJzumXfbyWDPBJwq4JIICPAgIpIWJhM1I119vjXYStwSS8kVfsoB
        iITn1Eo0YTMIipoICPAgUJtCVlG1+yhFEuIPh+An85uUGPVu07j99iPthHs9CwAICPEgaStg7XBTPUN5F6ms6x1BtM6l3WIh9EJHw+tTVAMa6vUICPEgZNCC
        Ex0LBlqrdWqqmYDqVxXucdin71IuqPIXU5QZIY4ICPAgpqW641GCK806Rr0oAtYSVwkR7tDP87yqsbRshD2O65YICPEgnEt0pbF2bpS2FOgC0tOCRqaH7RbK
        epIC59PHEP2GI70ICPAgsx0ihrDwS2Uo16MvUh9v18Eann2LXVrv6GZ2swpr5HwICPEg6Yx5aHz1ke4gFga00+D9WRcfW5ST/S1lVM9jSMec4L4ICPAgpeGX
        +oWPPUy7RXKingzYk1WctuoKv3EArqtRFibQt2IICPAgROgp/Lluvd30JO8rKxqJQQdqL5eINaD/XMWj31Nrm8UICPEgqhDbO74H4zlkTPkU34ipQRHMtMqF
        M08VdAi7bDNYt1kICAAFiJYNc9cZAQPavxz/8BDL1gSnWoRFOMzFJ0FbQwy4CPEEWRxcevAIFnOscUC/c7oAg9/jDS75DI4sK2h0dHBzOi8vYm9iLmJ0Yy5j
        YWxlbmRhci5vcGVudGltZXN0YW1wcy5vcmfwEOT/jCVT9+3mUhiw9w4jGPcI8QRZHFx58AjlekpyYB/rkACD3+MNLvkMji4taHR0cHM6Ly9hbGljZS5idGMu
        Y2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn
      `),
      expected: new Set([
        uint8ArrayConcat(
          uint8ArrayFromHex('591c5c79d5103f9ad3914c8b9b8a4261736c05cb0d576f498e5290e3862f8280c9618ea0ffe6d743d8ab7c9a'),
          writeLeaf({ type: 'pending', url: new URL('https://finney.calendar.eternitywall.com') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('267c8a43b9bf4968356f85f313943ef8371d106b4c6f67b2c4a8b05c3a30c940'),
          writeLeaf({ type: 'bitcoin', height: 466906 }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('591c5c7a85830d62b246bdce8c756ac7c76a39e475a1f90b89037eae1f3d51b25824caa91673ac7140bf73ba'),
          writeLeaf({ type: 'pending', url: new URL('https://bob.btc.calendar.opentimestamps.org') }),
        ),
        uint8ArrayConcat(
          uint8ArrayFromHex('591c5c7935c1c5d0980c54010cab2751ac8181b2a1aa51b8a7f956835f9081adb4ac2230e57a4a72601feb90'),
          writeLeaf({ type: 'pending', url: new URL('https://alice.btc.calendar.opentimestamps.org') }),
        ),
      ]),
      name: 'sha1 - a/b',
    },
  ])('$name', ({ input, expected }: { input: Uint8Array; expected: Set<Uint8Array> }): void => {
    const timestamp: Timestamp = read(input);
    expect(
      new Set(
        treeToPaths(timestamp.tree).map(({ operations, leaf }: Path) =>
          uint8ArrayConcat(callOps(operations, timestamp.fileHash.value), writeLeaf(leaf)),
        ),
      ),
    ).toStrictEqual(expected);
  });
});
