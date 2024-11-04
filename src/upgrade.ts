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

/**
 * This module exposes the upgrading functions.
 *
 * @packageDocumentation
 * @module
 */

import type { Path, Paths } from './internals';
import type { Leaf, Timestamp, Tree } from './types';

import { callOps, treeToPaths, pathsToTree } from './internals';
import { readTree } from './read';
import { retrieveGetBody, uint8ArrayToHex } from './utils';

/**
 * Query the given calendar {@link !URL} with the given message in order to get an "absolute" version of the pending {@link types!Leaf | assertion}.
 *
 * Calendars are queried by appending `/timestamp/{message}` to their {@link !URL}.
 * The calendar's response is then parsed as a {@link Tree} and returned.
 *
 * @example
 * ```typescript
 * import { infoTree } from './src/info';
 * import { upgradeFromCalendar } from './src/upgrade';
 *
 * console.log(
 *   infoTree(
 *     await upgradeFromCalendar(
 *       new URL('https://alice.btc.calendar.opentimestamps.org'),
 *       Uint8Array.of(
 *         0x57, 0xcf, 0xa5, 0xc4, 0x67, 0x16, 0xdf, 0x9b, 0xd9, 0xe8,
 *         0x35, 0x95, 0xbc, 0xe4, 0x39, 0xc5, 0x81, 0x08, 0xd8, 0xfc,
 *         0xc1, 0x67, 0x8f, 0x30, 0xd4, 0xc6, 0x73, 0x1c, 0x3f, 0x1f,
 *         0xa6, 0xc7, 0x9e, 0xd7, 0x12, 0xc6, 0x6f, 0xb1, 0xac, 0x8d,
 *         0x4e, 0x4e, 0xb0, 0xe7,
 *       ),
 *     ),
 *     undefined,
 *   ),
 * );
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 6563bb432a829ac8d6c54d1a9330d2240664cad8338dd05e63eec12a18a68d50)
 *   // msg = sha256(msg)
 *   // msg = append(msg, ba83ddbe2bd6772b4584b46eaed23606b712dd740a89e99e927571f77f64aa21)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 193c81e70e4472b52811fe7837ce1293b1d3542b244f27f44182af8287fc9f4e)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, c6c57696fcd39b4d992477889d04e6882829f5fe556304a281dce258b78a1f07)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 0100000001b592ca038eaa9c1b698a049b09be8ee8972b5d0eca29c19946027ba9248acb03000000004847304402200f992d5dbec6edb143f76c14e4538e0a50d66bae27c683cf4291e475287ec6af022010bae9443390aadbd2e2b8b9f757beea26d3f5c345f7e6b4d81b3d390edd381801fdffffff022eb142000000000023210338b2490eaa949538423737cd83449835d1061dca88f4ffaca7181bcac67d2095ac0000000000000000226a20)
 *   // msg = append(msg, 678a0600)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 977ac39d89bb8b879d4a2c38fca48a040c82637936707fc452c9db1390b515c8)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, 74268b23e614997d18c7c063d8d82d7e1db57b5fc4346cc47ac2c46d54168d71)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 560c45b854f8507c8bfacf2662fef269c208a7e5df5c3145cbce417ecacc595e)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 0dba8721b9cd4ac7c2fcc7e15ba2cb9f2906bfc577c212747cd352d61b5d7fdb)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 81107a010d527d18baa874bc99c19a3a7a25dfe110a4c8985bf30f6c3e77baed)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, ca3cdcd7093498b3f180b38a9773207e52fca992c2db1d660fdfa1b329500c39)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, ca6c6464dd02ced64c9c82246ccfc626caa78d9e624cc11013e3b4bbc09e9891)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, 1c7ae0feac018fa19bd8459a4ae971b3e6c816a87254317e0a9f0ec9425ba761)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 90263a73e415a975dc07706772dbb6200ef0d0a23006218e65d4a5d811206730)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 79530163b0d912249438628bd791ac9402fa707eb314c6237b0ef90271625c84)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // bitcoinVerify(msg, 428648)
 * ```
 *
 * @param calendarUrl - The calendar {@link !URL} to query.
 * @param msg - The message to query for.
 * @returns The calendar's {@link Tree} response.
 * @throws {@link !Error} If the calendar's response cannot be parsed correctly.
 */
export async function upgradeFromCalendar(calendarUrl: URL, msg: Uint8Array): Promise<Tree> {
  const body: Uint8Array = await retrieveGetBody(
    new URL(`${calendarUrl.toString().replace(/\/$/, '')}/timestamp/${uint8ArrayToHex(msg)}`),
  );
  const [upgradedTree, end]: [Tree, number] = readTree(body, 0);
  if (end !== body.length) {
    throw new Error('Garbage at end of calendar response');
  }
  return upgradedTree;
}

/**
 * Try to upgrade _all_ `pending` {@link Leaf | Leaves} on the given {@link Tree}.
 *
 * This function will iterate all `pending` {@link Leaf | Leaves} and try to query the calendar therein looking for an upgraded {@link Tree}.
 *
 * {@link !Error | Errors} encountered upon submission are not thrown, but rather collected and returned alongside the resulting {@link Tree}.
 *
 * > This function internally calls {@link upgradeFromCalendar}.
 *
 * @example
 * ```typescript
 * import type { Tree } from './src/types';
 *
 * import { infoTree } from './src/info';
 * import { EdgeMap, LeafSet } from './src/internals';
 * import { upgradeTree } from './src/upgrade';
 *
 * const pendingTree: Tree = {
 *   leaves: new LeafSet(),
 *   edges: new EdgeMap().add(
 *     {
 *       type: 'append',
 *       operand: Uint8Array.of(
 *         0xe7, 0x54, 0xbf, 0x93, 0x80, 0x6a, 0x7e, 0xba,
 *         0xa6, 0x80, 0xef, 0x7b, 0xd0, 0x11, 0x4b, 0xf4,
 *       ),
 *     },
 *     {
 *       leaves: new LeafSet(),
 *       edges: new EdgeMap().add(
 *         { type: 'sha256' },
 *         {
 *           leaves: new LeafSet(),
 *           edges: new EdgeMap().add(
 *             {
 *               type: 'append',
 *               operand: Uint8Array.of(
 *                 0xb5, 0x73, 0xe8, 0x85, 0x0c, 0xfd, 0x9e, 0x63,
 *                 0xd1, 0xf0, 0x43, 0xfb, 0xb6, 0xfc, 0x25, 0x0e,
 *               ),
 *             },
 *             {
 *               leaves: new LeafSet(),
 *               edges: new EdgeMap().add(
 *                 { type: 'sha256' },
 *                 {
 *                   leaves: new LeafSet(),
 *                   edges: new EdgeMap().add(
 *                     {
 *                       type: 'prepend',
 *                       operand: Uint8Array.of(0x57, 0xcf, 0xa5, 0xc4),
 *                     },
 *                     {
 *                       leaves: new LeafSet(),
 *                       edges: new EdgeMap().add(
 *                         {
 *                           type: 'append',
 *                           operand: Uint8Array.of(0x6f, 0xb1, 0xac, 0x8d, 0x4e, 0x4e, 0xb0, 0xe7),
 *                         },
 *                         {
 *                           edges: new EdgeMap(),
 *                           leaves: new LeafSet().add({
 *                             type: 'pending',
 *                             url: new URL('https://alice.btc.calendar.opentimestamps.org/'),
 *                           }),
 *                         },
 *                       ),
 *                     },
 *                   ),
 *                 },
 *               ),
 *             },
 *           ),
 *         },
 *       ),
 *     },
 *   ),
 * };
 *
 * const { tree, errors }: { tree: Tree; errors: Error[] } = await upgradeTree(
 *   pendingTree,
 *   Uint8Array.of(0x05, 0xc4, 0xf6, 0x16, 0xa8, 0xe5, 0x31, 0x0d,
 *                 0x19, 0xd9, 0x38, 0xcf, 0xd7, 0x69, 0x86, 0x4d,
 *                 0x7f, 0x4c, 0xcd, 0xc2, 0xca, 0x8b, 0x47, 0x9b,
 *                 0x10, 0xaf, 0x83, 0x56, 0x4b, 0x09, 0x7a, 0xf9,
 *   ),
 * );
 *
 * console.log(infoTree(pendingTree, undefined));
 *   // msg = append(msg, e754bf93806a7ebaa680ef7bd0114bf4)
 *   // msg = sha256(msg)
 *   // msg = append(msg, b573e8850cfd9e63d1f043fbb6fc250e)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 57cfa5c4)
 *   // msg = append(msg, 6fb1ac8d4e4eb0e7)
 *   // pendingVerify(msg, https://alice.btc.calendar.opentimestamps.org/)
 * console.log(infoTree(tree, undefined));
 *   // msg = append(msg, e754bf93806a7ebaa680ef7bd0114bf4)
 *   // msg = sha256(msg)
 *   // msg = append(msg, b573e8850cfd9e63d1f043fbb6fc250e)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 57cfa5c4)
 *   // msg = append(msg, 6fb1ac8d4e4eb0e7)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 6563bb432a829ac8d6c54d1a9330d2240664cad8338dd05e63eec12a18a68d50)
 *   // msg = sha256(msg)
 *   // msg = append(msg, ba83ddbe2bd6772b4584b46eaed23606b712dd740a89e99e927571f77f64aa21)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 193c81e70e4472b52811fe7837ce1293b1d3542b244f27f44182af8287fc9f4e)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, c6c57696fcd39b4d992477889d04e6882829f5fe556304a281dce258b78a1f07)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 0100000001b592ca038eaa9c1b698a049b09be8ee8972b5d0eca29c19946027ba9248acb03000000004847304402200f992d5dbec6edb143f76c14e4538e0a50d66bae27c683cf4291e475287ec6af022010bae9443390aadbd2e2b8b9f757beea26d3f5c345f7e6b4d81b3d390edd381801fdffffff022eb142000000000023210338b2490eaa949538423737cd83449835d1061dca88f4ffaca7181bcac67d2095ac0000000000000000226a20)
 *   // msg = append(msg, 678a0600)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 977ac39d89bb8b879d4a2c38fca48a040c82637936707fc452c9db1390b515c8)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, 74268b23e614997d18c7c063d8d82d7e1db57b5fc4346cc47ac2c46d54168d71)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 560c45b854f8507c8bfacf2662fef269c208a7e5df5c3145cbce417ecacc595e)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 0dba8721b9cd4ac7c2fcc7e15ba2cb9f2906bfc577c212747cd352d61b5d7fdb)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 81107a010d527d18baa874bc99c19a3a7a25dfe110a4c8985bf30f6c3e77baed)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, ca3cdcd7093498b3f180b38a9773207e52fca992c2db1d660fdfa1b329500c39)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, ca6c6464dd02ced64c9c82246ccfc626caa78d9e624cc11013e3b4bbc09e9891)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, 1c7ae0feac018fa19bd8459a4ae971b3e6c816a87254317e0a9f0ec9425ba761)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 90263a73e415a975dc07706772dbb6200ef0d0a23006218e65d4a5d811206730)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 79530163b0d912249438628bd791ac9402fa707eb314c6237b0ef90271625c84)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // bitcoinVerify(msg, 428648)
 * console.log(errors);
 *   // []
 * ```
 *
 * @param tree - The {@link Tree} to upgrade.
 * @param msg - The _initial_ message to use for upgrading.
 * @returns An object, mapping `tree` to the resulting {@link Tree}, and `errors` to a list of {@link !Error | Errors} encountered.
 */
export async function upgradeTree(tree: Tree, msg: Uint8Array): Promise<{ tree: Tree; errors: Error[] }> {
  const { paths, errors }: { paths: Paths; errors: Error[] } = (
    await Promise.all(
      treeToPaths(tree).map(async ({ operations, leaf }: Path): Promise<{ paths: Paths; errors: Error[] }> => {
        if ('pending' !== leaf.type) {
          return { paths: [{ operations, leaf }], errors: [] };
        } else {
          return upgradeFromCalendar(leaf.url, callOps(operations, msg))
            .then((upgradedTree: Tree): { paths: Paths; errors: Error[] } => {
              return {
                paths: treeToPaths(upgradedTree).map(
                  ({ operations: upgradedOperations, leaf: upgradedLeaf }: Path): Path => {
                    return { operations: operations.concat(upgradedOperations), leaf: upgradedLeaf };
                  },
                ),
                errors: [],
              };
            })
            .catch((e: unknown): { paths: Paths; errors: Error[] } => {
              return {
                paths: [{ operations, leaf }],
                errors: [new Error(`Error (${leaf.url.toString()}): ${(e as Error).message}`)],
              };
            });
        }
      }),
    )
  ).reduce(
    (
      prev: { paths: Paths; errors: Error[] },
      current: { paths: Paths; errors: Error[] },
    ): { paths: Paths; errors: Error[] } => {
      return {
        paths: prev.paths.concat(current.paths),
        errors: prev.errors.concat(current.errors),
      };
    },
    { paths: [], errors: [] },
  );
  return { tree: pathsToTree(paths), errors };
}

/**
 * Try to upgrade _all_ `pending` {@link Leaf | Leaves} on the given {@link Timestamp}.
 *
 * This function will try to upgrade all`pending` {@link Leaf | Leaves} on the given {@link Timestamp}, and return the resulting (potentially upgraded) {@link Timestamp}, and any {@link !Error | Errors} encountered.
 *
 * {@link !Error | Errors} encountered upon submission are not thrown, but rather collected and returned alongside the resulting {@link Timestamp}.
 *
 * > This function internally calls {@link upgradeTree}.
 *
 * @example
 * ```typescript
 * import type { Timestamp } from './src/types';
 *
 * import { info } from './src/info';
 * import { EdgeMap, LeafSet } from './src/internals';
 * import { upgrade } from './src/upgrade';
 *
 * const pendingTimestamp: Timestamp = {
 *   version: 1,
 *   fileHash: {
 *     algorithm: 'sha256',
 *     value: Uint8Array.of(0x05, 0xc4, 0xf6, 0x16, 0xa8, 0xe5, 0x31, 0x0d,
 *                          0x19, 0xd9, 0x38, 0xcf, 0xd7, 0x69, 0x86, 0x4d,
 *                          0x7f, 0x4c, 0xcd, 0xc2, 0xca, 0x8b, 0x47, 0x9b,
 *                          0x10, 0xaf, 0x83, 0x56, 0x4b, 0x09, 0x7a, 0xf9,
 *     ),
 *   },
 *   tree: {
 *     leaves: new LeafSet(),
 *     edges: new EdgeMap().add(
 *       {
 *         type: 'append',
 *         operand: Uint8Array.of(
 *           0xe7, 0x54, 0xbf, 0x93, 0x80, 0x6a, 0x7e, 0xba,
 *           0xa6, 0x80, 0xef, 0x7b, 0xd0, 0x11, 0x4b, 0xf4,
 *         ),
 *       },
 *       {
 *         leaves: new LeafSet(),
 *         edges: new EdgeMap().add(
 *           { type: 'sha256' },
 *           {
 *             leaves: new LeafSet(),
 *             edges: new EdgeMap().add(
 *               {
 *                 type: 'append',
 *                 operand: Uint8Array.of(
 *                   0xb5, 0x73, 0xe8, 0x85, 0x0c, 0xfd, 0x9e, 0x63,
 *                   0xd1, 0xf0, 0x43, 0xfb, 0xb6, 0xfc, 0x25, 0x0e,
 *                 ),
 *               },
 *               {
 *                 leaves: new LeafSet(),
 *                 edges: new EdgeMap().add(
 *                   { type: 'sha256' },
 *                   {
 *                     leaves: new LeafSet(),
 *                     edges: new EdgeMap().add(
 *                       {
 *                         type: 'prepend',
 *                         operand: Uint8Array.of(0x57, 0xcf, 0xa5, 0xc4),
 *                       },
 *                       {
 *                         leaves: new LeafSet(),
 *                         edges: new EdgeMap().add(
 *                           {
 *                             type: 'append',
 *                             operand: Uint8Array.of(0x6f, 0xb1, 0xac, 0x8d, 0x4e, 0x4e, 0xb0, 0xe7),
 *                           },
 *                           {
 *                             edges: new EdgeMap(),
 *                             leaves: new LeafSet().add({
 *                               type: 'pending',
 *                               url: new URL('https://alice.btc.calendar.opentimestamps.org/'),
 *                             }),
 *                           },
 *                         ),
 *                       },
 *                     ),
 *                   },
 *                 ),
 *               },
 *             ),
 *           },
 *         ),
 *       },
 *     ),
 *   },
 * };
 *
 * const { timestamp, errors }: { timestamp: Timestamp; errors: Error[] } = await upgrade(pendingTimestamp);
 *
 * console.log(info(pendingTimestamp));
 *   // msg = sha256(FILE)
 *   // msg = append(msg, e754bf93806a7ebaa680ef7bd0114bf4)
 *   // msg = sha256(msg)
 *   // msg = append(msg, b573e8850cfd9e63d1f043fbb6fc250e)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 57cfa5c4)
 *   // msg = append(msg, 6fb1ac8d4e4eb0e7)
 *   // pendingVerify(msg, https://alice.btc.calendar.opentimestamps.org/)
 * console.log(info(timestamp));
 *   // msg = sha256(FILE)
 *   // msg = append(msg, e754bf93806a7ebaa680ef7bd0114bf4)
 *   // msg = sha256(msg)
 *   // msg = append(msg, b573e8850cfd9e63d1f043fbb6fc250e)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 57cfa5c4)
 *   // msg = append(msg, 6fb1ac8d4e4eb0e7)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 6563bb432a829ac8d6c54d1a9330d2240664cad8338dd05e63eec12a18a68d50)
 *   // msg = sha256(msg)
 *   // msg = append(msg, ba83ddbe2bd6772b4584b46eaed23606b712dd740a89e99e927571f77f64aa21)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 193c81e70e4472b52811fe7837ce1293b1d3542b244f27f44182af8287fc9f4e)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, c6c57696fcd39b4d992477889d04e6882829f5fe556304a281dce258b78a1f07)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 0100000001b592ca038eaa9c1b698a049b09be8ee8972b5d0eca29c19946027ba9248acb03000000004847304402200f992d5dbec6edb143f76c14e4538e0a50d66bae27c683cf4291e475287ec6af022010bae9443390aadbd2e2b8b9f757beea26d3f5c345f7e6b4d81b3d390edd381801fdffffff022eb142000000000023210338b2490eaa949538423737cd83449835d1061dca88f4ffaca7181bcac67d2095ac0000000000000000226a20)
 *   // msg = append(msg, 678a0600)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 977ac39d89bb8b879d4a2c38fca48a040c82637936707fc452c9db1390b515c8)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, 74268b23e614997d18c7c063d8d82d7e1db57b5fc4346cc47ac2c46d54168d71)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 560c45b854f8507c8bfacf2662fef269c208a7e5df5c3145cbce417ecacc595e)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 0dba8721b9cd4ac7c2fcc7e15ba2cb9f2906bfc577c212747cd352d61b5d7fdb)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 81107a010d527d18baa874bc99c19a3a7a25dfe110a4c8985bf30f6c3e77baed)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, ca3cdcd7093498b3f180b38a9773207e52fca992c2db1d660fdfa1b329500c39)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, ca6c6464dd02ced64c9c82246ccfc626caa78d9e624cc11013e3b4bbc09e9891)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = append(msg, 1c7ae0feac018fa19bd8459a4ae971b3e6c816a87254317e0a9f0ec9425ba761)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 90263a73e415a975dc07706772dbb6200ef0d0a23006218e65d4a5d811206730)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // msg = prepend(msg, 79530163b0d912249438628bd791ac9402fa707eb314c6237b0ef90271625c84)
 *   // msg = sha256(msg)
 *   // msg = sha256(msg)
 *   // bitcoinVerify(msg, 428648)
 * console.log(errors);
 *   // []
 * ```
 *
 * @param timestamp - The {@link Timestamp} to upgrade.
 * @returns An object, mapping `timestamp` to the resulting {@link Timestamp}, and `errors` to a list of {@link !Error | Errors} encountered.
 */
export async function upgrade(timestamp: Timestamp): Promise<{ timestamp: Timestamp; errors: Error[] }> {
  const { tree, errors }: { tree: Tree; errors: Error[] } = await upgradeTree(timestamp.tree, timestamp.fileHash.value);
  return {
    timestamp: {
      version: timestamp.version,
      fileHash: timestamp.fileHash,
      tree,
    },
    errors,
  };
}
