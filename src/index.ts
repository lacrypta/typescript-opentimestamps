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

// ----------------------------------------------------------------------------------------------------------------------------------------
// -- API (type-likes) --------------------------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------------------------------------------

export type { Timestamp, FileHash, Tree, Leaf, Op, Verifier } from './types';
export type { Combine, ToKey } from './utils';

export { MergeMap, MergeSet } from './utils';

// ----------------------------------------------------------------------------------------------------------------------------------------
// -- API (function-likes) ----------------------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------------------------------------------

import { info as _info } from './info';
import {
  normalize as _normalize,
  newEdges as _newEdges,
  newLeaves as _newLeaves,
  newTree as _newTree,
} from './internals';
import { canShrink as _canShrink, canUpgrade as _canUpgrade, canVerify as _canVerify } from './predicates';
import { read as _read } from './read';
import { shrink as _shrink } from './shrink';
import { submit as _submit } from './submit';
import { upgrade as _upgrade } from './upgrade';
import { is as _is, assert as _assert, validate as _validate } from './validation';
import { write as _write } from './write';

import { verify as _verify } from './verify';
import { default as verifiers } from './verifiers';

/**
 * Construct an empty {@link MergeMap} suitable for usage to hold `<{@link Op}, {@link Tree}>` maps in a {@link Tree}.
 *
 * A {@link MergeMap} suitable for {@link Tree} usage requires two parameters: the `toKey` and `combine` functions.
 * In the case of `<{@link Op}, {@link Tree}>` mappings these are:
 *
 * - **`toKey`:** use the {@link Op}'s `type`; if this happens to be `append` or `prepend`, append a `:` followed by their `operand` to the constructed key.
 * - **`combine`:** simply merge the two {@link Tree}s.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { newEdges } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(newEdges());  // MergeMap { ... }
 * ```
 *
 * @returns The empty `<{@link Op}, {@link Tree}>` mapping.
 */
export const newEdges = _newEdges;

/**
 * Construct an empty {@link MergeSet} suitable for usage to hold {@link Leaf} sets in a {@link Tree}.
 *
 * A {@link MergeSet} suitable for {@link Tree} usage requires two parameters: the `toKey` and `combine` functions.
 * In the case of {@link Leaf} mappings these are:
 *
 * - **`toKey`:** return the {@link Leaf}'s `type` with a `:` at the, and, depending on the `type` itself, concatenate this with:
 *     - **`pending`:** the {@link Leaf}'s `url`;
 *     - **`unknown`:** the {@link Leaf}'s `header` as a hex string, a `:`, and its payload as a hex string;
 *     - **`bitcoin`, `litecoin`, or `ethereum`:** the {@link Leaf}'s height as a decimal string.
 * - **`combine`:** simply return the first of the two {@link Leaf | Leaves} (there's no point in holding more than one of each {@link Leaf} type).
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { newLeaves } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(newLeaves());  // MergeSet { ... }
 * ```
 *
 * @returns The empty {@link Leaf | Leaves} set.
 */
export const newLeaves = _newLeaves;

/**
 * Construct an empty {@link Tree}.
 *
 * This function merely calls {@link newLeaves} and {@link newEdges} to construct an empty {@link Tree}.
 *
 * @example
 * ```typescript
 * 'use strict';
 *
 * import { newTree } from '@lacrypta/typescript-opentimestamps';
 *
 * console.log(newTree());  // { edges: MergeMap { ... }, leaves: MergeSet { ... } }
 * ```
 *
 * @returns The empty tree constructed.
 */
export const newTree = _newTree;

/**
 * Generate a human-readable string form the given {@link Timestamp}.
 *
 * Human-readable strings are generated as a concatenation of:
 *
 * - The {@link Timestamp}'s `version` (as a _"faux comment"_, and only if the `verbose` parameter is true).
 * - The {@link Timestamp}'s `fileHash` as a simple function call.
 * - Function call trees for the main {@link Timestamp} `tree`.
 *
 * @example
 * ```typescript
 * import type { Timestamp } from '@lacrypta/typescript-opentimestamps';
 *
 * import { info, newEdges, newLeaves } from '@lacrypta/typescript-opentimestamps';
 *
 * const timestamp: Timestamp = {
 *   version: 1,
 *   fileHash: {
 *     algorithm: 'sha1',
 *     value: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
 *   },
 *   tree: {
 *     leaves: newLeaves(),
 *     edges: newEdges().add(
 *       { type: 'prepend', operand: Uint8Array.of(1, 2, 3) },
 *       { leaves: newLeaves(),
 *         edges: newEdges()
 *           .add(
 *             { type: 'reverse' },
 *             { leaves: newLeaves(),
 *               edges: newEdges().add(
 *                 { type: 'append', operand: Uint8Array.of(7, 8, 9) },
 *                 { edges: newEdges(),
 *                   leaves: newLeaves().add({ type: 'bitcoin', height: 123 }),
 *                 },
 *               ),
 *             },
 *           )
 *           .add(
 *             { type: 'prepend', operand: Uint8Array.of(4, 5, 6) },
 *             { edges: newEdges(),
 *               leaves: newLeaves().add({ type: 'bitcoin', height: 456 }),
 *             },
 *           ),
 *       },
 *     ),
 *   },
 * };
 *
 * console.log(info(timestamp));
 *   // msg = sha1(FILE)
 *   // msg = prepend(msg, 010203)
 *   //  -> msg = reverse(msg)
 *   //     msg = append(msg, 070809)
 *   //     bitcoinVerify(msg, 123)
 *   //  -> msg = prepend(msg, 040506)
 *   //     bitcoinVerify(msg, 456)
 * console.log(info(timestamp, true));
 *   // # version: 1
 *   // msg = sha1(FILE)
 *   //     = 0102030405060708090a0b0c0d0e0f1011121314
 *   // msg = prepend(msg, 010203)
 *   //     = 0102030102030405060708090a0b0c0d0e0f1011121314
 *   //  -> msg = reverse(msg)
 *   //         = 14131211100f0e0d0c0b0a090807060504030201030201
 *   //     msg = append(msg, 070809)
 *   //         = 14131211100f0e0d0c0b0a090807060504030201030201070809
 *   //     bitcoinVerify(msg, 123)
 *   //  -> msg = prepend(msg, 040506)
 *   //         = 0405060102030102030405060708090a0b0c0d0e0f1011121314
 *   //     bitcoinVerify(msg, 456)
 * ```
 *
 * @param timestamp - File hash to generate human-readable string for.
 * @param verbose - Whether to include the `value` field in the output or not.
 * @returns Human-readable string generated.
 */
export const info = _info;

export const normalize = _normalize;
export const canShrink = _canShrink;
export const canUpgrade = _canUpgrade;
export const canVerify = _canVerify;
export const read = _read;
export const shrink = _shrink;
export const submit = _submit;
export const upgrade = _upgrade;
export const is = _is;
export const assert = _assert;
export const validate = _validate;
export const write = _write;
export const verify = _verify;

export { verifiers };
