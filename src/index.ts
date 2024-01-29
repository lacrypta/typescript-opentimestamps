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

import type { Timestamp, FileHash, Tree, Leaf, Op, Verifier } from './types';

import { Merge, MergeSet, MergeMap } from './utils';

import { infoTimestamp } from './info';
import { normalizeTimestamp } from './internals';
import { canShrinkTimestamp, canUpgradeTimestamp, canVerifyTimestamp } from './predicates';
import { readTimestamp } from './read';
import { shrinkTimestamp } from './shrink';
import { submitTimestamp } from './submit';
import { upgradeTimestamp } from './upgrade';
import { isTimestamp, assertTimestamp, validateTimestamp } from './validation';
import { writeTimestamp } from './write';

import { verifyTimestamp } from './verify';
import { default as verifiers } from './verifiers';

// ----------------------------------------------------------------------------------------------------------------------------------------
// -- API ---------------------------------------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------------------------------------------

export type { Timestamp };
export type { FileHash };
export type { Tree };
export type { Leaf };
export type { Op };
export type { Verifier };

export type { Merge };

export { MergeSet };
export { MergeMap };

export const info = infoTimestamp;
export const normalize = normalizeTimestamp;
export const canShrink = canShrinkTimestamp;
export const canUpgrade = canUpgradeTimestamp;
export const canVerify = canVerifyTimestamp;
export const read = readTimestamp;
export const shrink = shrinkTimestamp;
export const submit = submitTimestamp;
export const upgrade = upgradeTimestamp;
export const is = isTimestamp;
export const assert = assertTimestamp;
export const validate = validateTimestamp;
export const write = writeTimestamp;
export const verify = verifyTimestamp;

export { verifiers };
