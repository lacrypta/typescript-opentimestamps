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
import { normalize as _normalize } from './internals';
import { canShrink as _canShrink, canUpgrade as _canUpgrade, canVerify as _canVerify } from './predicates';
import { read as _read } from './read';
import { shrink as _shrink } from './shrink';
import { submit as _submit } from './submit';
import { upgrade as _upgrade } from './upgrade';
import { is as _is, assert as _assert, validate as _validate } from './validation';
import { write as _write } from './write';

import { verify as _verify } from './verify';
import { default as verifiers } from './verifiers';

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
