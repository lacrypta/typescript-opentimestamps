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
 * This module gathers {@link types!Verifier | Verifiers} under a single entry point, and provides a default export ready for usage with {@link verify!verify | verify}.
 *
 * @packageDocumentation
 * @module
 */

import type { Verifier } from '../types';

import { default as verifyViaBlockchainInfo } from './blockchain.info';
import { default as verifyViaBlockstream } from './blockstream';

/**
 * A `default` export that simply re-exports all defined {@link Verifier | Verifiers} in the module in a manner suitable for usage with {@link verify!verify | verify}.
 *
 */
export default { verifyViaBlockchainInfo, verifyViaBlockstream } satisfies Record<string, Verifier>;
