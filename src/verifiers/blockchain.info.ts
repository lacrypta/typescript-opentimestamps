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

import type { LeafVerifier } from '../types';

import { uint8ArrayEquals, uint8ArrayFromHex } from '../utils';

export const verify: LeafVerifier = async (msg: Uint8Array, height: number): Promise<boolean> => {
  try {
    const value: unknown = await (await fetch(new URL(`https://blockchain.info/rawblock/${height}`))).json();
    return uint8ArrayEquals(msg, uint8ArrayFromHex((value as { mrkl_root: string }).mrkl_root));
  } catch {
    return false;
  }
};
