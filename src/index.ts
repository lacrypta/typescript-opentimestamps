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

export type { Timestamp } from './types';

export { readTimestamp as read } from './read';
export { writeTimestamp as write } from './write';
export { infoTimestamp as info } from './info';
export { submitTimestamp as submit } from './submit';
export { upgradeTimestamp as upgrade } from './upgrade';
export { normalizeTimestamp as normalize } from './internals';
export { isTimestamp, validateTimestamp as validate } from './validation';
export { verifyTimestamp as verify } from './verify';
export { shrinkTimestamp as shrink } from './shrink';
export * from './verifiers';
