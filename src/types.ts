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

import { MergeMap, MergeSet, uint8ArrayFromHex } from './utils';

export type Leaf =
  | { type: 'bitcoin'; height: number }
  | { type: 'litecoin'; height: number }
  | { type: 'ethereum'; height: number }
  | { type: 'pending'; url: URL }
  | { type: 'unknown'; header: Uint8Array; payload: Uint8Array };

export type Op =
  | { type: 'sha1' }
  | { type: 'ripemd160' }
  | { type: 'sha256' }
  | { type: 'keccak256' }
  | { type: 'reverse' }
  | { type: 'hexlify' }
  | { type: 'append'; operand: Uint8Array }
  | { type: 'prepend'; operand: Uint8Array };

export type Ops = Op[];

export type Path = { operations: Ops; leaf: Leaf };
export type Paths = Path[];

export type Tree = {
  leaves: MergeSet<Leaf>;
  edges: MergeMap<Op, Tree>;
};

export type Edge = [Op, Tree];

export type FileHash =
  | { algorithm: 'sha1'; value: Uint8Array }
  | { algorithm: 'ripemd160'; value: Uint8Array }
  | { algorithm: 'sha256'; value: Uint8Array }
  | { algorithm: 'keccak256'; value: Uint8Array };

export type Timestamp = {
  version: number;
  fileHash: FileHash;
  tree: Tree;
};

export enum Tag {
  attestation = 0x00,
  sha1 = 0x02,
  ripemd160 = 0x03,
  sha256 = 0x08,
  keccak256 = 0x67,
  append = 0xf0,
  prepend = 0xf1,
  reverse = 0xf2,
  hexlify = 0xf3,
}

export enum LeafHeader {
  bitcoin = '0588960d73d71901',
  litecoin = '06869a0d73d71b45',
  ethereum = '30fe8087b5c7ead7',
  pending = '83dfe30d2ef90c8e',

}

export const magicHeader: Uint8Array = uint8ArrayFromHex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294',
);

export const nonFinal: number = 0xff;

export type Verifier = (msg: Uint8Array, leaf: Leaf) => Promise<number | undefined>;
