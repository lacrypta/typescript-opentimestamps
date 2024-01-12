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

export function uint8ArrayToHex(data: Uint8Array): string {
  return data.reduce((result: string, value: number) => result + value.toString(16).padStart(2, '0'), '').toLowerCase();
}

export function uint8ArrayFromHex(hex: string): Uint8Array {
  if (hex.length % 2) {
    throw new Error('Hex value should be of even length');
  }
  return Uint8Array.from(
    (hex.match(/../g) ?? []).map((pair: string) => {
      if (!pair.match(/^[0-9a-f]{2}$/i)) {
        throw new Error('Malformed hex string');
      }
      return Number.parseInt(pair, 16);
    }),
  );
}

export function uint8ArrayEquals(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((element: number, index: number) => element === right[index]);
}

export function uint8ArrayCompare(left: Uint8Array, right: Uint8Array): number {
  for (let i: number = 0; i < left.length && i < right.length; i++) {
    if (left[i]! != right[i]!) {
      return left[i]! - right[i]!;
    }
  }
  return left.length - right.length;
}

// ref: https://stackoverflow.com/a/49129872
export function uint8ArrayConcat(arrays: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(
    arrays
      .map((item: Uint8Array): number => item.length)
      .reduce((prev: number, curr: number): number => prev + curr, 0),
  );
  let offset = 0;
  arrays.forEach((item: Uint8Array): void => {
    result.set(item, offset);
    offset += item.length;
  });
  return result;
}

export class MergeSet<V> {
  private mapping: Record<number | string | symbol, V> = {};

  constructor(
    private readonly toKey: (key: V) => number | string | symbol,
    private readonly combine: (left: V, right: V) => V,
  ) {}

  protected doAdd(key: number | string | symbol, value: V): this {
    this.mapping[key] = key in this.mapping ? this.combine(this.mapping[key]!, value) : value;
    return this;
  }

  public size(): number {
    return this.values().length;
  }

  public values(): V[] {
    return Object.values(this.mapping);
  }

  public remove(value: V): this {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.mapping[this.toKey(value)];
    return this;
  }

  public add(value: V): this {
    return this.doAdd(this.toKey(value), value);
  }

  public incorporate(other: typeof this): this {
    Object.entries(other.mapping).forEach(([key, value]: [number | string | symbol, V]) => this.doAdd(key, value));
    return this;
  }

  public clone(): MergeSet<V> {
    return new MergeSet<V>(this.toKey, this.combine).incorporate(this);
  }
}

export class MergeMap<K, V> {
  private keySet: Set<K> = new Set<K>();
  private mapping: Record<number | string | symbol, V> = {};

  constructor(
    private readonly toKey: (key: K) => number | string | symbol,
    private readonly combine: (left: V, right: V) => V,
  ) {}

  protected doAdd(key: K, value: V): this {
    this.keySet.add(key);
    const sKey: number | string | symbol = this.toKey(key);
    this.mapping[sKey] = sKey in this.mapping ? this.combine(this.mapping[sKey]!, value) : value;
    return this;
  }

  public size(): number {
    return this.keySet.size;
  }

  public keys(): K[] {
    return Array.from(this.keySet);
  }

  public values(): V[] {
    return Object.values(this.mapping);
  }

  public entries(): [K, V][] {
    return this.keys().map((key: K) => [key, this.mapping[this.toKey(key)]!]);
  }

  public remove(value: K): this {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.mapping[this.toKey(value)];
    this.keySet.delete(value);
    return this;
  }

  public add(key: K, value: V): this {
    return this.doAdd(key, value);
  }

  public incorporate(other: typeof this): this {
    other.entries().map(([key, value]: [K, V]) => this.doAdd(key, value));
    return this;
  }

  public clone(): MergeMap<K, V> {
    return new MergeMap<K, V>(this.toKey, this.combine).incorporate(this);
  }
}

export async function safeFetchBody(input: URL, init?: RequestInit): Promise<Uint8Array | Error> {
  try {
    const response: Response = await fetch(input, {
      headers: {
        Accept: 'application/vnd.opentimestamps.v1',
        'User-Agent': 'typescript-opentimestamps',
      },
      ...init,
    });
    if (!response.ok || null === response.body) {
      return new Error('Error retrieving response body');
    }
    // ref: https://stackoverflow.com/a/72718732
    return new Uint8Array(await new Response(response.body).arrayBuffer());
  } catch (e: unknown) {
    if (e instanceof Error) {
      return e;
    } else {
      return new Error('Unknown fetch() error');
    }
  }
}

export async function retrieveGetBody(url: URL): Promise<Uint8Array | Error> {
  return await safeFetchBody(url, { method: 'GET' });
}

export async function retrievePostBody(url: URL, body: Uint8Array): Promise<Uint8Array | Error> {
  return await safeFetchBody(url, { method: 'POST', body });
}
