# TypeScript OpenTimestamps (`typescript-opentimestamps`)

An OpenTimestamps client written in TypeScript

This project aims to provide a fully-tested, fully typed, OpenTimestamps Client.
It currently supports stamping, upgrading, and verifying timestamps.

## Table of Contents

1. [Background](#background)
2. [Install](#install)
3. [Usage](#usage)
4. [API](#api)
5. [Contributing](#contributing)
6. [License](#license)

## Background

The OpenTimestamps project currently hosts a number of Server, Client, and CLI [implementations](https://opentimestamps.org/#code-repositories).
This is our contribution to that list, adding TypeScript to it.

The project may be used as-is in Typescript directly, or it may be compiled and packaged for usage in the browser or NodeJS modules.

## Install

Installing the library is straightforward:

```sh
npm add @lacrypta/typescript-opentimestamps
```

```sh
yarn add @lacrypta/typescript-opentimestamps
```

```sh
pnpm add @lacrypta/typescript-opentimestamps
```

The only run-time dependency is [`@noble/hashes`](https://github.com/paulmillr/noble-hashes).

## Usage

Once installed the library can be directly imported:

```typescript
import {
  type Timestamp,
  read as read,
  verify as verify,
  //
  verifiers,
} from '@lacrypta/typescript-opentimestamps';

const rawTimestamp: Uint8Array = Uint8Array.from(someTimestampBytes);
const timestamp: Timestamp = read(rawTimestamp);

verify(
  timestamp,
  verifiers,
).then(
  ({ attestations,  errors }: { attestations: Record<number, string[]>; errors: Record<string, Error[]> }): void => {
    Object.entries(attestations).forEach(([time, verifiers]: [string, string[]]): void => {
      console.log(`Verifiers ${verifiers.join(', ')} attest to this timestamp as of ${time}`);
    });
    Object.entries(errors).forEach(([verifier, errorList]: [string, Error[]]): void => {
      console.log(`${verifier} reported the following errors:`);
      errorList.forEach((error: Error): void => {
        console.log(error.message);
      });
    });
  },
);
```

## API

This library exports the following types:

- **`Timestamp`:** a type alias containing version, file hash, and validation tree information.

It exports the following functions:

- **`info`:** obtain a human-readable description of the `Timestamp`'s content.
- **`canShrink`:** determine whether the given `Timestamp` can be shrunk to a single attestation chain.
- **`canUpgrade`:** determine whether the given `Timestamp` ca be upgraded via a Calendar.
- **`canVerify`:** determine whether the given `Timestamp` can be verified in the blockchain(s).
- **`read`:** read a `Uint8Array` and transform it into a `Timestamp` if valid.
- **`shrink`:** eliminate all but the _oldest_ attestation found in the given `Timestamp` for the given chain.
- **`submit`:** submit the given `Timestamp` to a Calendar for eventual inclusion in a blockchain.
- **`upgrade`:** upgrade the given `Timestamp` via a Calendar so as to make it independently verifiable.
- **`is`:** a [TypeScript type predicate](https://www.typescriptlang.org/docs/handbook/2/narrowing.html#using-type-predicates) that simply applies validation to the given `Timestamp`.
- **`validate`:** validate the given parameter and determine whether it is indeed a `Timestamp` object.
- **`verify`:** verify the given `Timestamp` against the blockchain(s).
- **_verifiers_:** a set of predefined lambda functions that will query the blockchain via explorer-provider APIs to check for the presence of a given Merkle root on-chain.
- **`write`:** generate a `Uint8Array` consisting of the standard serialization of the given `Timestamp` value.

More in-depth information and prototypes can be found in the generated documentation.

## Contributing

This project uses [`pnpm`](https://pnpm.io/) (think `npm` but faster), you'll need to [install it](https://pnpm.io/installation) if you haven't already.

You may clone the repository as usual:

```sh
git clone git@github.com:lacrypta/typescript-opentimestamps.git
cd typescript-opentimestamps
```

Now, simply install all dependencies:

```sh
pnpm install
```

We provide several `pnpm` commands for your convenience:

- **`pnpm format`:** will run formatters and linters in all the codebase.
- **`pnpm build`:** will build all targets (TypeScript type declarations included) in the `/dist` directory.
- **`pnpm analyze`:** will analyze previous build.
- **`pnpm doc`:** will generate _internal_ and _external_ documentation in the `/dist` directory.
- **`pnpm clean`:** will remove the `/dist` directory entirely.
- **`pnpm test`:** will run all tests and report coverage on the whole codebase.
- **`pnpm reset`:** will run `pnpm clean`, and remove the `/node_modules` directory and `pnpm-lock.yaml` file, so as to completely reset the installation.

You'll probably want to run the tests first, build the documentation, and take it from there:

```sh
pnpm test
pnpm doc
```

Now navigate to `/dist/docs/api/index.html` (for the end-use documentation) or `/dist/docs/internal/index.html` (for developer documentation) and peruse the generated documentation at your leisure.

Please follow contribution guidelines at [the GitHub repository](https://github.com/lacrypta/typescript-opentimestamps), we encourage PRs!

## License

GNU Affero General Public License v3.0 or later, see [LICENSE.md](./LICENSE.md).
