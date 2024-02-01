#!/usr/bin/env node

import { writeFileSync } from 'fs';

import { build } from 'esbuild';
import { umdWrapper } from 'esbuild-plugin-umd-wrapper';

const umdWrapperOptions = {
  libraryName: 'opentimestamps',
};

const buildOptions = {
  bundle: true,
  entryPoints: ['./src/index.ts'],
  globalName: 'opentimestamps',
  logLevel: 'debug',
  metafile: true,
  platform: 'neutral',
  sourcemap: 'linked',
  sourcesContent: false,
};

const results = await Promise.all([
  build({
    ...buildOptions,
    format: 'esm',
    outfile: './dist/index.js',
    packages: 'external',
  }),
  build({
    ...buildOptions,
    format: 'umd',
    minify: true,
    outfile: './dist/index.min.js',
    plugins: [umdWrapper(umdWrapperOptions)],
  }),
]);

writeFileSync('./dist/meta.json', JSON.stringify(results[0].metafile));
