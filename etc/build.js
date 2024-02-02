import { writeFileSync } from 'fs';

import { build } from 'esbuild';
import { umdWrapper } from 'esbuild-plugin-umd-wrapper';

const name = 'opentimestamps';

const umdWrapperOptions = {
  libraryName: name,
};

const buildOptions = {
  bundle: true,
  entryPoints: ['./src/index.ts'],
  globalName: name,
  logLevel: 'debug',
  metafile: true,
  platform: 'neutral',
  sourcemap: 'linked',
  sourcesContent: false,
  tsconfig: './etc/tsconfig.build.json',
};

const results = await Promise.all([
  build({
    ...buildOptions,
    format: 'esm',
    outfile: './dist/esm/index.js',
    packages: 'external',
  }),
  //
  build({
    ...buildOptions,
    format: 'esm',
    outfile: './dist/esm/index.min.js',
    minify: true,
  }),
  build({
    ...buildOptions,
    format: 'umd',
    outfile: './dist/umd/index.js',
    plugins: [umdWrapper(umdWrapperOptions)],
  }),
  build({
    ...buildOptions,
    format: 'umd',
    minify: true,
    outfile: './dist/umd/index.min.js',
    plugins: [umdWrapper(umdWrapperOptions)],
  }),
]);

writeFileSync('./dist/meta.json', JSON.stringify(results[0].metafile, null, 2));
