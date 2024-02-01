#!/usr/bin/env node

import { readFileSync } from 'fs';

import { analyzeMetafile } from 'esbuild';

const metafile = JSON.parse(readFileSync('./dist/meta.json'));

console.log(await analyzeMetafile(metafile, { verbose: true }));
