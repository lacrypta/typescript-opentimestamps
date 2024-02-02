import { readFileSync } from 'fs';

import { analyzeMetafile } from 'esbuild';

console.log(await analyzeMetafile(JSON.parse(readFileSync('./dist/meta.json')), { verbose: true }));
