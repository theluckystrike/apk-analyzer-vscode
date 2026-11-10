'use strict';
// npm test: runs every test/*.test.js with the Node test runner.
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '..', 'test');
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.test.js')).map((f) => path.join(dir, f));
const env = { ...process.env, ZOVO_SPONSORS_MODULE: path.join(__dirname, '..', 'src', 'license', 'sponsors.js') };
const r = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit', env });
process.exit(r.status === null ? 1 : r.status);
