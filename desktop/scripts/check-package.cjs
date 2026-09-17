'use strict';
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const base = path.resolve(__dirname, '..');
const code = `
  const fs = require('node:fs'), assert = require('node:assert/strict');
  const root = ${JSON.stringify(base)};
  const archive = root + '/dist/win-unpacked/resources/app.asar';
  assert.equal(require(archive + '/package.json').version, require(root + '/package.json').version);
  for (const name of ['main.cjs','preload.cjs','input.cjs','agent.html','settings.html']) {
    assert.deepEqual(fs.readFileSync(archive + '/' + name), fs.readFileSync(root + '/' + name));
  }
  assert.ok(fs.existsSync(archive + '/assets/icon.ico'));
  require(archive + '/input.cjs')();
  console.log('PACKAGE PASS: current sources, version, icon and native Windows bindings are bundled.');
`;
const result = spawnSync(path.join(base, 'dist/win-unpacked/Vitaz Gio.exe'), ['-e', code], {
  env:{ ...process.env, ELECTRON_RUN_AS_NODE:'1' }, windowsHide:true, encoding:'utf8', timeout:15000,
});
process.stdout.write(result.stdout || ''); process.stderr.write(result.stderr || '');
if (result.error) console.error(result.error);
process.exit(result.status ?? 1);
