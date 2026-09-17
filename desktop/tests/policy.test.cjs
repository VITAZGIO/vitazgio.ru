const { test } = require('node:test');
const assert = require('node:assert/strict');
const { siteURL, newer, releaseAsset, REPO } = require('../policy.cjs');
test('native bridge accepts only the exact site over HTTPS', () => {
  assert.equal(siteURL('https://vitazgio.ru/cabinet'), true);
  for (const value of ['http://vitazgio.ru', 'https://evil.vitazgio.ru', 'https://vitazgio.ru.evil.test',
    'https://vitazgio.ru@evil.test', 'https://user@vitazgio.ru', 'javascript:alert(1)', 'file:///tmp/x']) assert.equal(siteURL(value), false);
});
test('numeric versions and Windows-only stable releases with integrity digest', () => {
  assert.equal(newer('0.10.0','0.9.9'), true);
  assert.equal(newer('1.0.0','1.0.0'), false);
  assert.equal(newer('1.0.0-beta','0.9.9'), false);
  const release = version => ({ tag_name:'windows-v' + version, assets:[{
    name:`vitazgio-windows-${version}-x64.exe`, size:100,
    browser_download_url:`https://github.com/${REPO}/releases/download/windows-v${version}/vitazgio-windows-${version}-x64.exe`,
    digest:'sha256:' + 'a'.repeat(64),
  }] });
  assert.equal(releaseAsset([release('0.9.0'), { tag_name:'android-v999' }, release('0.10.0')]).version, '0.10.0');
  assert.equal(releaseAsset([{ ...release('9.0.0'), prerelease:true }]), null);
  const invalid = release('1.0.0'); invalid.assets[0].browser_download_url = 'https://evil.test/app.exe';
  assert.equal(releaseAsset([invalid]), null);
  const noHash = release('1.0.0'); delete noHash.assets[0].digest;
  assert.equal(releaseAsset([noHash]), null);
});
