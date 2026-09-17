'use strict';
const ORIGIN = 'https://vitazgio.ru';
const REPO = 'VITAZGIO/vitazgio.ru';
function siteURL(raw) {
  try { const u = new URL(raw); return u.origin === ORIGIN && !u.username && !u.password; }
  catch { return false; }
}
function newer(a, b) {
  const parse = v => /^\d+\.\d+\.\d+$/.test(v) ? v.split('.').map(Number) : null;
  const x = parse(a), y = parse(b);
  if (!x || !y) return false;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i];
  return false;
}
function releaseAsset(releases) {
  const rows = [];
  for (const release of releases) {
    if (release.draft || release.prerelease || !/^windows-v\d+\.\d+\.\d+$/.test(release.tag_name || '')) continue;
    const version = release.tag_name.slice(9);
    const name = `vitazgio-windows-${version}-x64.exe`;
    const asset = (release.assets || []).find(a => a.name === name);
    const url = `https://github.com/${REPO}/releases/download/${release.tag_name}/${name}`;
    if (!asset || asset.browser_download_url !== url || !/^sha256:[a-f0-9]{64}$/.test(asset.digest || '')) continue;
    rows.push({ version, name, url, size: asset.size, sha256: asset.digest.slice(7) });
  }
  return rows.sort((a, b) => newer(a.version, b.version) ? -1 : newer(b.version, a.version) ? 1 : 0)[0] || null;
}
module.exports = { ORIGIN, REPO, siteURL, newer, releaseAsset };
