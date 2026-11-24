// The host must verify this entire GitHub release attachment before execution.
import {execFileSync} from 'node:child_process';
import {createHash, createPublicKey, verify} from 'node:crypto';
import {constants} from 'node:fs';
import {lstat, mkdir, mkdtemp, open, readFile, realpath, rm, writeFile} from 'node:fs/promises';
import {basename, dirname, isAbsolute, join, resolve} from 'node:path';

// Bind the independently approved archive SHA-256, Ed25519 public key and exact
// component versions here before reviewing and publishing an immutable asset.
const approvedRelease = {
  "sha256": "7fc4f39d8325877913df271e05f7e952d2dec5fa947cb6a2e441fa28a5d89998",
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAXUmJA3NCVoUzZx0JK9FIQK/09FoLImn9g75j+n9Z3uc=\n-----END PUBLIC KEY-----\n",
  "versions": {
    "cli": "0.17.0",
    "mcp": "0.16.0",
    "skill": "0.7.0"
  }
};

const fileNames = [
  'my-agent.mjs', 'my-agent-client.mjs', 'my-agent-mcp.mjs', 'club-launcher.mjs',
  'club-release.mjs', 'club-release-public.pem', 'club-component-versions.json', 'package.json',
  'package-lock.json', 'README.md', 'THIRD-PARTY-NOTICES.txt', 'SKILL.md', 'references/member-guide.md',
];
const manifestName = 'release-manifest.json';
const signatureName = 'release-signature.txt';
const maxArchive = 3_000_000;
const maxFile = 400_000;
const maxContents = 2_000_000;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const components = ['cli', 'mcp', 'skill'];
const systemTmp = process.platform === 'darwin' ? '/private/tmp' : '/tmp';

function requireValue(condition, message) {
  if (!condition) throw Error(message);
}

function sameKeys(record, keys) {
  return record && typeof record === 'object' && !Array.isArray(record) &&
    Object.keys(record).length === keys.length && keys.every(key => Object.hasOwn(record, key));
}

function sameVersions(actual, expected) {
  return sameKeys(actual, components) && components.every(part => actual[part] === expected[part]);
}

async function readArchive(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    requireValue(stat.isFile() && stat.size > 0 && stat.size <= maxArchive, 'Invalid member ZIP size or type');
    const chunks = [];
    let length = 0;
    for await (const chunk of file.createReadStream({autoClose: false})) {
      length += chunk.length;
      requireValue(length <= maxArchive, 'Invalid member ZIP size');
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  } finally {
    await file.close();
  }
}

function verifiedFiles(path, release) {
  // Read bytes into buffers. Do not let the ZIP reader create filesystem entries.
  const read = (...args) => execFileSync('/usr/bin/unzip', args, {
    maxBuffer: maxFile + 1, timeout: 10_000, env: {LC_ALL: 'C'}, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const names = [...fileNames, manifestName, signatureName].sort();
  const listing = read('-Z', '-1', path).toString('latin1').split('\n');
  requireValue(listing.pop() === '' && listing.length === names.length &&
    listing.sort().every((name, index) => name === names[index]), 'Unexpected member ZIP inventory');
  let size = 0;
  const member = name => {
    const bytes = read('-p', path, name);
    size += bytes.length;
    requireValue(bytes.length > 0 && bytes.length <= maxFile && size <= maxContents, 'Invalid member file size');
    return bytes;
  };

  const raw = member(manifestName);
  const signature = member(signatureName).toString('latin1');
  const key = createPublicKey(release.publicKey);
  const decoded = Buffer.from(signature, 'base64');
  requireValue(key.asymmetricKeyType === 'ed25519' && decoded.length === 64 &&
    decoded.toString('base64') === signature && verify(null, raw, key, decoded), 'Member release signature mismatch');
  const manifest = JSON.parse(raw.toString('utf8'));
  requireValue(Buffer.from(JSON.stringify(manifest)).equals(raw) &&
    sameKeys(manifest, ['product', 'channel', 'contract', 'expires', 'versions', 'files']) &&
    manifest.product === 'club-agent' && manifest.channel === 'stable' && manifest.contract === 2 &&
    Number.isSafeInteger(manifest.expires) && manifest.expires > Date.now() &&
    sameKeys(manifest.files, fileNames), 'Initial release not approved');
  // The exact approval also sets the minimum allowed versions.
  requireValue(sameVersions(manifest.versions, release.versions), 'Unsupported initial component versions');

  const files = new Map();
  for (const name of fileNames) {
    const bytes = member(name);
    requireValue(sha256(bytes) === manifest.files[name], 'Member file hash mismatch');
    files.set(name, bytes);
  }
  requireValue(files.get('club-release-public.pem').equals(Buffer.from(key.export({type: 'spki', format: 'pem'}))) &&
    sameVersions(JSON.parse(files.get('club-component-versions.json')), release.versions), 'Invalid installed release identity');
  const pkg = JSON.parse(files.get('package.json'));
  const lock = JSON.parse(files.get('package-lock.json'));
  requireValue(pkg?.name === 'asc-member-connector' && pkg.version === release.versions.cli &&
    lock?.name === pkg.name && lock.version === pkg.version && lock.lockfileVersion === 3 &&
    lock.packages?.['']?.name === pkg.name && lock.packages[''].version === pkg.version,
    'Invalid installed package or dependency lock identity');
  return {files, expires: manifest.expires};
}

function requireCurrent(expires) {
  requireValue(expires > Date.now(), 'Initial release expired');
}

async function trustedDirectory(path, message) {
  let directory = '/';
  for (const part of path.split('/').filter(Boolean)) {
    directory = join(directory, part);
    const info = await lstat(directory);
    const stickySystemTmp = directory === systemTmp && info.uid === 0 && (info.mode & 0o1000) !== 0;
    requireValue(info.isDirectory() && (info.uid === 0 || info.uid === process.getuid()) &&
      ((info.mode & 0o022) === 0 || stickySystemTmp), message);
    // macOS ACL grants can permit writes even when the Unix mode forbids them.
    if (process.platform === 'darwin') {
      let listing;
      try {
        listing = execFileSync('/bin/ls', ['-lde', '-q', directory], {
          encoding: 'utf8', env: {LC_ALL: 'C'}, stdio: ['ignore', 'pipe', 'pipe'], timeout: 2_000,
        });
      } catch {
        throw Error(message);
      }
      const [, ...acl] = listing.trimEnd().split('\n');
      requireValue(acl.every(entry => /^\s*\d+: (?:group|user):.* deny [a-z_,]+$/.test(entry)), message);
    }
  }
}

async function installDependenciesAndCheck(dest, work, npmCli, release, files, expires) {
  requireValue(isAbsolute(npmCli), 'An independently trusted absolute npm-cli.js path is required');
  const npm = await realpath(npmCli);
  requireValue((await lstat(npm)).isFile() && basename(npm) === 'npm-cli.js', 'Trusted npm-cli.js was not found');
  const home = join(work, 'runtime');
  await mkdir(home, {mode: 0o700});
  const userConfig = join(home, 'npm-user.conf');
  const globalConfig = join(home, 'npm-global.conf');
  await Promise.all([userConfig, globalConfig].map(path => writeFile(path, '', {mode: 0o600, flag: 'wx'})));
  const env = {
    PATH: '/usr/bin:/bin',
    LC_ALL: 'C',
    HOME: home,
    TMPDIR: work,
    XDG_CONFIG_HOME: join(home, 'config'),
    XDG_CACHE_HOME: join(home, 'cache'),
    ASC_AGENT_HOME: join(home, 'member'),
    CLUB_MANAGED_ROOT: join(home, 'managed'),
  };
  const options = {cwd: dest, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']};
  requireCurrent(expires);
  try {
    const args = [
      npm, 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--no-update-notifier',
      '--userconfig=' + userConfig, '--globalconfig=' + globalConfig, '--registry=https://registry.npmjs.org',
      '--cache=' + join(home, 'npm-cache'),
    ];
    execFileSync(process.execPath, args, {...options, timeout: 300_000});
  } catch {
    throw Error('Could not install locked member dependencies');
  }

  for (const [name, expected] of files) {
    const installed = join(dest, name);
    const stat = await lstat(installed);
    requireValue(stat.isFile() && stat.size === expected.length && expected.equals(await readFile(installed)),
      'Installed member files changed during dependency installation');
  }
  requireCurrent(expires);
  let report;
  try {
    report = JSON.parse(execFileSync(process.execPath, [join(dest, 'club-launcher.mjs'), 'doctor'],
      {...options, timeout: 30_000}));
  } catch {
    throw Error('Member connector doctor failed');
  }
  requireValue(report?.os === process.platform && report.cliSupported === true && report.mcpRuntimePresent === true &&
    sameVersions(report.versions, release.versions), 'Member connector doctor did not confirm the expected runtime');
}

async function prepareInstall(zipPath, target, release, npmCli) {
  requireValue(['darwin', 'linux'].includes(process.platform) && process.versions.node.split('.')[0] === '24',
    'This installer requires macOS or Linux with Node.js 24');
  requireValue(release, 'No ASC member connector release is approved for this installer');
  const bytes = await readArchive(zipPath);
  requireValue(sha256(bytes) === release.sha256, 'Member ZIP digest mismatch');
  const dest = resolve(target);
  requireValue(basename(dest), 'Choose a new ASC installation directory');
  await trustedDirectory(dirname(dest), 'The ASC installation parent must be protected from other local users');
  await trustedDirectory(systemTmp, 'The system temporary directory is unsuitable for ASC installation');
  requireValue((await lstat(systemTmp)).uid === 0, 'The system temporary directory is unsuitable for ASC installation');
  const work = await mkdtemp(join(systemTmp, 'asc-verify-'));
  try {
    const zip = join(work, 'approved.zip');
    await writeFile(zip, bytes, {mode: 0o600, flag: 'wx'});
    const {files, expires} = verifiedFiles(zip, release);
    requireCurrent(expires);
    await mkdir(dest, {mode: 0o700});
    try {
      await mkdir(join(dest, 'references'), {mode: 0o700});
      for (const [name, content] of files) await writeFile(join(dest, name), content, {mode: 0o600, flag: 'wx'});
      if (npmCli !== undefined) await installDependenciesAndCheck(dest, work, npmCli, release, files, expires);
      requireCurrent(expires);
      return dest;
    } catch (error) {
      await rm(dest, {recursive: true, force: true});
      throw error;
    }
  } finally {
    await rm(work, {recursive: true, force: true});
  }
}

// Offline review/test callers can verify extraction without executing a connector.
export function extractFrozenRelease(zipPath, target, release = approvedRelease) {
  return prepareInstall(zipPath, target, release);
}

if (import.meta.main) {
  try {
    if (process.argv.length !== 5) throw Error('Use install-frozen.mjs ZIP NEW_DIRECTORY NPM_CLI_JS');
    console.log(await prepareInstall(process.argv[2], process.argv[3], approvedRelease, process.argv[4]));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
