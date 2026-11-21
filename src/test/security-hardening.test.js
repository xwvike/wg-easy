'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const AuthLimiter = require('../lib/AuthLimiter');
const Util = require('../lib/Util');
const Http = require('../lib/Http');

test('origin includes the browser-facing scheme behind a trusted proxy', () => {
  const http = new Http({ trustedProxies: '127.0.0.1' });
  const req = {
    method: 'POST',
    socket: { remoteAddress: '127.0.0.1' },
    headers: { host: 'vpn.example', 'x-forwarded-proto': 'https', origin: 'https://vpn.example' },
  };
  assert.doesNotThrow(() => http.assertSameOrigin(req));
  req.headers.origin = 'http://vpn.example';
  assert.throws(() => http.assertSameOrigin(req), { statusCode: 403 });
});

test('concurrent successes return all global reservations', () => {
  const limiter = new AuthLimiter({ globalMaxAttempts: 2 });
  for (let batch = 0; batch < 2; batch++) {
    const first = limiter.begin('192.0.2.1');
    const second = limiter.begin('192.0.2.1');
    assert.ok(first.ok && second.ok);
    limiter.succeed(second);
    limiter.succeed(first);
  }
  assert.ok(limiter.begin('192.0.2.2').ok);
});

test('one successful check leaves other pending checks and global failures accounted for', () => {
  const limiter = new AuthLimiter({ maxAttempts: 2, globalMaxAttempts: 2 });
  const first = limiter.begin('192.0.2.1');
  const second = limiter.begin('192.0.2.1');
  limiter.succeed(first);
  const third = limiter.begin('192.0.2.1');
  assert.ok(third.ok);
  assert.equal(limiter.begin('192.0.2.1').ok, false);
  assert.equal(limiter.fail(second).locked, false);
  assert.ok(limiter.fail(third).locked);
  assert.equal(limiter.begin('192.0.2.2').ok, false);
});

test('a cancelled password check releases both limits', () => {
  const limiter = new AuthLimiter({ maxAttempts: 1, globalMaxAttempts: 1 });
  limiter.cancel(limiter.begin('192.0.2.1'));
  assert.ok(limiter.begin('192.0.2.2').ok);
});

// node:test supplies a TestContext to this callback.
// eslint-disable-next-line mocha/handle-done-callback
test('startup preserves unreadable or malformed configuration and initializes a missing file', async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'wg-easy-test-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  process.env.WG_PATH = dir;
  process.env.WG_HOST = 'example.test';
  process.env.DEMO_TRAFFIC = 'false';
  // config.js reads WG_PATH at module load time.
  // eslint-disable-next-line global-require
  const WireGuard = require('../lib/WireGuard');
  const exec = t.mock.method(Util, 'exec', async () => '');
  const json = path.join(dir, 'wg0.json');
  const conf = path.join(dir, 'wg0.conf');
  await fs.writeFile(conf, 'original interface config');
  await fs.writeFile(json, '{"server":');
  await assert.rejects(new WireGuard().getConfig(), /Invalid JSON in wg0.json/);
  assert.equal(await fs.readFile(json, 'utf8'), '{"server":');
  assert.equal(await fs.readFile(conf, 'utf8'), 'original interface config');

  await fs.unlink(json);
  await fs.mkdir(json);
  await assert.rejects(new WireGuard().getConfig(), { code: 'EISDIR' });
  assert.equal(exec.mock.callCount(), 0);
  assert.equal(await fs.readFile(conf, 'utf8'), 'original interface config');

  await fs.rmdir(json);
  const initial = await new WireGuard().getConfig();
  assert.deepEqual(initial.clients, {});
  assert.deepEqual(JSON.parse(await fs.readFile(json, 'utf8')), initial);
  const reloaded = await new WireGuard().getConfig();
  assert.deepEqual(reloaded, initial);
  assert.equal(exec.mock.calls.filter((call) => call.arguments[0] === 'wg genkey').length, 1);
});

// eslint-disable-next-line mocha/handle-done-callback
test('fencing commits only after apply and stops serving state after failed rollback', async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'wg-easy-fence-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  // Each startup fixture needs its own config module and data directory.
  process.env.WG_PATH = dir;
  process.env.WG_HOST = 'example.test';
  process.env.DEMO_TRAFFIC = 'false';
  delete require.cache[require.resolve('../config')];
  delete require.cache[require.resolve('../lib/WireGuard')];
  // eslint-disable-next-line global-require
  const WireGuard = require('../lib/WireGuard');
  const exec = t.mock.method(Util, 'exec', async () => '');
  const wg = new WireGuard();
  const client = await wg.createClient({ name: 'test' });
  const file = path.join(dir, 'wg0.json');
  const readFlag = async () => JSON.parse(await fs.readFile(file, 'utf8')).clients[client.id].fenced;
  const entered = Promise.withResolvers();
  const resume = Promise.withResolvers();
  exec.mock.mockImplementation(async (cmd) => {
    if (cmd.startsWith('iptables-restore')) {
      entered.resolve();
      await resume.promise;
    }
    return '';
  });
  const update = wg.updateClientFenced({ clientId: client.id, fenced: true });
  await entered.promise;
  assert.equal(await readFlag(), false);
  const reader = wg.getClient({ clientId: client.id });
  resume.resolve();
  await update;
  assert.equal((await reader).fenced, true);
  assert.equal(await readFlag(), true);

  exec.mock.mockImplementation(async (cmd) => {
    if (cmd.startsWith('iptables-restore')) throw Error('test firewall unavailable');
    return '';
  });
  await assert.rejects(wg.updateClientFenced({ clientId: client.id, fenced: false }), { statusCode: 503 });
  assert.equal(await readFlag(), true);
  await assert.rejects(wg.getConfig(), { statusCode: 503 });
  assert.ok(exec.mock.calls.some((call) => call.arguments[0] === 'ip link set dev wg0 down'));
});
