import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import ts from 'typescript';

const require = createRequire(import.meta.url);
const source = readFileSync(new URL('../src/api/topology.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText.replace("from 'axios'", `from '${pathToFileURL(require.resolve('axios')).href}'`);
const { fetchTopology, resolveManagerAddress } = await import('data:text/javascript;base64,' + Buffer.from(compiled).toString('base64'));
const config = { username: 'wazuh', password: 'test', indexerUsername: 'reader', indexerPassword: 'test' };
const agent = (id) => ({ id, name: `host-${id}`, status: 'active', ip: '10.0.0.1' });
const bucket = (id, level, description) => ({
  key: id, highest: { hits: { hits: [{ _source: { rule: { level, description } } }] } },
});

function mockClient(records, alertResponse = { aggregations: { agents: { buckets: [] } } }) {
  const calls = { get: [], post: [] };
  return {
    calls,
    async get(url, options) {
      calls.get.push({ url, options });
      if (url.endsWith('/authenticate')) return { data: { data: { token: 'token' } } };
      assert.equal(url, '/wazuh-api/agents');
      assert.equal(options.headers.Authorization, 'Bearer token');
      const { offset, limit } = options.params;
      return { data: { error: 0, data: {
        affected_items: records.slice(offset, offset + limit), total_affected_items: records.length,
      } } };
    },
    async post(url, body, options) {
      calls.post.push({ url, body, options });
      assert.equal(url, '/wazuh-indexer/wazuh-alerts-*/_search');
      return { data: alertResponse };
    },
  };
}

test('设备与最高告警按 Agent ID 合并，无告警设备保留正常状态', async () => {
  const client = mockClient([agent('001'), agent('002')], {
    aggregations: { agents: { buckets: [bucket('002', 14, 'High severity')] } },
  });
  const result = await fetchTopology(config, undefined, client);
  assert.equal(result[0].has_threat, false);
  assert.equal(result[0].threat_level, 0);
  assert.equal(result[1].has_threat, true);
  assert.equal(result[1].threat_level, 14);
  assert.equal(result[1].threat_info, 'High severity');
  const { body, options } = client.calls.post[0];
  assert.equal(body.size, 0);
  assert.equal(body.aggs.agents.aggs.highest.top_hits.size, 1);
  assert.deepEqual(body.aggs.agents.aggs.highest.top_hits.sort[0], { 'rule.level': 'desc' });
  assert.equal(body.query.bool.filter[0].range['rule.level'].gte, 10);
  const since = new Date(body.query.bool.filter[1].range.timestamp.gte).getTime();
  assert.ok(Math.abs(Date.now() - since - 30 * 60000) < 5000);
  assert.deepEqual(options.auth, { username: 'reader', password: 'test' });
});

test('超过 500 台设备时完整分页，告警查询按设备分批', async () => {
  const records = Array.from({ length: 1001 }, (_, i) => agent(String(i).padStart(3, '0')));
  const client = mockClient(records);
  const result = await fetchTopology(config, undefined, client);
  assert.equal(result.length, 1001);
  assert.deepEqual(client.calls.get.slice(1).map(call => call.options.params.offset), [0, 500, 1000]);
  assert.deepEqual(client.calls.post.map(call => call.body.aggs.agents.terms.size), [500, 500, 1]);
  assert.deepEqual(client.calls.post[2].body.query.bool.filter[2].terms['agent.id'], ['1000']);
});

test('没有设备时返回空列表，不查询告警', async () => {
  const client = mockClient([]);
  assert.deepEqual(await fetchTopology(config, undefined, client), []);
  assert.equal(client.calls.post.length, 0);
});

test('认证失败时直接报错', async () => {
  const client = mockClient([]);
  client.get = async () => { throw new Error('401 Unauthorized'); };
  await assert.rejects(fetchTopology(config, undefined, client), /401 Unauthorized/);
  assert.equal(client.calls.post.length, 0);
});

test('配置缺失和无效 Token 不会继续查询', async () => {
  const client = mockClient([]);
  await assert.rejects(fetchTopology({ ...config, password: '' }, undefined, client), /账号密码/);
  assert.equal(client.calls.get.length, 0);
  client.get = async () => ({ data: { data: {} } });
  await assert.rejects(fetchTopology(config, undefined, client), /Token/);
});

test('设备分页提前结束会报错，避免静默遗漏设备', async () => {
  const client = mockClient([]);
  const original = client.get;
  client.get = async (url, options) => url.endsWith('/authenticate') ? original(url, options)
    : { data: { data: { affected_items: [], total_affected_items: 10 } } };
  await assert.rejects(fetchTopology(config, undefined, client), /分页提前结束/);
});

for (const response of [
  { timed_out: true, aggregations: { agents: { buckets: [] } } },
  { _shards: { failed: 1 }, aggregations: { agents: { buckets: [] } } },
  { hits: { hits: [] } },
]) {
  test(`不完整告警响应报错，不把设备误标为正常: ${JSON.stringify(response)}`, async () => {
    await assert.rejects(fetchTopology(config, undefined, mockClient([agent('001')], response)), /告警查询未完整返回/);
  });
}

test('请求使用超时和同一个取消信号', async () => {
  const controller = new AbortController();
  const client = mockClient([agent('001')]);
  await fetchTopology(config, controller.signal, client);
  for (const call of [...client.calls.get, ...client.calls.post]) {
    assert.equal(call.options.signal, controller.signal);
    assert.equal(call.options.timeout, 30000);
  }
});


test('中心节点返回回环地址时显示配置的 Wazuh 服务端地址', () => {
  for (const ip of ['127.0.0.1', '127.0.1.1', 'localhost', '::1', '[::1]',
    '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1', '0.0.0.0', '::', 'unknown', 'any', '', undefined]) {
    assert.equal(resolveManagerAddress(ip, '192.168.74.130'), '192.168.74.130');
  }
});

test('中心节点返回实际地址时保留实际地址，支持 IPv6 和域名', () => {
  assert.equal(resolveManagerAddress('10.0.0.5', '192.168.74.130'), '10.0.0.5');
  assert.equal(resolveManagerAddress('2001:db8::5', '192.168.74.130'), '2001:db8::5');
  assert.equal(resolveManagerAddress('127.0.0.1', 'wazuh.example.com'), 'wazuh.example.com');
});

test('没有有效服务器地址时显示配置提示，不误用访问者地址', () => {
  assert.equal(resolveManagerAddress('127.0.0.1', 'localhost'), '未配置服务器地址');
  assert.equal(resolveManagerAddress(undefined, undefined), '未配置服务器地址');
});
