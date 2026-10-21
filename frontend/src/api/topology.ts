import axios, { type AxiosInstance } from 'axios';

export interface TopologyAgent {
  id: string;
  name: string;
  ip: string;
  status: string;
  has_threat: boolean;
  threat_info: string;
  threat_level: number;
}

export interface TopologyConfig {
  username: string;
  password: string;
  indexerUsername: string;
  indexerPassword: string;
}

interface AgentRecord { id: string; name: string; ip?: string; status: string }
interface AlertBucket {
  key: string;
  highest: { hits: { hits: Array<{ _source: { rule: { level: number; description?: string } } }> } };
}

// Manager records may report a loopback address; use the configured Wazuh host instead.
export function resolveManagerAddress(ip?: string, configuredHost?: string): string {
  const usable = (value?: string): string => {
    const host = (value || '').trim().replace(/^\[|\]$/g, '');
    const normalized = host.toLowerCase();
    if (!host || ['unknown', 'any', 'localhost', '0.0.0.0', '::', '::1',
      '0:0:0:0:0:0:0:0', '0:0:0:0:0:0:0:1'].includes(normalized)
      || /^127\./.test(normalized) || normalized.endsWith('.localhost')
      || /^::ffff:127\./.test(normalized)) return '';
    return host;
  };
  return usable(ip) || usable(configuredHost) || '未配置服务器地址';
}

// Query through the existing same-origin proxies; no separate topology server is needed.
export async function fetchTopology(
  config: TopologyConfig,
  signal?: AbortSignal,
  client: Pick<AxiosInstance, 'get' | 'post'> = axios,
): Promise<TopologyAgent[]> {
  if (!config.username || !config.password || !config.indexerUsername || !config.indexerPassword) {
    throw new Error('请先配置 Wazuh API 和 Indexer 的账号密码');
  }
  const options = { signal, timeout: 30000 };
  const auth = await client.get('/wazuh-api/security/user/authenticate', {
    ...options, auth: { username: config.username, password: config.password },
  });
  const token = auth.data?.data?.token;
  if (typeof token !== 'string' || !token) throw new Error('Wazuh 认证未返回有效 Token');

  const agents: AgentRecord[] = [];
  const pageSize = 500;
  for (let offset = 0; ; ) {
    const response = await client.get('/wazuh-api/agents', {
      ...options,
      headers: { Authorization: 'Bearer ' + token },
      params: { limit: pageSize, offset, sort: '+id' },
    });
    const data = response.data?.data;
    if (response.data?.error || !Array.isArray(data?.affected_items)
      || !Number.isInteger(data.total_affected_items) || data.total_affected_items < 0
      || data.total_failed_items > 0) {
      throw new Error('Wazuh 设备列表响应异常');
    }
    const page: AgentRecord[] = data.affected_items;
    agents.push(...page);
    offset += page.length;
    if (offset >= data.total_affected_items) break;
    if (!page.length) throw new Error('Wazuh 设备列表分页提前结束，请重试');
  }

  const threats = new Map<string, { level: number; description?: string }>();
  const since = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  // Bound each aggregation to known agent IDs so high alert volume cannot hide other hosts.
  for (let start = 0; start < agents.length; start += pageSize) {
    const ids = agents.slice(start, start + pageSize).map(agent => String(agent.id));
    const response = await client.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 0,
      query: { bool: { filter: [
        { range: { 'rule.level': { gte: 10 } } },
        { range: { timestamp: { gte: since } } },
        { terms: { 'agent.id': ids } },
      ] } },
      aggs: { agents: { terms: { field: 'agent.id', size: ids.length }, aggs: {
        highest: { top_hits: {
          size: 1,
          sort: [{ 'rule.level': 'desc' }, { timestamp: 'desc' }],
          _source: ['rule.level', 'rule.description'],
        } },
      } } },
    }, {
      ...options, auth: { username: config.indexerUsername, password: config.indexerPassword },
    });
    const data = response.data;
    const buckets: AlertBucket[] = data?.aggregations?.agents?.buckets;
    if (data?.timed_out || data?._shards?.failed > 0 || !Array.isArray(buckets)) {
      throw new Error('Indexer 告警查询未完整返回，请重试');
    }
    for (const bucket of buckets) {
      const rule = bucket.highest?.hits?.hits?.[0]?._source?.rule;
      if (!rule || !Number.isFinite(rule.level)) throw new Error('Indexer 告警响应异常');
      threats.set(String(bucket.key), rule);
    }
  }
  return agents.map(agent => {
    const threat = threats.get(String(agent.id));
    return {
      id: String(agent.id), name: agent.name, ip: agent.ip || 'unknown', status: agent.status,
      has_threat: !!threat, threat_info: threat?.description || '', threat_level: threat?.level || 0,
    };
  });
}
