/* eslint-disable @typescript-eslint/no-explicit-any */
import { mkdir, readFile, writeFile } from 'node:fs/promises';

import { fetch, ProxyAgent, Response } from 'undici';

const { CLIENT_APP = 'app', API, STATS_API } = process.env;
const BROWSER = 'CHROME';
const TOKEN_CACHE_FILE = new URL('.cache/token.json', import.meta.url);
const TOKEN_CACHE_DIR = new URL('.cache/', import.meta.url);
const TOKEN_CACHE_GRACE_MS = 10 * 60_000;
const TOKEN_CACHE_FALLBACK_TTL_MS = 55 * 10 * 60_000;

type Token = { value: string; expirationTime?: number; [k: string]: unknown };
type ProxyEndpoint = { host: string; port: number; signature: string };
type PlanPrice = { plan: string; billing?: string; price: string; note?: string };
type TokenCache = { authToken: string; securityToken: Token; cachedAt: number };
type CountryEntry = {
  title?: string;
  code?: { iso2?: string; iso3?: string };
  accessType?: string;
  servers?: { elements?: any[] };
};

async function mustJson(res: Response): Promise<unknown> {
  const text = await res.text();
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return text;
  }
}

async function postJson<T>(url: string, body: unknown, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  const data = (await mustJson(res)) as T;
  if (!res.ok) {
    throw new Error(
      `POST ${url} failed: ${res.status} ${res.statusText}\n${typeof data === 'string' ? data : JSON.stringify(data)}`,
    );
  }
  return data;
}

async function getJson<T>(url: string, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetch(url, { headers });
  const data = (await mustJson(res)) as T;
  if (!res.ok) {
    throw new Error(
      `GET ${url} failed: ${res.status} ${res.statusText}\n${typeof data === 'string' ? data : JSON.stringify(data)}`,
    );
  }
  return data;
}

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function isTokenFresh(token: Token, cachedAt: number): boolean {
  if ((token as { expired?: boolean }).expired === true) return false;
  const expiresAt = typeof token.expirationTime === 'number' ? token.expirationTime : NaN;
  if (Number.isFinite(expiresAt)) {
    return expiresAt - Date.now() > TOKEN_CACHE_GRACE_MS;
  }
  return cachedAt + TOKEN_CACHE_FALLBACK_TTL_MS > Date.now();
}

async function readTokenCache(): Promise<TokenCache | null> {
  try {
    const raw = await readFile(TOKEN_CACHE_FILE, 'utf8');
    const parsed = JSON.parse(raw) as TokenCache;
    if (!parsed || typeof parsed !== 'object') return null;
    if (typeof parsed.authToken !== 'string' || !parsed.authToken) return null;
    if (!parsed.securityToken || typeof parsed.securityToken !== 'object') return null;
    if (typeof parsed.securityToken.value !== 'string' || !parsed.securityToken.value) return null;
    if (typeof parsed.cachedAt !== 'number') return null;
    return parsed;
  } catch {
    return null;
  }
}

async function writeTokenCache(authToken: string, securityToken: Token): Promise<void> {
  await mkdir(TOKEN_CACHE_DIR, { recursive: true });
  const payload: TokenCache = { authToken, securityToken, cachedAt: Date.now() };
  await writeFile(TOKEN_CACHE_FILE, JSON.stringify(payload, null, 2) + '\n', 'utf8');
}

async function getCachedAuthAndSecurityTokens(): Promise<{ authToken: string; securityToken: Token }> {
  const cached = await readTokenCache();
  if (cached && isTokenFresh(cached.securityToken, cached.cachedAt)) {
    return { authToken: cached.authToken, securityToken: cached.securityToken };
  }

  if (cached?.authToken) {
    try {
      const securityToken = await getSecurityToken(cached.authToken);
      await writeTokenCache(cached.authToken, securityToken);
      return { authToken: cached.authToken, securityToken };
    } catch {
      // fall through to a fresh registration
    }
  }

  const authToken = await registerAnonymous();
  const securityToken = await getSecurityToken(authToken);
  await writeTokenCache(authToken, securityToken);
  return { authToken, securityToken };
}

async function registerAnonymous(): Promise<string> {
  const url = `${API}/registrations/clientApps/${CLIENT_APP}/users/anonymous`;
  const data = await postJson<any>(url, { clientApp: { name: CLIENT_APP, browser: BROWSER } });

  // Some builds return { value: "..." }, others might return a raw string.
  if (typeof data === 'string') return data;
  if (data?.value) return String(data.value);
  throw new Error(`Unexpected anonymous registration response: ${JSON.stringify(data)}`);
}

async function getSecurityToken(authToken: string): Promise<Token> {
  const url = `${API}/security/tokens/accs`;
  const data = await postJson<Token>(
    url,
    { type: 'accs', clientApp: { name: CLIENT_APP } },
    { Authorization: `Bearer ${authToken}` },
  );
  if (!data?.value) throw new Error(`Unexpected security token response: ${JSON.stringify(data)}`);
  return data;
}

async function getCountries(securityTokenValue: string): Promise<CountryEntry[]> {
  const url = `${STATS_API}/entrypoints/countries`;

  // This is the header you were missing.
  const root = await getJson<any>(url, {
    'X-Client-App': CLIENT_APP,
    Accept: 'application/json',
    pragma: 'no-cache',
    'cache-control': 'no-cache',
    Authorization: `Bearer ${securityTokenValue}`,
  });

  return root?.countries?.elements ?? [];
}

function getCountryProxyEndpoints(country: CountryEntry): ProxyEndpoint[] {
  const endpoints: ProxyEndpoint[] = [];
  const servers: any[] = country?.servers?.elements ?? [];

  for (const s of servers) {
    const signature = String(s?.signature ?? '');
    const primary = s?.address?.primary;
    const secondary: any[] = s?.address?.secondary ?? [];

    if (primary?.host && primary?.port && signature) {
      endpoints.push({ host: String(primary.host), port: Number(primary.port), signature });
    }
    for (const a of secondary) {
      if (a?.host && a?.port && signature) {
        endpoints.push({ host: String(a.host), port: Number(a.port), signature });
      }
    }
  }

  if (!endpoints.length) return [];
  return dedupeProxyEndpoints(endpoints);
}

async function getProxyToken(securityTokenValue: string, signature: string): Promise<Token> {
  const url = `${API}/security/tokens/accs-proxy`;
  const data = await postJson<Token>(
    url,
    { type: 'accs-proxy', clientApp: { name: CLIENT_APP }, signature },
    { Authorization: `Bearer ${securityTokenValue}` },
  );
  if (!data?.value) throw new Error(`Unexpected proxy token response: ${JSON.stringify(data)}`);
  return data;
}

function parsePremiumPrices(html: string): string[] {
  const data = extractYtInitialData(html);
  if (data) {
    const plans = parsePremiumPlansFromInitialData(data);
    if (plans.length) return formatPlanPrices(plans);
  }

  // Fallback: extract plausible price strings like "$13.99".
  const priceRegex = /\$\s*\d+(?:[.,]\d{2})?/g;
  const matches = html.match(priceRegex) ?? [];
  return Array.from(new Set(matches.map((m) => m.trim())));
}

function extractYtInitialData(html: string): unknown | null {
  const json = extractJsonVar(html, 'ytInitialData');
  if (!json) return null;
  try {
    return JSON.parse(json) as unknown;
  } catch {
    return null;
  }
}

function extractJsonVar(html: string, name: string): string | null {
  const patterns = [`var ${name} =`, `${name} =`];
  let idx = -1;
  for (const pattern of patterns) {
    idx = html.indexOf(pattern);
    if (idx !== -1) break;
  }
  if (idx === -1) return null;
  idx = html.indexOf('=', idx);
  if (idx === -1) return null;
  idx += 1;
  while (idx < html.length && /\s/.test(html[idx])) idx += 1;
  if (html[idx] !== '{') return null;

  // Walk the JSON text with a brace counter that ignores strings.
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = idx; i < html.length; i++) {
    const ch = html[i];
    if (inString) {
      if (escape) {
        escape = false;
      } else if (ch === '\\') {
        escape = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
    } else if (ch === '{') {
      depth += 1;
    } else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return html.slice(idx, i + 1);
    }
  }
  return null;
}

function parsePremiumPlansFromInitialData(data: unknown): PlanPrice[] {
  const sections: any[] = [];
  walkJson(data, (node) => {
    if (node && typeof node === 'object' && 'lpOfferCardSectionViewModel' in node) {
      sections.push((node as any).lpOfferCardSectionViewModel);
    }
  });

  const entries: PlanPrice[] = [];
  for (const section of sections) {
    const sectionTitle = normalizeText(readText(section?.title));
    const groupLabel = deriveGroupLabel(sectionTitle);
    const cards: any[] = section?.offerCards ?? [];
    for (const cardRef of cards) {
      const card = cardRef?.lpOfferCardViewModel ?? cardRef;
      const planRaw = normalizeText(readText(card?.title));
      if (!planRaw) continue;
      const plan = applyGroupLabel(planRaw, groupLabel);
      const options: any[] = card?.offerOptions ?? [];
      for (const optionRef of options) {
        const option = optionRef?.lpOfferCardOptionViewModel ?? optionRef;
        const price = formatPriceText(readText(option?.title));
        if (!price) continue;
        const billing = normalizeText(readText(option?.eyebrowText));
        entries.push({ plan, billing, price });
      }
    }
  }

  if (entries.length) return dedupePlanPrices(entries);
  return parseOptionItemPlans(data);
}

function parseOptionItemPlans(data: unknown): PlanPrice[] {
  const entries: PlanPrice[] = [];
  walkJson(data, (node) => {
    if (node && typeof node === 'object' && 'optionItemRenderer' in node) {
      const item = (node as any).optionItemRenderer;
      const plan = normalizeText(readText(item?.title));
      if (!plan) return;
      const subtitle = normalizeText(readText(item?.subtitle));
      const priceMatches = subtitle.match(/\$\s*\d+(?:[.,]\d{2})?/g) ?? [];
      let price = priceMatches.length ? formatPriceText(priceMatches[priceMatches.length - 1]) : '';
      if (price && /\/\s*month\b|per\s+month\b/i.test(subtitle)) {
        price = `${price} per month`;
      }
      if (!price) return;
      entries.push({ plan, price });
    }
  });
  return dedupePlanPrices(entries);
}

function formatPlanPrices(entries: PlanPrice[]): string[] {
  return entries.map((entry) => {
    const plan = entry.plan;
    const billing = entry.billing ? ` (${entry.billing})` : '';
    return `${plan}${billing} - ${entry.price}`;
  });
}

function applyGroupLabel(plan: string, group?: string): string {
  if (!group) return plan;
  const lowerPlan = plan.toLowerCase();
  const lowerGroup = group.toLowerCase();
  if (lowerPlan.includes(lowerGroup)) return plan;
  if (lowerGroup === 'premium' && ['individual', 'family', 'student'].includes(lowerPlan)) {
    return `${group} ${plan}`;
  }
  return `${group} ${plan}`;
}

function deriveGroupLabel(title: string): string | undefined {
  const lower = title.toLowerCase();
  if (lower.includes('premium lite')) return 'Premium Lite';
  if (lower.includes('premium')) return 'Premium';
  return undefined;
}

function readText(node: unknown): string {
  if (!node) return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(readText).join('');
  if (typeof node === 'object') {
    const obj = node as any;
    if (typeof obj.content === 'string') return obj.content;
    if (typeof obj.simpleText === 'string') return obj.simpleText;
    if (Array.isArray(obj.runs)) return obj.runs.map((r: any) => (r?.text ? String(r.text) : '')).join('');
  }
  return '';
}

function normalizeText(text: string): string {
  return text
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, '')
    .replace(/\u00A0/g, ' ')
    .replace(/\u2022/g, ';')
    .replace(/\s*;\s*/g, '; ')
    .replace(/\s+/g, ' ')
    .replace(/\s*\*+$/g, '')
    .trim();
}

function formatCountryLabel(country: CountryEntry): string {
  const name = normalizeText(String(country?.title ?? '')) || 'Unknown';
  const iso2 = normalizeText(String(country?.code?.iso2 ?? '')).toUpperCase();
  return iso2 ? `${name} (${iso2})` : name;
}

function dedupeProxyEndpoints(endpoints: ProxyEndpoint[]): ProxyEndpoint[] {
  const seen = new Set<string>();
  const out: ProxyEndpoint[] = [];
  for (const endpoint of endpoints) {
    const key = `${endpoint.host}:${endpoint.port}:${endpoint.signature}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(endpoint);
  }
  return out;
}

function formatPriceText(text: string): string {
  return normalizeText(text)
    .replace(/\/\s*month\b/gi, ' per month')
    .replace(/\/\s*person\b/gi, ' per person');
}

function dedupePlanPrices(entries: PlanPrice[]): PlanPrice[] {
  const seen = new Set<string>();
  const out: PlanPrice[] = [];
  for (const entry of entries) {
    const key = `${entry.plan}|${entry.billing ?? ''}|${entry.price}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(entry);
  }
  return out;
}

function walkJson(node: unknown, visit: (value: unknown) => void): void {
  if (!node || typeof node !== 'object') return;
  visit(node);
  if (Array.isArray(node)) {
    for (const item of node) walkJson(item, visit);
    return;
  }
  for (const value of Object.values(node as Record<string, unknown>)) {
    walkJson(value, visit);
  }
}

async function fetchPremiumPricesViaProxies(securityTokenValue: string, proxies: ProxyEndpoint[]) {
  if (!proxies.length) throw new Error('No proxy endpoints available');

  const attempts = Math.min(8, proxies.length);
  for (let attempt = 0; attempt < attempts; attempt++) {
    const p = pickRandom(proxies);

    for (let i = 0; i < 3; i++) {
      const proxyToken = await getProxyToken(securityTokenValue, p.signature);

      // Proxy auth: username = proxyToken.value, password = "1"
      const proxyUrl = new URL(`http://${p.host}:${p.port}`);
      proxyUrl.username = proxyToken.value;
      proxyUrl.password = '1';

      const dispatcher = new ProxyAgent(proxyUrl.toString());
      const res = await fetch('https://www.youtube.com/premium', {
        dispatcher,
        headers: {
          // Basic headers so YouTube treats this like a normal browser request.
          'accept-language': 'en-US,en;q=0.9',
          'user-agent':
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        },
      });

      const html = await res.text();
      if (!res.ok) {
        await new Promise((resolve) => setTimeout(resolve, 5_000));
        continue;
      }
      return parsePremiumPrices(html);
    }

    return [];
  }
}

export async function printCountryPricesReport(): Promise<void> {
  const { securityToken } = await getCachedAuthAndSecurityTokens();
  const countries = await getCountries(securityToken.value);

  for (const country of countries) {
    const label = formatCountryLabel(country);
    const proxies = getCountryProxyEndpoints(country);

    if (!proxies.length || country?.accessType === 'INACCESSIBLE') {
      console.log(`${label}: SKIP (no accessible servers)`);
      continue;
    }

    try {
      const prices = await fetchPremiumPricesViaProxies(securityToken.value, proxies);
      prices?.length && console.log(`${label}: ${prices.join('; ')}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.log(`${label}: ERROR ${message}`);
    }
  }
}

// Tiny runnable example:
printCountryPricesReport().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
