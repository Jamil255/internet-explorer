// Application-layer writers. Each returns an AppWriter that appends one
// decoded layer to a frame.
import { ascii, hex, hexStr, ipb, macb, rand, u16, u24, u32, zeros, type AppWriter } from './bytes';

/* ---------- text protocols ---------- */

export function http(lines: string[], body = '', name = 'Hypertext Transfer Protocol'): AppWriter {
  return (w) => {
    w.begin('app', name);
    lines.forEach((l, i) => {
      const first = i === 0;
      const key = first ? (l.startsWith('HTTP/') ? 'Status line' : 'Request line') : l.split(':')[0];
      const value = first ? l : l.slice(l.indexOf(':') + 1).trim();
      w.f(key, value, ascii(l + '\r\n'));
    });
    w.f('End of headers', '\\r\\n', ascii('\r\n'));
    if (body) w.f('Body', `${ascii(body).length} bytes`, ascii(body));
    w.end(lines[0]);
  };
}

/** Line-based protocols such as SMTP: one field per line. */
export function lines(name: string, ls: string[], label: (line: string) => string): AppWriter {
  return (w) => {
    w.begin('app', name);
    for (const l of ls) w.f(l ? label(l) : 'End of headers', l || '(blank line)', ascii(l + '\r\n'));
    w.end(ls[0]);
  };
}

/** Opaque data (a continuation segment, for instance). */
export function data(name: string, text: string, label = 'Data'): AppWriter {
  return (w) => {
    w.begin('app', name);
    w.f(label, `${ascii(text).length} bytes`, ascii(text));
    w.end(`${ascii(text).length} bytes of data`);
  };
}

/* ---------- DNS ---------- */

type RType = 'A' | 'NS' | 'MX';
const RTYPES: Record<RType, number> = { A: 1, NS: 2, MX: 15 };

export interface RR {
  name: string;
  type: RType;
  ttl: number;
  data: string;
  pref?: number;
}

const qname = (n: string) => [...n.split('.').filter(Boolean).flatMap((p) => [p.length, ...ascii(p)]), 0];

export interface DnsSpec {
  id: number;
  response?: boolean;
  aa?: boolean;
  rd?: boolean;
  ra?: boolean;
  q: [string, RType];
  an?: RR[];
  ns?: RR[];
  ar?: RR[];
}

export function dns(o: DnsSpec): AppWriter {
  return (w) => {
    const an = o.an ?? [];
    const ns = o.ns ?? [];
    const ar = o.ar ?? [];
    w.begin('app', 'Domain Name System');
    w.f('Transaction ID', hex(o.id, 4), u16(o.id));
    const fl = (o.response ? 0x8000 : 0) | (o.aa ? 0x0400 : 0) | (o.rd ? 0x0100 : 0) | (o.ra ? 0x0080 : 0);
    const desc = [
      o.response ? 'response' : 'query',
      o.aa && 'authoritative',
      o.rd && 'recursion desired',
      o.ra && 'recursion available',
    ]
      .filter(Boolean)
      .join(', ');
    w.f('Flags', `${hex(fl, 4)} (${desc})`, u16(fl));
    w.f('Questions', 1, u16(1));
    w.f('Answer records', an.length, u16(an.length));
    w.f('Authority records', ns.length, u16(ns.length));
    w.f('Additional records', ar.length, u16(ar.length));
    w.f('Query', `${o.q[0]} · type ${o.q[1]} · class IN`, [...qname(o.q[0]), ...u16(RTYPES[o.q[1]]), ...u16(1)]);
    const rr = (section: string, r: RR) => {
      const rdata =
        r.type === 'A' ? ipb(r.data) : r.type === 'NS' ? qname(r.data) : [...u16(r.pref ?? 10), ...qname(r.data)];
      w.f(
        section,
        `${r.name} ${r.type} ${r.type === 'MX' ? `${r.pref ?? 10} ` : ''}${r.data} · TTL ${r.ttl}s`,
        [...qname(r.name), ...u16(RTYPES[r.type]), ...u16(1), ...u32(r.ttl), ...u16(rdata.length), ...rdata],
      );
    };
    an.forEach((r) => rr('Answer', r));
    ns.forEach((r) => rr('Authority', r));
    ar.forEach((r) => rr('Additional', r));
    w.end(`${o.response ? 'Response' : 'Query'} · ${o.q[1]} ${o.q[0]}`);
  };
}

/* ---------- DHCP ---------- */

const DHCP_TYPES = { DISCOVER: 1, OFFER: 2, REQUEST: 3, ACK: 5 } as const;

export interface DhcpSpec {
  op: 1 | 2;
  xid: number;
  type: keyof typeof DHCP_TYPES;
  chaddr: string;
  yiaddr?: string;
  siaddr?: string;
  requested?: string;
  server?: string;
  lease?: number;
  subnet?: string;
  router?: string;
  dnsServer?: string;
  hostname?: string;
  params?: boolean;
}

export function dhcp(o: DhcpSpec): AppWriter {
  return (w) => {
    w.begin('app', 'Dynamic Host Configuration Protocol');
    w.f('Message op', o.op === 1 ? 'Boot request (1)' : 'Boot reply (2)', [o.op]);
    w.f('Hardware type', 'Ethernet (1)', [1]);
    w.f('Hardware address length', 6, [6]);
    w.f('Hops', 0, [0]);
    w.f('Transaction ID', hex(o.xid, 8), u32(o.xid));
    w.f('Seconds elapsed', 0, [0, 0]);
    w.f('Flags', '0x0000 (unicast reply OK)', [0, 0]);
    const ip = (n: string, v = '0.0.0.0') => w.f(n, v, ipb(v));
    ip('Client IP (ciaddr)');
    ip('Your IP (yiaddr)', o.yiaddr);
    ip('Server IP (siaddr)', o.siaddr);
    ip('Relay agent IP (giaddr)');
    w.f('Client MAC (chaddr)', o.chaddr, [...macb(o.chaddr), ...zeros(10)]);
    w.f('Server name · Boot file', 'unused (192 zero bytes)', zeros(192));
    w.f('Magic cookie', 'DHCP (0x63825363)', [0x63, 0x82, 0x53, 0x63]);
    const opt = (code: number, name: string, value: string, body: number[]) =>
      w.f(`Option ${code} · ${name}`, value, [code, body.length, ...body]);
    opt(53, 'Message type', `${o.type} (${DHCP_TYPES[o.type]})`, [DHCP_TYPES[o.type]]);
    if (o.hostname) opt(12, 'Host name', o.hostname, ascii(o.hostname));
    if (o.requested) opt(50, 'Requested IP', o.requested, ipb(o.requested));
    if (o.server) opt(54, 'Server identifier', o.server, ipb(o.server));
    if (o.params) opt(55, 'Parameter request list', 'Subnet mask, Router, DNS server, Domain name', [1, 3, 6, 15]);
    if (o.lease) opt(51, 'Lease time', `${o.lease / 3600} hours`, u32(o.lease));
    if (o.subnet) opt(1, 'Subnet mask', o.subnet, ipb(o.subnet));
    if (o.router) opt(3, 'Router', o.router, ipb(o.router));
    if (o.dnsServer) opt(6, 'DNS server', o.dnsServer, ipb(o.dnsServer));
    w.f('Option 255 · End', '—', [255]);
    w.end(`DHCP ${o.type} · ${hex(o.xid, 8)}`);
  };
}

/* ---------- NTP ---------- */

const NTP_BASE_MS = Date.UTC(2026, 10, 11, 12, 0, 0);

function ntpTs(offsetMs: number | null): [string, number[]] {
  if (offsetMs === null) return ['0 (not set)', zeros(8)];
  const ms = NTP_BASE_MS + offsetMs;
  const secs = Math.floor(ms / 1000) + 2208988800;
  const frac = Math.floor(((ms % 1000) / 1000) * 2 ** 32);
  const label = new Date(ms).toISOString().replace('T', ' ').replace('Z', ' UTC');
  return [label, [...u32(secs), ...u32(frac)]];
}

export function ntp(o: { mode: 3 | 4; t1: number; t2?: number; t3?: number }): AppWriter {
  return (w) => {
    const server = o.mode === 4;
    w.begin('app', 'Network Time Protocol');
    w.f('Leap · Version · Mode', `no warning · NTPv4 · ${server ? 'server (4)' : 'client (3)'}`, [(4 << 3) | o.mode]);
    w.f('Stratum', server ? '2 (synced to a reference clock)' : '0 (unspecified)', [server ? 2 : 0]);
    w.f('Poll interval', '2⁶ = 64 s', [6]);
    w.f('Precision', '2⁻²⁰ s (about 1 µs)', [0xec]);
    w.f('Root delay', server ? '0.0005 s' : '0', server ? [0, 0, 0, 0x21] : zeros(4));
    w.f('Root dispersion', server ? '0.0010 s' : '0', server ? [0, 0, 0, 0x42] : zeros(4));
    w.f('Reference ID', server ? '192.0.2.1 (upstream clock)' : '0', server ? ipb('192.0.2.1') : zeros(4));
    const ts = (n: string, v: number | null) => {
      const [label, b] = ntpTs(v);
      w.f(n, label, b);
    };
    ts('Reference timestamp', server ? -30000 : null);
    ts('Origin timestamp (T1)', server ? o.t1 : null);
    ts('Receive timestamp (T2)', server ? o.t2 ?? null : null);
    ts('Transmit timestamp', server ? o.t3 ?? null : o.t1);
    w.end(server ? 'Server reply' : 'Client request');
  };
}

/* ---------- TLS 1.3 ---------- */

const ext = (type: number, body: number[]) => [...u16(type), ...u16(body.length), ...body];

export function clientHello(sni: string): AppWriter {
  return (w) => {
    w.begin('app', 'Transport Layer Security');
    const sniB = ascii(sni);
    const exts: [string, string, number[]][] = [
      ['Extension · server_name (SNI)', sni, ext(0, [...u16(sniB.length + 3), 0, ...u16(sniB.length), ...sniB])],
      ['Extension · supported_groups', 'x25519', ext(0x0a, [0, 2, 0, 0x1d])],
      ['Extension · signature_algorithms', 'ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256', ext(0x0d, [0, 4, 4, 3, 8, 4])],
      ['Extension · supported_versions', 'TLS 1.3, TLS 1.2', ext(0x2b, [4, 3, 4, 3, 3])],
      ['Extension · key_share', 'x25519 public key (32 bytes)', ext(0x33, [0, 36, 0, 0x1d, 0, 32, ...rand('ck' + sni, 32)])],
    ];
    const extLen = exts.reduce((s, e) => s + e[2].length, 0);
    const suites = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];
    const hsLen = 2 + 32 + 33 + 2 + suites.length + 2 + 2 + extLen;
    w.f('Content type', 'Handshake (22)', [22]);
    w.f('Record version', '0x0301 (legacy value)', u16(0x0301));
    w.f('Record length', `${hsLen + 4} bytes`, u16(hsLen + 4));
    w.f('Handshake type', 'Client Hello (1)', [1]);
    w.f('Handshake length', `${hsLen} bytes`, u24(hsLen));
    w.f('Legacy version', 'TLS 1.2 (0x0303)', u16(0x0303));
    w.f('Random', '32 random bytes', rand('cr' + sni, 32));
    w.f('Session ID', '32 bytes (compatibility mode)', [32, ...rand('sid' + sni, 32)]);
    w.f(
      'Cipher suites',
      'TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256',
      [...u16(suites.length), ...suites],
    );
    w.f('Compression methods', 'null', [1, 0]);
    w.f('Extensions length', `${extLen} bytes`, u16(extLen));
    exts.forEach(([n, v, b]) => w.f(n, v, b));
    w.end(`Client Hello · SNI ${sni}`);
  };
}

function appRecord(w: Parameters<AppWriter>[0], len: number, what: string, seed: string) {
  w.f('Content type', 'Application Data (23)', [23]);
  w.f('Record version', 'TLS 1.2 (0x0303)', u16(0x0303));
  w.f('Record length', `${len} bytes`, u16(len));
  w.f('Encrypted data', what, rand(seed, len));
}

export function serverHello(sni: string): AppWriter {
  return (w) => {
    w.begin('app', 'Transport Layer Security');
    const exts: [string, string, number[]][] = [
      ['Extension · supported_versions', 'TLS 1.3 (0x0304)', ext(0x2b, [3, 4])],
      ['Extension · key_share', 'x25519 public key (32 bytes)', ext(0x33, [0, 0x1d, 0, 32, ...rand('sk' + sni, 32)])],
    ];
    const extLen = exts.reduce((s, e) => s + e[2].length, 0);
    const hsLen = 2 + 32 + 33 + 2 + 1 + 2 + extLen;
    w.f('Content type', 'Handshake (22)', [22]);
    w.f('Record version', 'TLS 1.2 (0x0303)', u16(0x0303));
    w.f('Record length', `${hsLen + 4} bytes`, u16(hsLen + 4));
    w.f('Handshake type', 'Server Hello (2)', [2]);
    w.f('Handshake length', `${hsLen} bytes`, u24(hsLen));
    w.f('Legacy version', 'TLS 1.2 (0x0303)', u16(0x0303));
    w.f('Random', '32 random bytes', rand('sr' + sni, 32));
    w.f('Session ID (echoed)', '32 bytes', [32, ...rand('sid' + sni, 32)]);
    w.f('Chosen cipher suite', 'TLS_AES_128_GCM_SHA256 (0x1301)', [0x13, 0x01]);
    w.f('Compression method', 'null', [0]);
    w.f('Extensions length', `${extLen} bytes`, u16(extLen));
    exts.forEach(([n, v, b]) => w.f(n, v, b));
    w.f('Change Cipher Spec record', 'compatibility only (6 bytes)', [20, 3, 3, 0, 1, 1]);
    appRecord(w, 1180, 'Encrypted Extensions, Certificate, Certificate Verify, Finished', 'sflight' + sni);
    w.end('Server Hello, Change Cipher Spec, encrypted handshake');
  };
}

export function clientFinished(sni: string): AppWriter {
  return (w) => {
    w.begin('app', 'Transport Layer Security');
    w.f('Change Cipher Spec record', 'compatibility only (6 bytes)', [20, 3, 3, 0, 1, 1]);
    appRecord(w, 53, 'Finished (a MAC over the whole handshake)', 'cfin' + sni);
    w.end('Change Cipher Spec, encrypted Finished');
  };
}

export function encrypted(len: number, what: string, seed: string): AppWriter {
  return (w) => {
    w.begin('app', 'Transport Layer Security');
    appRecord(w, len, what, seed);
    w.end(`Application Data · ${len} bytes`);
  };
}

/* ---------- WebSocket ---------- */

const WS_OPS: Record<number, string> = { 1: 'Text', 8: 'Close', 9: 'Ping', 10: 'Pong' };

export function wsFrame(o: { text?: string; opcode?: number; masked: boolean; seed: string; close?: number }): AppWriter {
  return (w) => {
    const op = o.opcode ?? 1;
    let payload = o.text !== undefined ? ascii(o.text) : [];
    if (o.close !== undefined) payload = [...u16(o.close), ...payload];
    w.begin('app', 'WebSocket');
    w.f('FIN · Opcode', `final frame · ${WS_OPS[op]} (${op})`, [0x80 | op]);
    w.f('Mask · Payload length', `${o.masked ? 'masked' : 'not masked'} · ${payload.length} bytes`, [
      (o.masked ? 0x80 : 0) | payload.length,
    ]);
    const shown = o.close !== undefined ? `${o.close} (normal closure)` : o.text ? `“${o.text}”` : '(empty)';
    if (o.masked) {
      const key = rand(o.seed, 4);
      w.f('Masking key', hexStr(key), key);
      w.f('Payload (masked)', shown, payload.map((b, i) => b ^ key[i % 4]));
    } else if (payload.length) {
      w.f('Payload', shown, payload);
    }
    w.end(`${WS_OPS[op]} frame${o.text ? ` · ${o.text}` : ''}`);
  };
}
