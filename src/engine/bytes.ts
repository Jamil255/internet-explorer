// Low-level packet builder: writes real bytes and records every field's
// position, so the inspector can decode a frame byte by byte.

/** 'eth' | 'ip' | 'tcp' | 'udp' | 'icmp' | 'app' for IP frames; any short key for custom layers (e.g. 'wlan', 'arp', 'pppoe'). */
export type LayerKey = string;

export interface Field {
  name: string;
  value: string;
  start: number;
  len: number;
}

export interface Layer {
  key: LayerKey;
  name: string;
  summary: string;
  start: number;
  len: number;
  fields: Field[];
}

export interface Frame {
  bytes: number[];
  layers: Layer[];
  payloadLen: number;
}

export const u16 = (v: number) => [(v >>> 8) & 255, v & 255];
export const u24 = (v: number) => [(v >>> 16) & 255, (v >>> 8) & 255, v & 255];
export const u32 = (v: number) => [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
export const ipb = (s: string) => s.split('.').map(Number);
/** IPv6 text → 16 bytes (supports :: compression). */
export function ip6b(s: string): number[] {
  const [head, tail] = s.includes('::') ? s.split('::') : [s, ''];
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = [...h, ...new Array(8 - h.length - t.length).fill('0'), ...t];
  return groups.flatMap((g) => u16(parseInt(g || '0', 16)));
}
export const isV6 = (s: string) => s.includes(':');
export const addrb = (s: string) => (isV6(s) ? ip6b(s) : ipb(s));
export const macb = (s: string) => s.split(':').map((h) => parseInt(h, 16));
export const ascii = (s: string) => Array.from(new TextEncoder().encode(s));
export const hex = (n: number, w = 2) => '0x' + (n >>> 0).toString(16).padStart(w, '0');
export const zeros = (n: number) => new Array<number>(n).fill(0);
export const hexStr = (b: number[]) => b.map((x) => x.toString(16).padStart(2, '0')).join(' ');

/** Deterministic pseudo-random bytes, so keys and ciphertext look real but never change. */
export function rand(seed: string, n: number): number[] {
  let h = 2166136261;
  for (const c of seed) h = Math.imul(h ^ c.charCodeAt(0), 16777619);
  if (h === 0) h = 1;
  const out: number[] = [];
  for (let i = 0; i < n; i++) {
    h ^= h << 13;
    h ^= h >>> 17;
    h ^= h << 5;
    out.push(h & 255);
  }
  return out;
}

export class Writer {
  b: number[] = [];
  layers: Layer[] = [];
  private cur: Layer | null = null;

  get pos() {
    return this.b.length;
  }

  begin(key: LayerKey, name: string): Layer {
    this.cur = { key, name, summary: '', start: this.pos, len: 0, fields: [] };
    this.layers.push(this.cur);
    return this.cur;
  }

  end(summary?: string) {
    const c = this.cur;
    if (!c) return;
    c.len = this.pos - c.start;
    if (summary !== undefined) c.summary = summary;
    this.cur = null;
  }

  f(name: string, value: string | number, bytes: number[]): Field {
    const fld: Field = { name, value: String(value), start: this.pos, len: bytes.length };
    this.cur?.fields.push(fld);
    for (const x of bytes) this.b.push(x & 255);
    return fld;
  }

  put(at: number, bytes: number[]) {
    bytes.forEach((x, i) => (this.b[at + i] = x & 255));
  }
}

export function checksum(data: number[]): number {
  let s = 0;
  for (let i = 0; i < data.length; i += 2) s += (data[i] << 8) + (data[i + 1] ?? 0);
  while (s >>> 16) s = (s & 0xffff) + (s >>> 16);
  return ~s & 0xffff;
}

export type L4 =
  | {
      kind: 'tcp';
      sport: number;
      dport: number;
      seq: number;
      ack: number;
      flags: string;
      mss?: boolean;
      relSeq?: number;
      relAck?: number;
      window?: number;
    }
  | { kind: 'udp'; sport: number; dport: number }
  | { kind: 'icmp'; type: number; code: number; id?: number; seq?: number; data?: number[]; dataName?: string }
  /** No transport header: the app writer supplies everything after IP (ESP, IGMP, GRE…). */
  | { kind: 'raw'; proto: number; name: string };

export type AppWriter = (w: Writer) => void;

export interface FrameSpec {
  srcMac: string;
  dstMac: string;
  src: string;
  dst: string;
  ttl?: number;
  df?: boolean;
  l4: L4;
  app?: AppWriter;
}

const FLAGS: [string, number, string][] = [
  ['F', 1, 'FIN'],
  ['S', 2, 'SYN'],
  ['R', 4, 'RST'],
  ['P', 8, 'PSH'],
  ['A', 16, 'ACK'],
];

export const flagNames = (f: string) =>
  FLAGS.filter(([c]) => f.includes(c))
    .map(([, , n]) => n)
    .join(', ');

const ICMP_TYPES: Record<number, string> = {
  0: 'Echo reply',
  3: 'Destination unreachable',
  8: 'Echo request',
  11: 'Time exceeded',
};
const ICMP6_TYPES: Record<number, string> = {
  1: 'Destination unreachable',
  3: 'Time exceeded',
  128: 'Echo request',
  129: 'Echo reply',
  133: 'Router Solicitation',
  134: 'Router Advertisement',
  135: 'Neighbor Solicitation',
  136: 'Neighbor Advertisement',
};

/** Writes an Ethernet II header as its own layer. */
export function ethHeader(w: Writer, dstMac: string, srcMac: string, type: number, typeName: string) {
  w.begin('eth', 'Ethernet II');
  w.f('Destination MAC', dstMac === 'ff:ff:ff:ff:ff:ff' ? 'ff:ff:ff:ff:ff:ff (broadcast)' : dstMac, macb(dstMac));
  w.f('Source MAC', srcMac, macb(srcMac));
  w.f('EtherType', `${typeName} (${hex(type, 4)})`, u16(type));
  w.end(`${srcMac} → ${dstMac}`);
}

/**
 * A frame that is not Ethernet+IP (ARP, 802.11, EAPOL, PPPoE discovery…).
 * The writer callback adds every layer itself with w.begin()/w.f()/w.end().
 */
export function rawFrame(write: (w: Writer) => void): Frame {
  const w = new Writer();
  write(w);
  return { bytes: w.b, layers: w.layers, payloadLen: 0 };
}

export function frame(o: FrameSpec): Frame {
  const w = new Writer();
  const l4 = o.l4;
  const v6 = isV6(o.src);

  ethHeader(w, o.dstMac, o.srcMac, v6 ? 0x86dd : 0x0800, v6 ? 'IPv6' : 'IPv4');

  const proto =
    l4.kind === 'tcp' ? 6 : l4.kind === 'udp' ? 17 : l4.kind === 'icmp' ? (v6 ? 58 : 1) : l4.proto;
  const protoName = l4.kind === 'raw' ? l4.name : l4.kind === 'icmp' && v6 ? 'ICMPv6' : l4.kind.toUpperCase();
  const ttl = o.ttl ?? 64;
  const r = rand(o.src + o.dst + JSON.stringify(l4), 2);
  const id = (r[0] << 8) | r[1];
  const df = o.df ?? true;

  const ipStart = w.pos;
  let totF: Field;
  let ipCk: Field | null = null;
  if (v6) {
    w.begin('ip', 'Internet Protocol Version 6');
    w.f('Version · Traffic class · Flow label', '6 · 0x00 · 0x00000', [0x60, 0, 0, 0]);
    totF = w.f('Payload length', '', [0, 0]);
    w.f('Next header', `${protoName} (${proto})`, [proto]);
    w.f('Hop limit', ttl, [ttl]);
    w.f('Source address', o.src, ip6b(o.src));
    w.f('Destination address', o.dst, ip6b(o.dst));
    w.end(`${o.src} → ${o.dst} · Hop limit ${ttl}`);
  } else {
    w.begin('ip', 'Internet Protocol Version 4');
    w.f('Version · Header length', '4 · 20 bytes', [0x45]);
    w.f('Differentiated services', '0x00 (best effort)', [0]);
    totF = w.f('Total length', '', [0, 0]);
    w.f('Identification', hex(id, 4), u16(id));
    w.f('Flags · Fragment offset', df ? "Don't fragment · 0" : 'None · 0', u16(df ? 0x4000 : 0));
    w.f('Time to live', `${ttl} hops`, [ttl]);
    w.f('Protocol', `${protoName} (${proto})`, [proto]);
    ipCk = w.f('Header checksum', '', [0, 0]);
    w.f('Source address', o.src, ipb(o.src));
    w.f('Destination address', o.dst, ipb(o.dst));
    w.end(`${o.src} → ${o.dst} · TTL ${ttl}`);
  }
  const ipHdr = v6 ? 40 : 20;
  const TYPES = v6 ? ICMP6_TYPES : ICMP_TYPES;

  const l4Start = w.pos;
  let lenF: Field | null = null;
  let ckF!: Field;
  let l4Layer!: Layer;

  if (l4.kind === 'tcp') {
    l4Layer = w.begin('tcp', 'Transmission Control Protocol');
    const hasAck = l4.flags.includes('A');
    w.f('Source port', l4.sport, u16(l4.sport));
    w.f('Destination port', l4.dport, u16(l4.dport));
    w.f(
      'Sequence number',
      l4.relSeq !== undefined ? `${l4.relSeq} (raw ${l4.seq >>> 0})` : l4.seq >>> 0,
      u32(l4.seq),
    );
    w.f(
      'Acknowledgment number',
      hasAck ? (l4.relAck !== undefined ? `${l4.relAck} (raw ${l4.ack >>> 0})` : l4.ack >>> 0) : '0 (not used)',
      u32(hasAck ? l4.ack : 0),
    );
    const hdrLen = 20 + (l4.mss ? 4 : 0);
    let bits = 0;
    for (const [c, b] of FLAGS) if (l4.flags.includes(c)) bits |= b;
    w.f('Header length · Flags', `${hdrLen} bytes · ${flagNames(l4.flags)}`, u16(((hdrLen / 4) << 12) | bits));
    const win = l4.window ?? 64240;
    w.f('Window size', `${win} bytes`, u16(win));
    ckF = w.f('Checksum', '', [0, 0]);
    w.f('Urgent pointer', 0, [0, 0]);
    if (l4.mss) w.f('Option: Maximum segment size', '1460 bytes', [2, 4, ...u16(1460)]);
    w.end();
  } else if (l4.kind === 'udp') {
    l4Layer = w.begin('udp', 'User Datagram Protocol');
    w.f('Source port', l4.sport, u16(l4.sport));
    w.f('Destination port', l4.dport, u16(l4.dport));
    lenF = w.f('Length', '', [0, 0]);
    ckF = w.f('Checksum', '', [0, 0]);
    w.end();
  } else if (l4.kind === 'icmp') {
    l4Layer = w.begin('icmp', v6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol');
    w.f('Type', `${l4.type} (${TYPES[l4.type] ?? 'other'})`, [l4.type]);
    w.f('Code', l4.code === 0 && l4.type === (v6 ? 3 : 11) ? '0 (TTL expired in transit)' : l4.code, [l4.code]);
    ckF = w.f('Checksum', '', [0, 0]);
    const echo = v6 ? l4.type === 128 || l4.type === 129 : l4.type === 0 || l4.type === 8;
    if (echo) {
      w.f('Identifier', l4.id ?? 1, u16(l4.id ?? 1));
      w.f('Sequence number', l4.seq ?? 1, u16(l4.seq ?? 1));
    } else if (!(v6 && l4.type >= 133)) {
      w.f('Unused', '0', [0, 0, 0, 0]);
    }
    if (l4.data) w.f(l4.dataName ?? 'Data', `${l4.data.length} bytes`, l4.data);
    w.end();
  }

  const appStart = w.pos;
  o.app?.(w);
  const payloadLen = w.pos - appStart;

  const total = v6 ? w.pos - ipStart - ipHdr : w.pos - ipStart;
  w.put(totF.start, u16(total));
  totF.value = `${total} bytes`;
  if (ipCk) {
    const ihc = checksum(w.b.slice(ipStart, ipStart + 20));
    w.put(ipCk.start, u16(ihc));
    ipCk.value = hex(ihc, 4);
  }

  const l4Len = w.pos - l4Start;
  if (lenF) {
    w.put(lenF.start, u16(l4Len));
    lenF.value = `${l4Len} bytes`;
  }
  if (l4.kind !== 'raw') {
    const pseudo = v6
      ? [...ip6b(o.src), ...ip6b(o.dst), ...u32(l4Len), 0, 0, 0, proto]
      : [...ipb(o.src), ...ipb(o.dst), 0, proto, ...u16(l4Len)];
    const ck = l4.kind === 'icmp' && !v6 ? checksum(w.b.slice(l4Start)) : checksum([...pseudo, ...w.b.slice(l4Start)]);
    w.put(ckF.start, u16(ck));
    ckF.value = hex(ck, 4);
  }

  if (l4.kind === 'tcp')
    l4Layer.summary = `${l4.sport} → ${l4.dport} · [${flagNames(l4.flags)}] · Seq ${l4.relSeq ?? l4.seq} · Len ${payloadLen}`;
  else if (l4.kind === 'udp') l4Layer.summary = `${l4.sport} → ${l4.dport} · Len ${payloadLen}`;
  else if (l4.kind === 'icmp') l4Layer.summary = TYPES[l4.type] ?? `Type ${l4.type}`;

  return { bytes: w.b, layers: w.layers, payloadLen };
}
