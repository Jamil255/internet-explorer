// Helpers that keep lesson files short: addressing, packet factories and a
// TCP session that tracks sequence numbers for you.
import { flagNames, frame, hex, type AppWriter, type Frame, type L4 } from '@/engine/bytes';
import { dns } from '@/engine/protocols';
import { findPath } from '@/engine/graph';
import { NODE_INFO } from '@/engine/nodes';
import type { Lesson, NodeId, Packet, PacketColor } from '@/engine/types';

export const IP = (id: NodeId) => NODE_INFO[id]?.ip ?? '0.0.0.0';
export const MAC = {
  client: '3c:22:fb:7a:10:4e',
  router: 'a4:91:b1:0c:22:01',
  isp: '00:1b:21:9e:44:10',
  bcast: 'ff:ff:ff:ff:ff:ff',
};

export interface PacketSpec {
  from: NodeId;
  to: NodeId;
  color: PacketColor;
  label: string;
  proto: string;
  info?: string;
  lost?: boolean;
  /** Ethernet + IP + this transport. Omit when passing `raw`. */
  l4?: L4;
  app?: AppWriter;
  /** A ready-made frame (from rawFrame) for non-IP traffic such as ARP, 802.11 or PPPoE discovery. */
  raw?: Frame;
  src?: string;
  dst?: string;
  ttl?: number;
  srcMac?: string;
  dstMac?: string;
  df?: boolean;
}

export function packet(p: PacketSpec): Packet {
  const src = p.src ?? IP(p.from);
  const dst = p.dst ?? IP(p.to);
  const [sm, dm] =
    p.from === 'client'
      ? [MAC.client, MAC.router]
      : p.to === 'client'
        ? [MAC.router, MAC.client]
        : [MAC.isp, MAC.router];
  const ttl = p.ttl ?? (p.to === 'client' && p.from !== 'router' ? 57 : 64);
  if (!p.raw && !p.l4) throw new Error(`packet ${p.label}: needs l4 or raw`);
  const fr = p.raw ?? frame({ srcMac: p.srcMac ?? sm, dstMac: p.dstMac ?? dm, src, dst, ttl, df: p.df, l4: p.l4!, app: p.app });
  return {
    from: p.from,
    to: p.to,
    color: p.color,
    label: p.label,
    proto: p.proto,
    info: p.info ?? '',
    lost: p.lost,
    src,
    dst,
    frame: fr,
    len: fr.bytes.length,
    time: 0,
  };
}

export const udp = (p: Omit<PacketSpec, 'l4'> & { sport: number; dport: number }) =>
  packet({ ...p, l4: { kind: 'udp', sport: p.sport, dport: p.dport } });

/** A plain DNS A lookup between the laptop and its resolver. */
export function dnsPair(name = 'www.example.com', answer = '203.0.113.10', id = 0x3b1e, sport = 59321): Packet[] {
  return [
    udp({
      from: 'client',
      to: 'dns',
      sport,
      dport: 53,
      color: 'blue',
      label: 'DNS QUERY',
      proto: 'DNS',
      info: `Standard query ${hex(id, 4)} A ${name}`,
      app: dns({ id, rd: true, q: [name, 'A'] }),
    }),
    udp({
      from: 'dns',
      to: 'client',
      sport: 53,
      dport: sport,
      color: 'blue',
      label: 'DNS REPLY',
      proto: 'DNS',
      info: `Standard query response ${hex(id, 4)} A ${name} A ${answer}`,
      app: dns({
        id,
        response: true,
        rd: true,
        ra: true,
        q: [name, 'A'],
        an: [{ name, type: 'A', ttl: 3600, data: answer }],
      }),
    }),
  ];
}

interface SegOpts {
  label: string;
  color?: PacketColor;
  proto?: string;
  info?: string;
  app?: AppWriter;
  lost?: boolean;
  mss?: boolean;
}

/** A TCP connection between node a (client side) and node b. Call methods in time order. */
export function tcp(a: NodeId, b: NodeId, aPort: number, bPort: number) {
  const isn = { a: (0x6b1f0a20 + aPort * 7919) >>> 0, b: (0x2c9d4e71 + bPort * 104729) >>> 0 };
  const seq = { a: 0, b: 0 };

  const seg = (side: 'a' | 'b', flags: string, o: SegOpts): Packet => {
    const other = side === 'a' ? 'b' : 'a';
    const sport = side === 'a' ? aPort : bPort;
    const dport = side === 'a' ? bPort : aPort;
    const hasAck = flags.includes('A');
    const p = packet({
      from: side === 'a' ? a : b,
      to: side === 'a' ? b : a,
      color: o.color ?? 'green',
      label: o.label,
      proto: o.proto ?? 'TCP',
      lost: o.lost,
      app: o.app,
      l4: {
        kind: 'tcp',
        sport,
        dport,
        flags,
        mss: o.mss,
        seq: (isn[side] + seq[side]) >>> 0,
        ack: hasAck ? (isn[other] + seq[other]) >>> 0 : 0,
        relSeq: seq[side],
        relAck: hasAck ? seq[other] : undefined,
      },
    });
    const len = p.frame.payloadLen;
    p.info =
      o.info ??
      `${sport} → ${dport} [${flagNames(flags)}] Seq=${seq[side]}${hasAck ? ` Ack=${seq[other]}` : ''} Len=${len}`;
    if (!o.lost) seq[side] += len + (flags.includes('S') || flags.includes('F') ? 1 : 0);
    return p;
  };

  return {
    handshake: (): Packet[] => [
      seg('a', 'S', { label: 'SYN', mss: true }),
      seg('b', 'SA', { label: 'SYN-ACK', mss: true }),
      seg('a', 'A', { label: 'ACK' }),
    ],
    send: (side: 'a' | 'b', app: AppWriter, o: Omit<SegOpts, 'app'>) => seg(side, 'PA', { ...o, app }),
    ack: (side: 'a' | 'b', label = 'ACK') => seg(side, 'A', { label }),
    close: (): Packet[] => [
      seg('a', 'FA', { label: 'FIN' }),
      seg('b', 'FA', { label: 'FIN-ACK' }),
      seg('a', 'A', { label: 'ACK' }),
    ],
    seg,
  };
}

/** Fill in capture timestamps and counts. */
export function lesson(l: Omit<Lesson, 'packetCount'>): Lesson {
  let t = 0;
  let count = 0;
  for (const s of l.steps) {
    for (const p of s.packets ?? []) {
      p.time = t;
      t += 0.0015 + (findPath(l.links, p.from, p.to).length - 1) * 0.0042;
      count++;
    }
    t += 0.01;
  }
  return { ...l, packetCount: count };
}

/** Standard layout: laptop → router → internet → servers. */
export function webNodes(server: NodeId = 'web', withDns = true) {
  const nodes = [
    { id: 'client', x: 9, y: 62 },
    { id: 'router', x: 29, y: 62 },
    { id: 'internet', x: 51, y: 62 },
    ...(withDns ? [{ id: 'dns', x: 78, y: 24 }] : []),
    { id: server, x: 82, y: withDns ? 70 : 62 },
  ];
  const links: [NodeId, NodeId][] = [
    ['client', 'router'],
    ['router', 'internet'],
    ...(withDns ? ([['internet', 'dns']] as [NodeId, NodeId][]) : []),
    ['internet', server],
  ];
  return { nodes, links };
}
