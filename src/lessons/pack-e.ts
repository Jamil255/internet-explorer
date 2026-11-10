// Pack E: real-time media, telephony, streaming and industrial control.
// udp · webrtc · sip · rtsp · rtmp · modbus
import { ascii, checksum, hex, hexStr, ipb, macb, rand, u16, u24, u32, type AppWriter, type Writer } from '@/engine/bytes';
import { registerNodes } from '@/engine/nodes';
import { encrypted } from '@/engine/protocols';
import type { Lesson, Packet, PacketColor } from '@/engine/types';
import { MAC, lesson, tcp, udp } from './kit';

registerNodes({
  stun: { label: 'STUN server', icon: 'server', ip: '203.0.113.3' },
  peer: { label: 'Friend’s laptop', icon: 'laptop', ip: '198.51.100.77' },
  signal: { label: 'meet.example.com', icon: 'globe', ip: '203.0.113.60' },
  pbx: { label: 'SIP server (PBX)', icon: 'phone', ip: '203.0.113.70' },
  phone2: { label: 'Sara’s phone', icon: 'smartphone', ip: '198.51.100.42' },
  camera: { label: 'IP camera', icon: 'camera', ip: '192.168.1.64' },
  ingest: { label: 'live.example.com', icon: 'video', ip: '203.0.113.80' },
  otswitch: { label: 'Plant switch', icon: 'switch' },
  plc: { label: 'PLC', icon: 'factory', ip: '192.168.1.20' },
});

const PUBLIC_IP = '198.51.100.7'; // the home router's address on the internet

/* ================================================================ helpers */

/** Rewrite a frame for traffic that stays on the LAN: real MACs both ways and TTL 64. */
function onLan(p: Packet, macs: Record<string, string>): Packet {
  const b = p.frame.bytes;
  const eth = p.frame.layers[0];
  const setMac = (i: number, mac: string) => {
    const f = eth.fields[i];
    macb(mac).forEach((x, k) => (b[f.start + k] = x));
    f.value = mac;
  };
  setMac(0, macs[p.to]);
  setMac(1, macs[p.from]);
  eth.summary = `${macs[p.from]} → ${macs[p.to]}`;
  const ip = p.frame.layers.find((l) => l.key === 'ip');
  if (ip) {
    const o = ip.start;
    const ttlF = ip.fields.find((f) => f.name === 'Time to live')!;
    const ckF = ip.fields.find((f) => f.name === 'Header checksum')!;
    b[o + 8] = 64;
    ttlF.value = '64 hops';
    b[o + 10] = 0;
    b[o + 11] = 0;
    const ck = checksum(b.slice(o, o + 20));
    b[o + 10] = ck >> 8;
    b[o + 11] = ck & 255;
    ckF.value = hex(ck, 4);
    ip.summary = ip.summary.replace(/TTL \d+/, 'TTL 64');
  }
  return p;
}

/** A text message with headers and an optional body (SIP, RTSP). Content-Length is computed. */
function textMsg(name: string, start: string, headers: string[], body: string[] = [], bodyLabel = 'SDP'): AppWriter {
  return (w) => {
    const bodyBytes = body.reduce((n, l) => n + ascii(l + '\r\n').length, 0);
    const all = [...headers];
    if (body.length) all.push('Content-Type: application/sdp');
    all.push(`Content-Length: ${bodyBytes}`);
    w.begin('app', name);
    const isStatus = /^(SIP|RTSP)\/\d\.\d /.test(start);
    w.f(isStatus ? 'Status line' : 'Request line', start, ascii(start + '\r\n'));
    for (const h of all) w.f(h.split(':')[0], h.slice(h.indexOf(':') + 1).trim(), ascii(h + '\r\n'));
    w.f('End of headers', '\\r\\n', ascii('\r\n'));
    for (const l of body) w.f(`${bodyLabel} ${l.slice(0, 2)}`, l, ascii(l + '\r\n'));
    w.end(start);
  };
}

interface RtpOpts {
  pt: number;
  ptName: string;
  seq: number;
  ts: number;
  ssrc: number;
  marker?: boolean;
  len: number;
  what: string;
  seed: string;
  /** Extra payload-header fields written before the media bytes (e.g. H.264 FU-A). */
  pre?: [string, string, number[]][];
  /** SRTP: encrypt the payload and add a 10-byte auth tag. */
  srtp?: boolean;
}

function rtpFields(w: Writer, o: RtpOpts) {
  w.f('Version · Padding · Extension · CSRC count', '2 · no · no · 0', [0x80]);
  w.f('Marker · Payload type', `${o.marker ? 'set' : 'clear'} · ${o.ptName} (${o.pt})`, [(o.marker ? 0x80 : 0) | o.pt]);
  w.f('Sequence number', o.seq, u16(o.seq));
  w.f('Timestamp', o.ts, u32(o.ts));
  w.f('SSRC (stream ID)', hex(o.ssrc, 8), u32(o.ssrc));
  for (const [n, v, b] of o.pre ?? []) w.f(n, v, b);
  if (o.srtp) {
    w.f('Encrypted payload', `${o.len} bytes · ${o.what}`, rand(o.seed, o.len));
    w.f('Authentication tag', 'HMAC-SHA1-80 (10 bytes)', rand(o.seed + 'tag', 10));
  } else {
    w.f('Payload', `${o.len} bytes · ${o.what}`, rand(o.seed, o.len));
  }
}

function rtp(o: RtpOpts): AppWriter {
  return (w) => {
    w.begin('app', o.srtp ? 'Secure Real-time Transport Protocol' : 'Real-time Transport Protocol');
    rtpFields(w, o);
    w.end(`${o.ptName} · Seq ${o.seq} · TS ${o.ts}`);
  };
}

/* ---------- STUN ---------- */

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(b: number[]) {
  let c = 0xffffffff;
  for (const x of b) c = CRC_TABLE[(c ^ x) & 255] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const COOKIE = [0x21, 0x12, 0xa4, 0x42];
const attr = (type: number, body: number[]) => {
  const pad = (4 - (body.length % 4)) % 4;
  return [...u16(type), ...u16(body.length), ...body, ...new Array(pad).fill(0)];
};
const xorAddr = (ip: string, port: number) =>
  attr(0x0020, [0, 1, ...u16(port ^ 0x2112), ...ipb(ip).map((x, i) => x ^ COOKIE[i])]);

interface StunOpts {
  response: boolean;
  txid: string;
  mapped?: [string, number];
  ice?: { username: string; controlling: boolean };
}

function stun(o: StunOpts): AppWriter {
  return (w) => {
    const tid = rand('stun' + o.txid, 12);
    const attrs: [string, string, number[]][] = [];
    if (o.ice && !o.response) {
      attrs.push(['Attribute · USERNAME', o.ice.username, attr(0x0006, ascii(o.ice.username))]);
      attrs.push(['Attribute · PRIORITY', '1853817087 (host candidate)', attr(0x0024, u32(1853817087))]);
      attrs.push([
        `Attribute · ${o.ice.controlling ? 'ICE-CONTROLLING' : 'ICE-CONTROLLED'}`,
        'tie-breaker (8 random bytes)',
        attr(o.ice.controlling ? 0x802a : 0x8029, rand('tb' + o.txid, 8)),
      ]);
      attrs.push(['Attribute · USE-CANDIDATE', 'nominate this pair', attr(0x0025, [])]);
    }
    if (o.mapped)
      attrs.push([
        'Attribute · XOR-MAPPED-ADDRESS',
        `${o.mapped[0]}:${o.mapped[1]} (stored XOR-ed with the magic cookie)`,
        xorAddr(o.mapped[0], o.mapped[1]),
      ]);
    if (o.ice)
      attrs.push([
        'Attribute · MESSAGE-INTEGRITY',
        'HMAC-SHA1 keyed with the ICE password (20 bytes)',
        attr(0x0008, rand('mi' + o.txid, 20)),
      ]);
    const fpLen = o.ice ? 8 : 0;
    const bodyLen = attrs.reduce((n, a) => n + a[2].length, 0) + fpLen;
    const type = o.response ? 0x0101 : 0x0001;
    const header = [...u16(type), ...u16(bodyLen), ...COOKIE, ...tid];
    if (o.ice) {
      const crc = (crc32([...header, ...attrs.flatMap((a) => a[2])]) ^ 0x5354554e) >>> 0;
      attrs.push(['Attribute · FINGERPRINT', `CRC-32 ${hex(crc, 8)}`, attr(0x8028, u32(crc))]);
    }
    w.begin('app', 'Session Traversal Utilities for NAT');
    w.f('Message type', o.response ? 'Binding Success Response (0x0101)' : 'Binding Request (0x0001)', u16(type));
    w.f('Message length', `${bodyLen} bytes`, u16(bodyLen));
    w.f('Magic cookie', '0x2112a442', COOKIE);
    w.f('Transaction ID', hexStr(tid), tid);
    for (const [n, v, b] of attrs) w.f(n, v, b);
    w.end(o.response ? 'Binding Success Response' : 'Binding Request');
  };
}

/* ---------- DTLS ---------- */

interface DtlsRec {
  ct: 20 | 22 | 23;
  epoch: number;
  seq: number;
  hs?: { type: number; name: string; mseq: number };
  len: number;
  what: string;
}
const CT_NAMES = { 20: 'Change Cipher Spec', 22: 'Handshake', 23: 'Application Data' } as const;

function dtls(recs: DtlsRec[], seed: string, summary: string): AppWriter {
  return (w) => {
    w.begin('app', 'Datagram Transport Layer Security');
    recs.forEach((r, i) => {
      const n = `#${i + 1}`;
      const plainHs = r.hs && r.epoch === 0;
      const len = r.ct === 20 ? 1 : plainHs ? 12 + r.len : r.len;
      w.f(`Record ${n} · content type`, `${CT_NAMES[r.ct]} (${r.ct})`, [r.ct]);
      w.f(`Record ${n} · version`, 'DTLS 1.2 (0xfefd)', u16(0xfefd));
      w.f(`Record ${n} · epoch`, r.epoch === 0 ? '0 (not encrypted yet)' : `${r.epoch} (encrypted)`, u16(r.epoch));
      w.f(`Record ${n} · sequence number`, r.seq, [0, 0, ...u32(r.seq)]);
      w.f(`Record ${n} · length`, `${len} bytes`, u16(len));
      if (r.ct === 20) w.f('Change Cipher Spec', 'switch to the new keys', [1]);
      else if (plainHs && r.hs) {
        w.f('Handshake type', `${r.hs.name} (${r.hs.type})`, [r.hs.type]);
        w.f('Handshake length', `${r.len} bytes`, u24(r.len));
        w.f('Message sequence', r.hs.mseq, u16(r.hs.mseq));
        w.f('Fragment offset · length', `0 · ${r.len} (not fragmented)`, [...u24(0), ...u24(r.len)]);
        w.f(`${r.hs.name} body`, r.what, rand(seed + i, r.len));
      } else w.f('Encrypted data', r.what, rand(seed + i, r.len));
    });
    w.end(summary);
  };
}

/* ---------- RTMP / AMF0 ---------- */

const f64 = (n: number) => {
  const dv = new DataView(new ArrayBuffer(8));
  dv.setFloat64(0, n);
  return Array.from(new Uint8Array(dv.buffer));
};
const amfStr = (s: string) => [0x02, ...u16(ascii(s).length), ...ascii(s)];
const amfNum = (n: number) => [0x00, ...f64(n)];
const AMF_NULL = [0x05];
const amfObj = (o: Record<string, string | number>) => [
  0x03,
  ...Object.entries(o).flatMap(([k, v]) => [...u16(k.length), ...ascii(k), ...(typeof v === 'number' ? amfNum(v) : amfStr(v))]),
  0,
  0,
  9,
];
const RTMP_TYPES: Record<number, string> = {
  1: 'Set Chunk Size',
  5: 'Window Acknowledgement Size',
  6: 'Set Peer Bandwidth',
  8: 'Audio',
  9: 'Video',
  18: 'AMF0 Data',
  20: 'AMF0 Command',
};

interface RtmpMsg {
  csid: number;
  type: number;
  stream: number;
  ts?: number;
  body: number[];
  what: string;
}

function rtmpMsgs(msgs: RtmpMsg[], summary: string): AppWriter {
  return (w) => {
    w.begin('app', 'Real-Time Messaging Protocol');
    for (const m of msgs) {
      const t = RTMP_TYPES[m.type];
      w.f(`Chunk header · ${t}`, `fmt 0 · chunk stream ${m.csid}`, [m.csid & 0x3f]);
      w.f('Timestamp', `${m.ts ?? 0} ms`, u24(m.ts ?? 0));
      w.f('Message length', `${m.body.length} bytes`, u24(m.body.length));
      w.f('Message type', `${t} (${m.type})`, [m.type]);
      w.f('Message stream ID', m.stream, [m.stream & 255, (m.stream >> 8) & 255, (m.stream >> 16) & 255, (m.stream >>> 24) & 255]);
      w.f(m.type === 20 || m.type === 18 ? 'AMF0 body' : 'Body', m.what, m.body);
    }
    w.end(summary);
  };
}

/** Raw handshake bytes (C0/C1/S0/S1/S2/C2 pieces), one field per piece. */
function rtmpHs(pieces: [string, string, number[]][], summary: string): AppWriter {
  return (w) => {
    w.begin('app', 'RTMP Handshake');
    for (const [n, v, b] of pieces) w.f(n, v, b);
    w.end(summary);
  };
}

/* ---------- Modbus ---------- */

function modbus(txn: number, pdu: [string, string, number[]][], summary: string): AppWriter {
  return (w) => {
    const len = 1 + pdu.reduce((n, f) => n + f[2].length, 0);
    w.begin('app', 'Modbus/TCP');
    w.f('Transaction ID', txn, u16(txn));
    w.f('Protocol ID', '0 (Modbus)', u16(0));
    w.f('Length', `${len} bytes follow`, u16(len));
    w.f('Unit ID', 1, [1]);
    for (const [n, v, b] of pdu) w.f(n, v, b);
    w.end(summary);
  };
}

/* ================================================================ UDP */

function buildUdp(): Lesson {
  const ME = 0x5a3c91e2;
  const THEM = 0x1f6b0d44;
  const voice = (from: 'client' | 'peer', seq: number, lost = false): Packet => {
    const mine = from === 'client';
    const base = mine ? 21000 : 8000;
    const ts = (mine ? 160000 : 990000) + (seq - base) * 960;
    return udp({
      from,
      to: mine ? 'peer' : 'client',
      sport: mine ? 49170 : 50010,
      dport: mine ? 50010 : 49170,
      dst: mine ? undefined : '192.168.1.10',
      color: mine ? 'blue' : 'violet',
      label: lost ? 'VOICE' : `VOICE #${seq - base + 1}`,
      proto: 'RTP',
      lost,
      info: `PT=opus, SSRC=${hex(mine ? ME : THEM, 8)}, Seq=${seq}, Time=${ts}`,
      app: rtp({ pt: 111, ptName: 'Opus', seq, ts, ssrc: mine ? ME : THEM, len: 92, what: '20 ms of compressed voice', seed: `v${from}${seq}` }),
    });
  };

  return lesson({
    id: 'udp',
    name: 'UDP',
    title: 'Fast datagrams',
    layer: 4,
    tagline: 'No handshake, no retries — perfect for a live voice call.',
    nodes: [
      { id: 'client', x: 9, y: 58 },
      { id: 'router', x: 31, y: 58 },
      { id: 'internet', x: 55, y: 58 },
      { id: 'peer', x: 84, y: 58 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
      ['internet', 'peer'],
    ],
    legend: [
      ['blue', 'Your voice'],
      ['violet', 'Their voice'],
    ],
    overview: {
      full: 'User Datagram Protocol',
      description:
        'UDP puts just four fields on top of IP — source port, destination port, length and checksum — 8 bytes in total. There is no connection to set up, no acknowledgement and no retransmission. For a voice call that is exactly right: a sound that arrives late is useless, so it is better to keep going than to wait for a resend.',
      facts: [
        ['Layer', 'Transport (4)'],
        ['Header', '8 bytes'],
        ['Connection', 'None'],
        ['Delivery', 'Best effort — may be lost or reordered'],
        ['Used by', 'Voice, video, games, DNS, QUIC'],
        ['Spec', 'RFC 768'],
      ],
    },
    steps: [
      {
        title: 'Send right away',
        desc: 'The first datagram needs no setup',
        detail:
          'The call app has your friend’s address and port from call setup. The moment you speak it wraps 20 ms of Opus audio in an RTP header and hands it to UDP, which adds its 8-byte header and sends it. Compare with TCP, which would need a full round trip of SYN / SYN-ACK / ACK first.',
        facts: [
          ['UDP header', '8 bytes'],
          ['RTP header', '12 bytes'],
          ['Audio per packet', '20 ms'],
        ],
        packets: [voice('client', 21000)],
      },
      {
        title: 'A stream of datagrams',
        desc: 'Fifty packets every second',
        detail:
          'Every 20 ms another datagram leaves. Each is independent — UDP does not number them. The RTP header inside does: the sequence number goes up by one and the timestamp by 960 (20 ms at 48 kHz), so the receiver can put them back in order and play them at the right moment.',
        facts: [
          ['Rate', '50 packets/s'],
          ['Seq step', '+1'],
          ['Timestamp step', '+960'],
        ],
        packets: [voice('client', 21001), voice('client', 21002), voice('client', 21003)],
      },
      {
        title: 'Lost on the way',
        desc: 'A congested link drops one',
        detail:
          'Datagram 21004 is dropped by a busy router. Nobody tells the sender, and UDP has no timer that would send it again. The next datagram simply follows 20 ms later.',
        packets: [voice('client', 21004, true), voice('client', 21005)],
      },
      {
        title: 'Replies come back',
        desc: 'The other direction is its own stream',
        detail:
          'Your friend’s app sends its own datagrams the other way, with its own SSRC (stream ID) and sequence numbers. There is no “connection” tying the two directions together — just two flows of packets between the same pair of ports.',
        facts: [['Their SSRC', hex(THEM, 8)]],
        packets: [voice('peer', 8000), voice('peer', 8001), voice('peer', 8002)],
      },
      {
        title: 'The app decides',
        desc: 'Jitter buffer and loss concealment',
        detail:
          'On the receiving side the app holds packets for a few tens of milliseconds in a jitter buffer to smooth out uneven arrival. When it sees the gap at sequence 21004 it doesn’t wait: the Opus decoder fills the missing 20 ms with a guess based on the sound around it. You hear, at worst, a tiny blip.',
        facts: [
          ['Gap detected by', 'RTP sequence number'],
          ['Repair', 'Packet loss concealment'],
          ['Waiting for a resend', 'Never'],
        ],
        packets: [voice('client', 21006)],
      },
    ],
    outro: {
      title: 'Call keeps flowing',
      text: 'UDP delivered voice with almost no overhead and no delay for setup. When one datagram vanished, the application — not the transport — decided that carrying on was better than waiting.',
      facts: [
        ['Datagrams lost', '1'],
        ['Audio missing', '20 ms, concealed'],
      ],
    },
  });
}

/* ================================================================ WebRTC */

function buildWebrtc(): Lesson {
  const sigA = tcp('client', 'signal', 51720, 443);
  const sigB = tcp('peer', 'signal', 60412, 443);
  const offerUp = sigA.send('a', encrypted(1180, 'WebSocket message: SDP offer (codecs, ICE ufrag/pwd, DTLS fingerprint)', 'offer1'), {
    label: 'SDP OFFER',
    proto: 'TLSv1.3',
    info: 'Application Data (WebSocket: SDP offer)',
    color: 'amber',
  });
  const offerDown = sigB.send('b', encrypted(1180, 'WebSocket message: the forwarded SDP offer', 'offer2'), {
    label: 'SDP OFFER',
    proto: 'TLSv1.3',
    info: 'Application Data (WebSocket: SDP offer)',
    color: 'amber',
  });
  const answerUp = sigB.send('a', encrypted(1020, 'WebSocket message: SDP answer', 'ans1'), {
    label: 'SDP ANSWER',
    proto: 'TLSv1.3',
    info: 'Application Data (WebSocket: SDP answer)',
    color: 'violet',
  });
  const answerDown = sigA.send('b', encrypted(1020, 'WebSocket message: the forwarded SDP answer', 'ans2'), {
    label: 'SDP ANSWER',
    proto: 'TLSv1.3',
    info: 'Application Data (WebSocket: SDP answer)',
    color: 'violet',
  });

  const LPORT = 54321;
  const PPORT = 61000;
  const stunReq = udp({
    from: 'client', to: 'stun', sport: LPORT, dport: 3478, color: 'blue', label: 'BINDING?', proto: 'STUN',
    info: 'Binding Request', app: stun({ response: false, txid: 's1' }),
  });
  const stunRes = udp({
    from: 'stun', to: 'client', sport: 3478, dport: LPORT, color: 'blue', label: 'YOU ARE…', proto: 'STUN',
    info: `Binding Success Response XOR-MAPPED-ADDRESS: ${PUBLIC_IP}:40123`,
    app: stun({ response: true, txid: 's1', mapped: [PUBLIC_IP, 40123] }),
  });

  const ufrag = 'Fq3d:Kp9z';
  const check = udp({
    from: 'client', to: 'peer', sport: LPORT, dport: PPORT, color: 'teal', label: 'ICE CHECK', proto: 'STUN',
    info: `Binding Request user: ${ufrag}`, app: stun({ response: false, txid: 'ice1', ice: { username: ufrag, controlling: true } }),
  });
  const checkOk = udp({
    from: 'peer', to: 'client', sport: PPORT, dport: LPORT, dst: '192.168.1.10', color: 'teal', label: 'ICE OK', proto: 'STUN',
    info: `Binding Success Response XOR-MAPPED-ADDRESS: ${PUBLIC_IP}:40123`,
    app: stun({ response: true, txid: 'ice1', mapped: [PUBLIC_IP, 40123], ice: { username: ufrag, controlling: true } }),
  });

  const d = (from: 'client' | 'peer', recs: DtlsRec[], label: string, info: string, seed: string, color: PacketColor = 'pink') =>
    udp({
      from, to: from === 'client' ? 'peer' : 'client',
      sport: from === 'client' ? LPORT : PPORT, dport: from === 'client' ? PPORT : LPORT,
      dst: from === 'client' ? undefined : '192.168.1.10',
      color, label, proto: 'DTLSv1.2', info, app: dtls(recs, seed, info),
    });
  const ch = d('client', [{ ct: 22, epoch: 0, seq: 0, hs: { type: 1, name: 'Client Hello', mseq: 0 }, len: 158, what: 'random, cipher suites, use_srtp extension' }], 'CLIENT HELLO', 'Client Hello', 'dch');
  const sf = d(
    'peer',
    [
      { ct: 22, epoch: 0, seq: 0, hs: { type: 2, name: 'Server Hello', mseq: 0 }, len: 98, what: 'chosen cipher + SRTP profile' },
      { ct: 22, epoch: 0, seq: 1, hs: { type: 11, name: 'Certificate', mseq: 1 }, len: 412, what: 'self-signed certificate — its hash must match the SDP fingerprint' },
      { ct: 22, epoch: 0, seq: 2, hs: { type: 12, name: 'Server Key Exchange', mseq: 2 }, len: 110, what: 'ECDHE public key + signature' },
      { ct: 22, epoch: 0, seq: 3, hs: { type: 13, name: 'Certificate Request', mseq: 3 }, len: 24, what: 'please prove who you are too' },
      { ct: 22, epoch: 0, seq: 4, hs: { type: 14, name: 'Server Hello Done', mseq: 4 }, len: 0, what: 'empty' },
    ],
    'SERVER FLIGHT',
    'Server Hello, Certificate, Server Key Exchange, Certificate Request, Server Hello Done',
    'dsf',
  );
  const cf = d(
    'client',
    [
      { ct: 22, epoch: 0, seq: 1, hs: { type: 11, name: 'Certificate', mseq: 1 }, len: 404, what: 'the laptop’s own self-signed certificate' },
      { ct: 22, epoch: 0, seq: 2, hs: { type: 16, name: 'Client Key Exchange', mseq: 2 }, len: 33, what: 'ECDHE public key' },
      { ct: 22, epoch: 0, seq: 3, hs: { type: 15, name: 'Certificate Verify', mseq: 3 }, len: 74, what: 'signature proving it owns the certificate' },
      { ct: 20, epoch: 0, seq: 4, len: 1, what: '' },
      { ct: 22, epoch: 1, seq: 0, len: 40, what: 'Finished (encrypted)' },
    ],
    'CLIENT FLIGHT',
    'Certificate, Client Key Exchange, Certificate Verify, Change Cipher Spec, Finished',
    'dcf',
  );
  const sfin = d(
    'peer',
    [
      { ct: 20, epoch: 0, seq: 5, len: 1, what: '' },
      { ct: 22, epoch: 1, seq: 0, len: 40, what: 'Finished (encrypted)' },
    ],
    'FINISHED',
    'Change Cipher Spec, Finished',
    'dsfin',
  );

  const media = (from: 'client' | 'peer', kind: 'audio' | 'video', seq: number) => {
    const mine = from === 'client';
    const video = kind === 'video';
    return udp({
      from, to: mine ? 'peer' : 'client',
      sport: mine ? LPORT : PPORT, dport: mine ? PPORT : LPORT, dst: mine ? undefined : '192.168.1.10',
      color: video ? 'violet' : 'green', label: video ? 'SRTP VIDEO' : 'SRTP AUDIO', proto: 'SRTP',
      info: `PT=${video ? 'VP8' : 'opus'}, Seq=${seq}${video ? ' (encrypted video)' : ' (encrypted voice)'}`,
      app: rtp({
        pt: video ? 96 : 111, ptName: video ? 'VP8' : 'Opus', seq, ts: seq * (video ? 3000 : 960),
        ssrc: mine ? (video ? 0x7b11c0de : 0x7b11a0d1) : video ? 0x3e9f2c10 : 0x3e9f2a01,
        marker: video, len: video ? 980 : 88, what: video ? 'part of a video frame' : '20 ms of voice',
        seed: `m${from}${kind}${seq}`, srtp: true,
      }),
    });
  };

  return lesson({
    id: 'webrtc',
    name: 'WebRTC',
    title: 'A video call',
    layer: 7,
    tagline: 'Browsers find a direct path to each other and stream encrypted media.',
    nodes: [
      { id: 'client', x: 8, y: 60 },
      { id: 'router', x: 27, y: 60 },
      { id: 'internet', x: 49, y: 60 },
      { id: 'signal', x: 76, y: 18 },
      { id: 'stun', x: 86, y: 47 },
      { id: 'peer', x: 78, y: 82 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
      ['internet', 'signal'],
      ['internet', 'stun'],
      ['internet', 'peer'],
    ],
    legend: [
      ['amber', 'Offer'],
      ['violet', 'Answer / video'],
      ['blue', 'STUN'],
      ['teal', 'ICE check'],
      ['pink', 'DTLS'],
      ['green', 'Audio'],
    ],
    overview: {
      full: 'Web Real-Time Communication',
      description:
        'WebRTC lets two browsers send audio and video straight to each other. A web server only helps them exchange a description of the call (SDP). Each side then asks a STUN server what its public address looks like, ICE tests which path between them works, DTLS agrees on keys, and the media flows as SRTP — encrypted RTP over UDP.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Media', 'SRTP over UDP'],
        ['NAT traversal', 'STUN, ICE (TURN as fallback)'],
        ['Keys', 'DTLS-SRTP'],
        ['Signalling', 'Not defined — any channel'],
        ['Spec', 'RFC 8825 family, W3C WebRTC'],
      ],
    },
    steps: [
      {
        title: 'Offer and answer',
        desc: 'Swap call descriptions via the website',
        detail:
          'The two browsers can’t reach each other yet, so they talk through the meeting site’s WebSocket. Your browser sends an SDP offer listing its codecs, a short ICE username/password and the fingerprint of its DTLS certificate; your friend’s browser replies with an answer. The site just passes the messages on — and it’s all inside TLS.',
        facts: [
          ['Carried over', 'WebSocket over TLS'],
          ['SDP contains', 'codecs, ICE creds, cert fingerprint'],
        ],
        packets: [offerUp, offerDown, answerUp, answerDown],
      },
      {
        title: 'Ask STUN: who am I?',
        desc: 'Learn the public address',
        detail:
          'The laptop only knows its private address 192.168.1.10. It sends a tiny STUN Binding Request to a public STUN server, which replies with the address and port it saw the packet come from — the router’s public side. The answer is XOR-ed with the magic cookie 0x2112A442 so that NAT boxes don’t “helpfully” rewrite it.',
        facts: [
          ['Port', 'UDP 3478'],
          ['Private', '192.168.1.10:54321'],
          ['Public (seen)', `${PUBLIC_IP}:40123`],
        ],
        packets: [stunReq, stunRes],
      },
      {
        title: 'ICE connectivity check',
        desc: 'Does the direct path work?',
        detail:
          'Each side has collected candidate addresses and shared them through signalling. ICE now pairs them up and tests each pair with a STUN Binding Request sent straight to the other browser, signed with the ICE password and protected by a CRC fingerprint. A successful response means packets can flow directly — no server in the middle.',
        facts: [
          ['Check signed with', 'HMAC-SHA1 (ICE password)'],
          ['Role', 'ICE-CONTROLLING (the offerer)'],
          ['Fallback if blocked', 'TURN relay'],
        ],
        packets: [check, checkOk],
      },
      {
        title: 'DTLS handshake',
        desc: 'TLS, but for datagrams',
        detail:
          'Over the path ICE just proved, the browsers run DTLS — TLS adapted to UDP, with record sequence numbers and its own retransmission timers. Both sides present self-signed certificates; each browser checks that the certificate’s hash matches the fingerprint it received in the SDP. That ties the encryption to the signalling.',
        facts: [
          ['Version', 'DTLS 1.2'],
          ['Auth', 'Cert fingerprint from SDP'],
          ['Extension', 'use_srtp'],
        ],
        packets: [ch, sf, cf, sfin],
      },
      {
        title: 'Encrypted media',
        desc: 'SRTP both ways',
        detail:
          'Keys exported from DTLS now encrypt every RTP packet. The 12-byte RTP header stays readable (it’s needed for ordering and timing), but the audio and video payloads are ciphertext followed by a 10-byte authentication tag that detects tampering.',
        facts: [
          ['Audio', 'Opus, 20 ms packets'],
          ['Video', 'VP8'],
          ['Integrity', '80-bit HMAC tag'],
        ],
        packets: [media('client', 'audio', 1), media('client', 'video', 1), media('peer', 'audio', 1), media('peer', 'video', 1)],
      },
    ],
    outro: {
      title: 'Face to face',
      text: 'The website only carried two descriptions. STUN found the public address, ICE proved a direct path, DTLS agreed keys tied to those descriptions, and now voice and video stream peer to peer, encrypted end to end.',
      facts: [
        ['Media path', 'Direct, peer to peer'],
        ['Encryption', 'DTLS-SRTP'],
      ],
    },
  });
}

/* ================================================================ SIP */

function buildSip(): Lesson {
  const ME = '192.168.1.10';
  const PBX = '203.0.113.70';
  const SARA = '198.51.100.42';
  const sipPkt = (from: string, to: string, label: string, color: PacketColor, start: string, headers: string[], sdp: string[] = []) =>
    udp({
      from, to, sport: 5060, dport: 5060, color, label, proto: 'SIP' + (sdp.length ? '/SDP' : ''),
      info: start.startsWith('SIP/2.0') ? `Status: ${start.slice(8)}` : `Request: ${start}`,
      app: textMsg('Session Initiation Protocol', start, headers, sdp),
    });

  const regBase = (cseq: number, extra: string[] = []) => [
    `Via: SIP/2.0/UDP ${ME}:5060;branch=z9hG4bK-reg${cseq};rport`,
    'Max-Forwards: 70',
    'From: <sip:amir@example.net>;tag=8f3a21',
    'To: <sip:amir@example.net>',
    'Call-ID: reg-7f2c0b91@192.168.1.10',
    `CSeq: ${cseq} REGISTER`,
    `Contact: <sip:amir@${ME}:5060>`,
    ...extra,
    'Expires: 3600',
  ];
  const reg1 = sipPkt('client', 'pbx', 'REGISTER', 'amber', 'REGISTER sip:example.net SIP/2.0', regBase(1));
  const r401 = sipPkt('pbx', 'client', '401', 'red', 'SIP/2.0 401 Unauthorized', [
    `Via: SIP/2.0/UDP ${ME}:5060;branch=z9hG4bK-reg1;received=${PUBLIC_IP};rport=5060`,
    'From: <sip:amir@example.net>;tag=8f3a21',
    'To: <sip:amir@example.net>;tag=pbx-2210',
    'Call-ID: reg-7f2c0b91@192.168.1.10',
    'CSeq: 1 REGISTER',
    'WWW-Authenticate: Digest realm="example.net", nonce="5f1c9a7e0b", algorithm=MD5',
  ]);
  const reg2 = sipPkt(
    'client', 'pbx', 'REGISTER', 'amber', 'REGISTER sip:example.net SIP/2.0',
    regBase(2, [
      'Authorization: Digest username="amir", realm="example.net", nonce="5f1c9a7e0b", uri="sip:example.net", response="6629fae49393a05397450978507c4ef1", algorithm=MD5',
    ]),
  );
  const r200reg = sipPkt('pbx', 'client', '200 OK', 'violet', 'SIP/2.0 200 OK', [
    `Via: SIP/2.0/UDP ${ME}:5060;branch=z9hG4bK-reg2;received=${PUBLIC_IP};rport=5060`,
    'From: <sip:amir@example.net>;tag=8f3a21',
    'To: <sip:amir@example.net>;tag=pbx-2210',
    'Call-ID: reg-7f2c0b91@192.168.1.10',
    'CSeq: 2 REGISTER',
    `Contact: <sip:amir@${ME}:5060>;expires=3600`,
  ]);

  const callId = 'Call-ID: a84b4c76e66710@192.168.1.10';
  const from = 'From: "Amir" <sip:amir@example.net>;tag=1928301774';
  const toNo = 'To: <sip:sara@example.net>';
  const toTag = 'To: <sip:sara@example.net>;tag=a6c85cf';
  const viaMe = `Via: SIP/2.0/UDP ${ME}:5060;branch=z9hG4bK776asdhds;rport`;
  const viaPbx = `Via: SIP/2.0/UDP ${PBX}:5060;branch=z9hG4bK-pbx-91`;
  const myOffer = [
    'v=0',
    `o=amir 2890844526 2890844526 IN IP4 ${ME}`,
    's=Call',
    `c=IN IP4 ${ME}`,
    't=0 0',
    'm=audio 49170 RTP/AVP 0 8 101',
    'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:8 PCMA/8000',
    'a=rtpmap:101 telephone-event/8000',
  ];
  const saraAnswer = [
    'v=0',
    `o=sara 5520371 5520371 IN IP4 ${SARA}`,
    's=Call',
    `c=IN IP4 ${SARA}`,
    't=0 0',
    'm=audio 40000 RTP/AVP 0',
    'a=rtpmap:0 PCMU/8000',
  ];
  const inviteHdr = (vias: string[]) => [
    ...vias,
    'Max-Forwards: 70',
    from,
    toNo,
    callId,
    'CSeq: 1 INVITE',
    `Contact: <sip:amir@${ME}:5060>`,
  ];
  const inv1 = sipPkt('client', 'pbx', 'INVITE', 'amber', 'INVITE sip:sara@example.net SIP/2.0', inviteHdr([viaMe]), myOffer);
  const trying = sipPkt('pbx', 'client', '100 TRYING', 'slate', 'SIP/2.0 100 Trying', [viaMe, from, toNo, callId, 'CSeq: 1 INVITE']);
  const inv2 = sipPkt(
    'pbx', 'phone2', 'INVITE', 'amber', 'INVITE sip:sara@198.51.100.42:5060 SIP/2.0',
    [
      viaPbx,
      `${viaMe};received=${PUBLIC_IP}`,
      `Record-Route: <sip:${PBX};lr>`,
      'Max-Forwards: 69',
      from,
      toNo,
      callId,
      'CSeq: 1 INVITE',
      `Contact: <sip:amir@${ME}:5060>`,
    ],
    myOffer,
  );
  const ringHdr = (vias: string[]) => [...vias, from, toTag, callId, 'CSeq: 1 INVITE', `Contact: <sip:sara@${SARA}:5060>`];
  const ring1 = sipPkt('phone2', 'pbx', '180 RINGING', 'violet', 'SIP/2.0 180 Ringing', ringHdr([viaPbx, viaMe]));
  const ring2 = sipPkt('pbx', 'client', '180 RINGING', 'violet', 'SIP/2.0 180 Ringing', ringHdr([viaMe]));
  const ok1 = sipPkt('phone2', 'pbx', '200 OK', 'violet', 'SIP/2.0 200 OK', [...ringHdr([viaPbx, viaMe]), `Record-Route: <sip:${PBX};lr>`], saraAnswer);
  const ok2 = sipPkt('pbx', 'client', '200 OK', 'violet', 'SIP/2.0 200 OK', [...ringHdr([viaMe]), `Record-Route: <sip:${PBX};lr>`], saraAnswer);
  const ackHdr = (vias: string[]) => [...vias, 'Max-Forwards: 70', `Route: <sip:${PBX};lr>`, from, toTag, callId, 'CSeq: 1 ACK'];
  const ack1 = sipPkt('client', 'pbx', 'ACK', 'amber', 'ACK sip:sara@198.51.100.42:5060 SIP/2.0', ackHdr([`Via: SIP/2.0/UDP ${ME}:5060;branch=z9hG4bKack1;rport`]));
  const ack2 = sipPkt('pbx', 'phone2', 'ACK', 'amber', 'ACK sip:sara@198.51.100.42:5060 SIP/2.0', ackHdr([viaPbx, `Via: SIP/2.0/UDP ${ME}:5060;branch=z9hG4bKack1;rport`]));

  const voice = (mine: boolean, seq: number) =>
    udp({
      from: mine ? 'client' : 'phone2', to: mine ? 'phone2' : 'client',
      sport: mine ? 49170 : 40000, dport: mine ? 40000 : 49170, dst: mine ? undefined : ME,
      color: 'green', label: 'RTP', proto: 'RTP',
      info: `PT=ITU-T G.711 PCMU, Seq=${seq}, Time=${seq * 160}`,
      app: rtp({ pt: 0, ptName: 'PCMU (G.711 µ-law)', seq, ts: seq * 160, ssrc: mine ? 0x2a7c11f0 : 0x6d0e43b2, len: 160, what: '20 ms of 8 kHz audio', seed: `sip${mine}${seq}` }),
    });

  const byeHdr = (vias: string[]) => [...vias, 'Max-Forwards: 70', `Route: <sip:${PBX};lr>`, from, toTag, callId, 'CSeq: 2 BYE'];
  const bye1 = sipPkt('client', 'pbx', 'BYE', 'amber', 'BYE sip:sara@198.51.100.42:5060 SIP/2.0', byeHdr([`Via: SIP/2.0/UDP ${ME}:5060;branch=z9hG4bKbye1;rport`]));
  const bye2 = sipPkt('pbx', 'phone2', 'BYE', 'amber', 'BYE sip:sara@198.51.100.42:5060 SIP/2.0', byeHdr([viaPbx, `Via: SIP/2.0/UDP ${ME}:5060;branch=z9hG4bKbye1;rport`]));
  const okBye1 = sipPkt('phone2', 'pbx', '200 OK', 'violet', 'SIP/2.0 200 OK', [viaPbx, `Via: SIP/2.0/UDP ${ME}:5060;branch=z9hG4bKbye1;rport`, from, toTag, callId, 'CSeq: 2 BYE']);
  const okBye2 = sipPkt('pbx', 'client', '200 OK', 'violet', 'SIP/2.0 200 OK', [`Via: SIP/2.0/UDP ${ME}:5060;branch=z9hG4bKbye1;rport`, from, toTag, callId, 'CSeq: 2 BYE']);

  return lesson({
    id: 'sip',
    name: 'SIP',
    title: 'Internet phone calls',
    layer: 7,
    tagline: 'Register, ring, answer — then the voice goes straight across.',
    nodes: [
      { id: 'client', x: 8, y: 58, label: 'Your softphone' },
      { id: 'router', x: 27, y: 58 },
      { id: 'internet', x: 49, y: 58 },
      { id: 'pbx', x: 78, y: 22 },
      { id: 'phone2', x: 84, y: 74 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
      ['internet', 'pbx'],
      ['internet', 'phone2'],
    ],
    legend: [
      ['amber', 'Request'],
      ['violet', 'Response'],
      ['slate', 'Provisional'],
      ['red', 'Challenge'],
      ['green', 'Voice (RTP)'],
    ],
    overview: {
      full: 'Session Initiation Protocol',
      description:
        'SIP sets up, changes and ends calls. It looks a lot like HTTP — text requests such as INVITE and BYE, and numbered responses such as 180 Ringing and 200 OK — and carries an SDP body describing the audio. SIP only does the signalling: once both phones agree, the voice itself travels separately as RTP.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', '5060 (UDP or TCP), 5061 TLS'],
        ['Methods', 'REGISTER, INVITE, ACK, BYE, CANCEL'],
        ['Media', 'RTP, described by SDP'],
        ['Spec', 'RFC 3261'],
      ],
    },
    steps: [
      {
        title: 'Register',
        desc: '“Here’s where to reach me”',
        detail:
          'When the softphone starts it sends REGISTER to the SIP server so that calls for amir@example.net can find it. The server doesn’t know who is asking yet, so it answers 401 Unauthorized with a Digest challenge: a realm and a one-time nonce. The server also notes the public address the packet really came from (received / rport) — that’s how it reaches phones behind NAT.',
        facts: [
          ['Challenge', 'Digest, MD5'],
          ['Nonce', '5f1c9a7e0b'],
        ],
        packets: [reg1, r401],
      },
      {
        title: 'Prove it',
        desc: 'Digest response, then 200 OK',
        detail:
          'The phone repeats REGISTER with an Authorization header. The response value is a hash of the username, password, realm and nonce — the password itself never crosses the network. The server checks the hash and accepts the registration for an hour.',
        facts: [['Registered for', '3600 s']],
        packets: [reg2, r200reg],
      },
      {
        title: 'INVITE',
        desc: 'Call sara@example.net',
        detail:
          'You dial Sara. INVITE carries an SDP offer: “send audio to 192.168.1.10 port 49170, I can do PCMU, PCMA or DTMF tones.” The server replies 100 Trying straight away so the phone stops retransmitting, looks up where Sara is registered and forwards the INVITE, adding its own Via and a Record-Route so later requests go through it too.',
        facts: [
          ['Codecs offered', 'PCMU, PCMA'],
          ['Media port', '49170'],
        ],
        packets: [inv1, trying, inv2],
      },
      {
        title: 'Ringing',
        desc: '180 travels back hop by hop',
        detail:
          'Sara’s phone starts ringing and sends 180 Ringing. Responses follow the Via headers back the way the request came: phone → server → you. Your softphone plays the ringback tone.',
        packets: [ring1, ring2],
      },
      {
        title: 'Answer and ACK',
        desc: '200 OK with the SDP answer',
        detail:
          'Sara picks up. Her 200 OK contains her SDP answer: “send audio to 198.51.100.42 port 40000, PCMU.” Your phone confirms with ACK — the only request that gets no response. This three-way INVITE / 200 / ACK exchange completes the call setup.',
        facts: [
          ['Agreed codec', 'PCMU (G.711)'],
          ['Her media port', '40000'],
        ],
        packets: [ok1, ok2, ack1, ack2],
      },
      {
        title: 'Talk',
        desc: 'RTP goes directly between phones',
        detail:
          'The voice does not pass through the SIP server. Each phone sends RTP datagrams straight to the address in the other’s SDP: 160 bytes of 8 kHz audio every 20 ms, with sequence numbers and timestamps for ordering and timing.',
        facts: [
          ['Packet size', '160 B payload'],
          ['Every', '20 ms'],
        ],
        packets: [voice(true, 1), voice(false, 1), voice(true, 2), voice(false, 2)],
      },
      {
        title: 'Hang up',
        desc: 'BYE and 200 OK',
        detail: 'You hang up. BYE follows the recorded route through the server to Sara’s phone, which answers 200 OK. Both phones stop sending RTP.',
        packets: [bye1, bye2, okBye1, okBye2],
      },
    ],
    outro: {
      title: 'Call completed',
      text: 'SIP did the talking-about-talking: who you are, where Sara is, which codec to use and when to stop. The conversation itself went straight between the phones as RTP.',
      facts: [
        ['Signalling', 'via the SIP server'],
        ['Voice', 'peer to peer'],
      ],
    },
  });
}

/* ================================================================ RTSP */

function buildRtsp(): Lesson {
  const CAM = '192.168.1.64';
  const URL = `rtsp://${CAM}:554/stream1`;
  const macs = { client: MAC.client, camera: 'bc:ad:28:4f:12:9a' };
  const c = tcp('client', 'camera', 51050, 554);
  const req = (start: string, headers: string[], label: string) =>
    onLan(c.send('a', textMsg('Real Time Streaming Protocol', start, headers), { label, proto: 'RTSP', info: `Request: ${start}`, color: 'amber' }), macs);
  const res = (headers: string[], label: string, body: string[] = []) =>
    onLan(
      c.send('b', textMsg('Real Time Streaming Protocol', 'RTSP/1.0 200 OK', headers, body), {
        label,
        proto: body.length ? 'RTSP/SDP' : 'RTSP',
        info: 'Reply: RTSP/1.0 200 OK',
        color: 'violet',
      }),
      macs,
    );
  const UA = 'User-Agent: NetworkExplorer/1.0';
  const hs = c.handshake().map((p) => onLan(p, macs));
  const options = req(`OPTIONS ${URL} RTSP/1.0`, ['CSeq: 1', UA], 'OPTIONS');
  const optionsOk = res(['CSeq: 1', 'Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN'], '200 OK');
  const describe = req(`DESCRIBE ${URL} RTSP/1.0`, ['CSeq: 2', UA, 'Accept: application/sdp'], 'DESCRIBE');
  const describeOk = res(
    ['CSeq: 2', `Content-Base: ${URL}/`],
    '200 OK + SDP',
    [
      'v=0',
      `o=- 1700000000 1 IN IP4 ${CAM}`,
      's=Front door camera',
      't=0 0',
      'm=video 0 RTP/AVP 96',
      'a=rtpmap:96 H264/90000',
      'a=fmtp:96 packetization-mode=1;profile-level-id=4D0029',
      'a=control:trackID=1',
    ],
  );
  const setup = req(`SETUP ${URL}/trackID=1 RTSP/1.0`, ['CSeq: 3', UA, 'Transport: RTP/AVP;unicast;client_port=50000-50001'], 'SETUP');
  const setupOk = res(
    ['CSeq: 3', 'Transport: RTP/AVP;unicast;client_port=50000-50001;server_port=6970-6971;ssrc=1A2B3C4D', 'Session: 4A3B21;timeout=60'],
    '200 OK',
  );
  const play = req(`PLAY ${URL}/ RTSP/1.0`, ['CSeq: 4', UA, 'Session: 4A3B21', 'Range: npt=0.000-'], 'PLAY');
  const playOk = res(['CSeq: 4', 'Session: 4A3B21', `RTP-Info: url=${URL}/trackID=1;seq=17000;rtptime=3000000`], '200 OK');

  const frag = (seq: number, part: 'start' | 'middle' | 'end') => {
    const fuHeader = part === 'start' ? 0x85 : part === 'end' ? 0x45 : 0x05;
    return onLan(
      udp({
        from: 'camera', to: 'client', sport: 6970, dport: 50000, color: 'teal', label: `H.264 ${part.toUpperCase()}`, proto: 'RTP',
        info: `PT=H264 (DynamicRTP-Type-96), SSRC=0x1A2B3C4D, Seq=${seq}, Time=3000000${part === 'end' ? ', Mark' : ''}`,
        app: rtp({
          pt: 96, ptName: 'H.264', seq, ts: 3000000, ssrc: 0x1a2b3c4d, marker: part === 'end',
          len: part === 'end' ? 640 : 1380, what: `keyframe slice data (${part} fragment)`, seed: `cam${seq}`,
          pre: [
            ['FU indicator', 'NRI 3 · type 28 (FU-A fragment)', [0x7c]],
            ['FU header', `${part === 'start' ? 'Start' : part === 'end' ? 'End' : 'Middle'} · NAL type 5 (IDR keyframe)`, [fuHeader]],
          ],
        }),
      }),
      macs,
    );
  };
  const teardown = req(`TEARDOWN ${URL}/ RTSP/1.0`, ['CSeq: 5', UA, 'Session: 4A3B21'], 'TEARDOWN');
  const teardownOk = res(['CSeq: 5'], '200 OK');
  const close = c.close().map((p) => onLan(p, macs));

  return lesson({
    id: 'rtsp',
    name: 'RTSP',
    title: 'IP camera streams',
    layer: 7,
    tagline: 'A remote control over TCP, with the video arriving over RTP.',
    nodes: [
      { id: 'client', x: 12, y: 58, label: 'Viewer app' },
      { id: 'router', x: 47, y: 58, label: 'Home router (switch)' },
      { id: 'camera', x: 82, y: 58 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'camera'],
    ],
    legend: [
      ['green', 'TCP control'],
      ['amber', 'RTSP request'],
      ['violet', 'RTSP reply'],
      ['teal', 'RTP video'],
    ],
    overview: {
      full: 'Real Time Streaming Protocol',
      description:
        'RTSP is the “remote control” most IP cameras speak. Over a TCP connection the viewer asks what streams exist (DESCRIBE), picks one and says where to send it (SETUP), then presses PLAY. The video itself doesn’t travel inside RTSP: it arrives separately as RTP packets over UDP.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', 'TCP 554'],
        ['Media', 'RTP over UDP (or interleaved in TCP)'],
        ['Methods', 'OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN'],
        ['Spec', 'RFC 2326 (2.0: RFC 7826)'],
      ],
    },
    steps: [
      {
        title: 'Connect and ask OPTIONS',
        desc: 'What can this camera do?',
        detail:
          'The viewer opens TCP port 554 on the camera — both are on the same home network, so frames go straight to the camera’s MAC address. OPTIONS asks which methods are supported. Every request carries a CSeq number that the reply echoes. (Real cameras usually demand Digest authentication with a 401 first.)',
        packets: [...hs, options, optionsOk],
      },
      {
        title: 'DESCRIBE',
        desc: 'The stream, described in SDP',
        detail:
          'DESCRIBE returns an SDP document: one video track, payload type 96 mapped to H.264 with a 90 kHz clock, and a control URL (trackID=1) used to address that track.',
        facts: [
          ['Codec', 'H.264'],
          ['RTP clock', '90 000 Hz'],
        ],
        packets: [describe, describeOk],
      },
      {
        title: 'SETUP',
        desc: 'Where should the video go?',
        detail:
          'SETUP tells the camera to send RTP to the viewer’s UDP ports 50000 (video) and 50001 (RTCP reports). The camera answers with its own ports and a Session ID that every later request must include.',
        facts: [
          ['Client ports', '50000–50001'],
          ['Server ports', '6970–6971'],
          ['Session', '4A3B21'],
        ],
        packets: [setup, setupOk],
      },
      {
        title: 'PLAY',
        desc: 'Start streaming',
        detail:
          'PLAY starts the stream from now (npt=0-). The reply’s RTP-Info gives the first sequence number and timestamp, so the viewer can line the packets up with the request.',
        packets: [play, playOk],
      },
      {
        title: 'Video arrives as RTP',
        desc: 'A keyframe in fragments',
        detail:
          'A keyframe is far larger than one packet, so H.264 splits it with FU-A fragmentation: the first packet has the Start bit, the last has the End bit and the RTP Marker set, and all share one timestamp. These are UDP datagrams, outside the RTSP connection.',
        facts: [
          ['Transport', 'UDP 6970 → 50000'],
          ['Fragmentation', 'FU-A'],
          ['Marker', 'last packet of the frame'],
        ],
        packets: [frag(17000, 'start'), frag(17001, 'middle'), frag(17002, 'end')],
      },
      {
        title: 'TEARDOWN',
        desc: 'Stop and disconnect',
        detail: 'When you close the viewer it sends TEARDOWN for the session; the camera stops sending RTP and the TCP connection is closed.',
        packets: [teardown, teardownOk, ...close],
      },
    ],
    outro: {
      title: 'Stream watched',
      text: 'Five short text requests over TCP steered the camera, while the video itself flowed as RTP over UDP. Plain RTSP is unencrypted — keep cameras off the open internet or use RTSPS.',
      facts: [
        ['Control', 'RTSP over TCP 554'],
        ['Video', 'RTP over UDP'],
      ],
    },
  });
}

/* ================================================================ RTMP */

function buildRtmp(): Lesson {
  const c = tcp('client', 'ingest', 52940, 1935);
  const hsTcp = c.handshake();
  const r1 = rand('c1', 1528);
  const s1r = rand('s1', 1528);
  const hsSeg = (side: 'a' | 'b', pieces: [string, string, number[]][], label: string, summary: string) =>
    c.send(side, rtmpHs(pieces, summary), { label, proto: 'RTMP', info: `Handshake: ${summary}`, color: side === 'a' ? 'amber' : 'violet' });
  const time0 = u32(0);
  const c01a = hsSeg('a', [
    ['C0 · version', '3 (plain RTMP)', [3]],
    ['C1 · time', '0', time0],
    ['C1 · zero', '0', [0, 0, 0, 0]],
    ['C1 · random (part 1)', '1451 of 1528 random bytes', r1.slice(0, 1451)],
  ], 'C0+C1 (1/2)', 'C0 + C1, part 1');
  const c01b = hsSeg('a', [['C1 · random (part 2)', 'last 77 random bytes', r1.slice(1451)]], 'C1 (2/2)', 'C1, part 2');
  const s012a = hsSeg('b', [
    ['S0 · version', '3', [3]],
    ['S1 · time', '0', time0],
    ['S1 · zero', '0', [0, 0, 0, 0]],
    ['S1 · random (part 1)', '1451 of 1528 random bytes', s1r.slice(0, 1451)],
  ], 'S0+S1', 'S0 + S1, part 1');
  const s012b = hsSeg('b', [
    ['S1 · random (part 2)', 'last 77 random bytes', s1r.slice(1451)],
    ['S2 · time', '0 (echo of C1 time)', time0],
    ['S2 · time2', '12 ms (when C1 arrived)', u32(12)],
    ['S2 · echo of C1 random (part 1)', 'copied from C1', r1.slice(0, 1375)],
  ], 'S1+S2', 'S1 part 2 + S2 part 1');
  const s012c = hsSeg('b', [['S2 · echo of C1 random (part 2)', 'copied from C1', r1.slice(1375)]], 'S2', 'S2, part 2');
  const c2a = hsSeg('a', [
    ['C2 · time', '0 (echo of S1 time)', time0],
    ['C2 · time2', '25 ms (when S1 arrived)', u32(25)],
    ['C2 · echo of S1 random (part 1)', 'copied from S1', s1r.slice(0, 1452)],
  ], 'C2 (1/2)', 'C2, part 1');
  const c2b = hsSeg('a', [['C2 · echo of S1 random (part 2)', 'copied from S1', s1r.slice(1452)]], 'C2 (2/2)', 'C2, part 2');

  const msg = (side: 'a' | 'b', msgs: RtmpMsg[], label: string, info: string, color: PacketColor) =>
    c.send(side, rtmpMsgs(msgs, info), { label, proto: 'RTMP', info, color });

  const connect = msg('a', [
    { csid: 2, type: 1, stream: 0, body: u32(4096), what: 'my chunks are now up to 4096 bytes' },
    {
      csid: 3, type: 20, stream: 0,
      body: [...amfStr('connect'), ...amfNum(1), ...amfObj({ app: 'live', type: 'nonprivate', flashVer: 'FMLE/3.0', tcUrl: 'rtmp://live.example.com/live' })],
      what: 'connect(1, {app: "live", tcUrl: "rtmp://live.example.com/live"})',
    },
  ], 'CONNECT', "Set Chunk Size 4096 | connect('live')", 'amber');
  const connected = msg('b', [
    { csid: 2, type: 5, stream: 0, body: u32(2500000), what: 'acknowledge every 2,500,000 bytes' },
    { csid: 2, type: 6, stream: 0, body: [...u32(2500000), 2], what: '2,500,000 bytes, dynamic' },
    { csid: 2, type: 1, stream: 0, body: u32(4096), what: 'server chunks up to 4096 bytes' },
    {
      csid: 3, type: 20, stream: 0,
      body: [...amfStr('_result'), ...amfNum(1), ...amfObj({ fmsVer: 'FMS/3,0,1,123', capabilities: 31 }), ...amfObj({ level: 'status', code: 'NetConnection.Connect.Success', description: 'Connection succeeded.' })],
      what: '_result(1, …, {code: "NetConnection.Connect.Success"})',
    },
  ], '_RESULT', 'Window Ack Size | Set Peer Bandwidth | Set Chunk Size | _result(NetConnection.Connect.Success)', 'violet');
  const createStream = msg('a', [
    { csid: 3, type: 20, stream: 0, body: [...amfStr('createStream'), ...amfNum(2), ...AMF_NULL], what: 'createStream(2, null)' },
  ], 'CREATE STREAM', 'createStream()', 'amber');
  const streamOk = msg('b', [
    { csid: 3, type: 20, stream: 0, body: [...amfStr('_result'), ...amfNum(2), ...AMF_NULL, ...amfNum(1)], what: '_result(2, null, 1) — your stream ID is 1' },
  ], '_RESULT', '_result() stream ID 1', 'violet');
  const publish = msg('a', [
    { csid: 8, type: 20, stream: 1, body: [...amfStr('publish'), ...amfNum(3), ...AMF_NULL, ...amfStr('my-secret-stream-key'), ...amfStr('live')], what: 'publish(3, null, "my-secret-stream-key", "live")' },
  ], 'PUBLISH', "publish('my-secret-stream-key')", 'amber');
  const onStatus = msg('b', [
    { csid: 5, type: 20, stream: 1, body: [...amfStr('onStatus'), ...amfNum(0), ...AMF_NULL, ...amfObj({ level: 'status', code: 'NetStream.Publish.Start', description: 'Start publishing' })], what: 'onStatus({code: "NetStream.Publish.Start"})' },
  ], 'ON STATUS', 'onStatus(NetStream.Publish.Start)', 'violet');
  const meta = msg('a', [
    {
      csid: 4, type: 18, stream: 1,
      body: [...amfStr('@setDataFrame'), ...amfStr('onMetaData'), 0x08, ...u32(5), ...[['width', 1920], ['height', 1080], ['framerate', 30], ['videocodecid', 7], ['audiocodecid', 10]].flatMap(([k, v]) => [...u16(String(k).length), ...ascii(String(k)), ...amfNum(Number(v))]), 0, 0, 9],
      what: 'onMetaData {width 1920, height 1080, framerate 30, H.264, AAC}',
    },
    { csid: 6, type: 9, stream: 1, body: [0x17, 0x00, 0, 0, 0, 1, 0x4d, 0x00, 0x29, 0xff, 0xe1, ...rand('sps', 30)], what: 'AVC sequence header (SPS/PPS decoder setup)' },
    { csid: 4, type: 8, stream: 1, body: [0xaf, 0x00, 0x12, 0x10], what: 'AAC sequence header (44.1 kHz stereo)' },
  ], 'METADATA', '@setDataFrame onMetaData | Video config | Audio config', 'teal');
  const video = (ts: number, key: boolean, len: number) =>
    msg('a', [
      { csid: 6, type: 9, stream: 1, ts, body: [key ? 0x17 : 0x27, 0x01, 0, 0, 0, ...rand(`v${ts}`, len)], what: `${key ? 'keyframe (IDR)' : 'inter frame'} · H.264 NAL units` },
    ], key ? 'KEYFRAME' : 'VIDEO', `Video Data (${key ? 'keyframe' : 'inter frame'}) t=${ts} ms`, key ? 'pink' : 'blue');
  const audio = (ts: number) =>
    msg('a', [{ csid: 4, type: 8, stream: 1, ts, body: [0xaf, 0x01, ...rand(`a${ts}`, 180)], what: 'AAC frame (~23 ms of sound)' }], 'AUDIO', `Audio Data t=${ts} ms`, 'green');
  const v1 = video(0, true, 1200);
  const a1 = audio(0);
  const v2 = video(33, false, 640);
  const ack = c.ack('b');

  return lesson({
    id: 'rtmp',
    name: 'RTMP',
    title: 'Live streaming upload',
    layer: 7,
    tagline: 'How streaming software pushes your camera to a live platform.',
    nodes: [
      { id: 'client', x: 9, y: 60, label: 'Streaming PC' },
      { id: 'router', x: 30, y: 60 },
      { id: 'internet', x: 53, y: 60 },
      { id: 'ingest', x: 83, y: 60 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
      ['internet', 'ingest'],
    ],
    legend: [
      ['green', 'TCP control / audio'],
      ['amber', 'Client → server'],
      ['violet', 'Server → client'],
      ['teal', 'Setup data'],
      ['pink', 'Keyframe'],
      ['blue', 'Video'],
    ],
    overview: {
      full: 'Real-Time Messaging Protocol',
      description:
        'RTMP started in Flash and lives on as the way encoders such as OBS upload a live stream to platforms. It runs over one TCP connection: a fixed-size handshake, then messages cut into chunks — commands like connect and publish encoded in AMF0, followed by a steady flow of audio and video messages.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', 'TCP 1935 (RTMPS: 443)'],
        ['Encoding', 'AMF0 commands, FLV-style media tags'],
        ['Typical media', 'H.264 + AAC'],
        ['Spec', 'Adobe RTMP specification'],
      ],
    },
    steps: [
      {
        title: 'TCP and C0 + C1',
        desc: 'A fixed-size hello',
        detail:
          'After the TCP handshake the encoder sends C0 (one byte: version 3) and C1 (1536 bytes: a time, four zero bytes and random data). C1 is larger than one TCP segment, so it goes in two pieces.',
        facts: [
          ['C0', '1 byte'],
          ['C1', '1536 bytes'],
        ],
        packets: [...hsTcp, c01a, c01b],
      },
      {
        title: 'S0, S1, S2 and C2',
        desc: 'Each side echoes the other',
        detail:
          'The server answers with S0, its own random S1 and S2 — an exact copy of the client’s C1. The client sends C2, a copy of S1. Once both echoes match, the handshake is done: 3,073 bytes from the server and 3,073 from the client.',
        facts: [['Echo check', 'S2 = C1, C2 = S1']],
        packets: [s012a, s012b, s012c, c2a, c2b],
      },
      {
        title: 'connect',
        desc: 'Join the “live” application',
        detail:
          'The encoder first raises its chunk size from the default 128 bytes to 4096, then sends the AMF0 command connect with the application name and URL. The server sets flow-control limits and replies _result with NetConnection.Connect.Success.',
        facts: [
          ['App', 'live'],
          ['Chunk size', '128 → 4096 bytes'],
        ],
        packets: [connect, connected],
      },
      {
        title: 'createStream and publish',
        desc: 'The stream key',
        detail:
          'createStream gets a message stream ID (1). publish sends the stream key — the secret that tells the platform which channel this is. In plain RTMP the key travels unencrypted, which is why platforms now prefer RTMPS on port 443.',
        facts: [
          ['Stream ID', '1'],
          ['Stream key', 'sent in plain text!'],
        ],
        packets: [createStream, streamOk, publish, onStatus],
      },
      {
        title: 'Metadata and decoder setup',
        desc: 'Describe the stream first',
        detail:
          'Before any picture the encoder sends onMetaData (1920×1080 at 30 fps, H.264 + AAC) and the codec configuration: the AVC sequence header with SPS/PPS and the AAC header. A player can’t decode anything without these.',
        packets: [meta],
      },
      {
        title: 'Media flows',
        desc: 'Keyframes, inter frames and audio',
        detail:
          'Now video and audio messages stream continuously, each with a millisecond timestamp. The first video message is a keyframe (byte 0x17) that can be decoded on its own; the following inter frames (0x27) only store what changed. TCP acknowledges as the bytes arrive.',
        facts: [
          ['Keyframe marker', '0x17'],
          ['Inter frame', '0x27'],
          ['Keyframe every', '~2 s (typical)'],
        ],
        packets: [v1, a1, v2, ack],
      },
    ],
    outro: {
      title: 'You’re live',
      text: 'A 1536-byte echo handshake, three AMF0 commands and the stream key turned one TCP connection into a live upload. The platform now re-encodes and fans the stream out to viewers.',
      facts: [
        ['Connection', '1 TCP, port 1935'],
        ['Secret', 'stream key — use RTMPS'],
      ],
    },
  });
}

/* ================================================================ Modbus */

function buildModbus(): Lesson {
  const macs = { client: MAC.client, plc: '00:80:f4:1b:22:9c' };
  const c = tcp('client', 'plc', 50214, 502);
  const hs = c.handshake().map((p) => onLan(p, macs));
  const send = (side: 'a' | 'b', txn: number, pdu: [string, string, number[]][], label: string, info: string, color: PacketColor) =>
    onLan(c.send(side, modbus(txn, pdu, info), { label, proto: 'Modbus/TCP', info, color }), macs);

  const regs = [215, 220, 1, 1340];
  const readReq = send('a', 1, [
    ['Function code', 'Read Holding Registers (3)', [3]],
    ['Starting address', '0 (register 40001)', u16(0)],
    ['Quantity', '4 registers', u16(4)],
  ], 'READ 4', 'Query: Trans 1; Read Holding Registers 0–3', 'amber');
  const readRes = send('b', 1, [
    ['Function code', 'Read Holding Registers (3)', [3]],
    ['Byte count', '8', [8]],
    ['Register 40001', '215 → tank temperature 21.5 °C', u16(regs[0])],
    ['Register 40002', '220 → setpoint 22.0 °C', u16(regs[1])],
    ['Register 40003', '1 → pump running', u16(regs[2])],
    ['Register 40004', '1340 → flow 13.40 L/min', u16(regs[3])],
  ], 'VALUES', 'Response: Trans 1; Read Holding Registers', 'violet');
  const writeReq = send('a', 2, [
    ['Function code', 'Write Single Register (6)', [6]],
    ['Register address', '1 (register 40002)', u16(1)],
    ['Value', '235 → new setpoint 23.5 °C', u16(235)],
  ], 'WRITE 1', 'Query: Trans 2; Write Single Register 1 = 235', 'amber');
  const writeRes = send('b', 2, [
    ['Function code', 'Write Single Register (6)', [6]],
    ['Register address', '1 (echoed)', u16(1)],
    ['Value', '235 (echoed)', u16(235)],
  ], 'OK', 'Response: Trans 2; Write Single Register', 'violet');
  const multiReq = send('a', 3, [
    ['Function code', 'Write Multiple Registers (16)', [16]],
    ['Starting address', '10 (register 40011)', u16(10)],
    ['Quantity', '3 registers', u16(3)],
    ['Byte count', '6', [6]],
    ['Values', '500, 300, 1 → high alarm 50.0 °C, low alarm 30.0 °C, alarms on', [...u16(500), ...u16(300), ...u16(1)]],
  ], 'WRITE 3', 'Query: Trans 3; Write Multiple Registers 10–12', 'amber');
  const multiRes = send('b', 3, [
    ['Function code', 'Write Multiple Registers (16)', [16]],
    ['Starting address', '10', u16(10)],
    ['Quantity', '3 written', u16(3)],
  ], 'OK', 'Response: Trans 3; Write Multiple Registers', 'violet');
  const badReq = send('a', 4, [
    ['Function code', 'Read Holding Registers (3)', [3]],
    ['Starting address', '1024 (register 41025)', u16(1024)],
    ['Quantity', '2 registers', u16(2)],
  ], 'READ 2', 'Query: Trans 4; Read Holding Registers 1024–1025', 'amber');
  const badRes = send('b', 4, [
    ['Function code', '0x83 = 3 + 0x80 (exception)', [0x83]],
    ['Exception code', '2 (Illegal Data Address)', [2]],
  ], 'EXCEPTION', 'Response: Trans 4; Exception: Illegal Data Address', 'red');
  const close = c.close().map((p) => onLan(p, macs));

  return lesson({
    id: 'modbus',
    name: 'Modbus',
    title: 'Talking to a PLC',
    layer: 7,
    tagline: 'Read and write numbered registers in a factory controller.',
    nodes: [
      { id: 'client', x: 12, y: 58, label: 'Engineering laptop' },
      { id: 'otswitch', x: 47, y: 58 },
      { id: 'plc', x: 82, y: 58 },
    ],
    links: [
      ['client', 'otswitch'],
      ['otswitch', 'plc'],
    ],
    legend: [
      ['green', 'TCP control'],
      ['amber', 'Request'],
      ['violet', 'Response'],
      ['red', 'Exception'],
    ],
    overview: {
      full: 'Modbus over TCP',
      description:
        'Modbus is a 1979 protocol that still runs countless factories, pumps and building systems. A PLC exposes numbered 16-bit registers; a client reads or writes them with tiny requests made of a function code and an address. Modbus/TCP just puts a 7-byte MBAP header in front and sends it to port 502 — with no login and no encryption.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', 'TCP 502'],
        ['Header', 'MBAP, 7 bytes'],
        ['Data', '16-bit registers, 1-bit coils'],
        ['Security', 'None built in'],
        ['Spec', 'Modbus Application Protocol v1.1b3'],
      ],
    },
    steps: [
      {
        title: 'Connect to port 502',
        desc: 'Plain TCP on the plant network',
        detail:
          'The engineering laptop and the PLC sit on the same plant network, so frames go through the switch straight to the PLC’s MAC address. A normal TCP handshake to port 502 is all it takes — there is no login step in Modbus.',
        packets: hs,
      },
      {
        title: 'Read holding registers',
        desc: 'Function code 3',
        detail:
          'The request is just 12 bytes: the MBAP header (transaction ID, protocol 0, length, unit ID) and the PDU “read 4 registers starting at address 0”. The PLC answers with 8 bytes of values. Modbus has no units or names — the plant’s documentation says register 40001 is temperature in tenths of a degree.',
        facts: [
          ['Request', '12 bytes'],
          ['Values', '215, 220, 1, 1340'],
        ],
        packets: [readReq, readRes],
      },
      {
        title: 'Write one register',
        desc: 'Function code 6',
        detail:
          'Changing the setpoint to 23.5 °C is one register write: address 1, value 235. The PLC confirms by echoing the request back. The heater logic in the PLC reacts immediately.',
        packets: [writeReq, writeRes],
      },
      {
        title: 'Write several at once',
        desc: 'Function code 16',
        detail:
          'Function 16 writes a block of consecutive registers in one go — here the high and low alarm limits and an “alarms enabled” flag. The reply confirms the start address and how many were written.',
        packets: [multiReq, multiRes],
      },
      {
        title: 'An exception',
        desc: 'Asking for a register that doesn’t exist',
        detail:
          'Reading address 1024 fails: this PLC has no register there. Instead of data it returns the function code with the top bit set (0x83) and exception code 2, Illegal Data Address. The transaction ID shows which request failed.',
        facts: [
          ['Function', '0x03 → 0x83'],
          ['Exception', '2 Illegal Data Address'],
        ],
        packets: [badReq, badRes],
      },
      {
        title: 'No security',
        desc: 'Anyone who can connect can write',
        detail:
          'Nothing in those packets proved who sent them, and none were encrypted. Any device that can reach port 502 could change the setpoint too. Plants protect Modbus by isolating the network and filtering traffic, or use Modbus/TCP Security (TLS on port 802).',
        facts: [
          ['Authentication', 'none'],
          ['Encryption', 'none'],
          ['Secure variant', 'Modbus/TCP Security, port 802'],
        ],
        packets: close,
      },
    ],
    outro: {
      title: 'PLC updated',
      text: 'Four tiny request/response pairs read the process values, changed a setpoint, set alarm limits and revealed an error — all in plain, unauthenticated bytes.',
      facts: [
        ['Requests', '4'],
        ['Login needed', 'never'],
      ],
    },
  });
}

export const PACK: Lesson[] = [buildUdp(), buildWebrtc(), buildSip(), buildRtsp(), buildRtmp(), buildModbus()];
