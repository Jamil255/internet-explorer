// Link-layer lessons: Ethernet & switches, Wi-Fi (WPA2), WPA3, PPPoE,
// RADIUS / 802.1X, and captive portals.
import { ascii, ethHeader, frame, hex, ipb, macb, rand, rawFrame, u16, zeros, type Writer } from '@/engine/bytes';
import { dns, http } from '@/engine/protocols';
import { registerNodes } from '@/engine/nodes';
import type { Lesson, Packet, PacketColor } from '@/engine/types';
import { MAC, lesson, packet, tcp, udp } from './kit';

registerNodes({
  switch: { label: 'Switch', icon: 'switch' },
  nas: { label: 'NAS', icon: 'hdd', ip: '192.168.1.20' },
  tv: { label: 'Smart TV', icon: 'tv', ip: '192.168.1.30' },
  ap: { label: 'Wi-Fi access point', icon: 'wifi' },
  radius: { label: 'RADIUS server', icon: 'key', ip: '10.0.0.5' },
  bras: { label: 'ISP access server', icon: 'building', ip: '198.51.100.1' },
  detect: { label: 'Connectivity check', icon: 'globe', ip: '203.0.113.80' },
});

/* ================================================================ helpers */

const le16 = (v: number) => [v & 255, (v >>> 8) & 255];
const le64 = (n: number) => Array.from({ length: 8 }, (_, i) => Math.floor(n / 2 ** (8 * i)) % 256);
const ZERO_MAC = '00:00:00:00:00:00';
const BCAST = MAC.bcast;
const CL = MAC.client;
const BSSID = '02:5e:a1:44:9c:10';
const NAS_MAC = '00:11:32:8a:4c:21';
const TV_MAC = '70:2a:d5:19:e0:3b';
const macLabel = (m: string) => (m === BCAST ? `${m} (broadcast)` : m);

interface RawSpec {
  from: string;
  to: string;
  color: PacketColor;
  label: string;
  proto: string;
  info: string;
  src: string;
  dst: string;
  write: (w: Writer) => void;
}
const rawPkt = (o: RawSpec): Packet =>
  packet({ from: o.from, to: o.to, color: o.color, label: o.label, proto: o.proto, info: o.info, src: o.src, dst: o.dst, raw: rawFrame(o.write) });

/* ---------- ARP */

function arp(w: Writer, op: 1 | 2, sMac: string, sIp: string, tMac: string, tIp: string, dstMac: string) {
  ethHeader(w, dstMac, sMac, 0x0806, 'ARP');
  w.begin('arp', 'Address Resolution Protocol');
  w.f('Hardware type', 'Ethernet (1)', u16(1));
  w.f('Protocol type', 'IPv4 (0x0800)', u16(0x0800));
  w.f('Hardware size', 6, [6]);
  w.f('Protocol size', 4, [4]);
  w.f('Opcode', op === 1 ? 'request (1)' : 'reply (2)', u16(op));
  w.f('Sender MAC', sMac, macb(sMac));
  w.f('Sender IP', sIp, ipb(sIp));
  w.f('Target MAC', tMac === ZERO_MAC ? `${ZERO_MAC} (unknown — that’s the question)` : tMac, macb(tMac));
  w.f('Target IP', tIp, ipb(tIp));
  w.end(op === 1 ? `Who has ${tIp}? Tell ${sIp}` : `${sIp} is at ${sMac}`);
}

/* ---------- 802.11 */

const FC: Record<string, [number, string]> = {
  beacon: [0x80, 'Beacon'],
  'probe-req': [0x40, 'Probe Request'],
  'probe-resp': [0x50, 'Probe Response'],
  auth: [0xb0, 'Authentication'],
  'assoc-req': [0x00, 'Association Request'],
  'assoc-resp': [0x10, 'Association Response'],
  data: [0x08, 'Data'],
};

function wlan(
  w: Writer,
  kind: keyof typeof FC,
  o: { a1: string; a2: string; a3: string; seq: number; toDs?: boolean; fromDs?: boolean; prot?: boolean },
) {
  const [fc0, name] = FC[kind];
  const flags = (o.toDs ? 1 : 0) | (o.fromDs ? 2 : 0) | (o.prot ? 0x40 : 0);
  const fl = [o.toDs && 'to DS', o.fromDs && 'from DS', o.prot && 'protected'].filter(Boolean).join(', ');
  w.begin('wlan', `IEEE 802.11 ${name}`);
  w.f('Frame control', `${name} (${hex(fc0)})${fl ? ` · ${fl}` : ''}`, [fc0, flags]);
  const dur = o.a1 === BCAST ? 0 : 44;
  w.f('Duration', `${dur} µs`, le16(dur));
  w.f('Address 1 (receiver)', macLabel(o.a1), macb(o.a1));
  w.f('Address 2 (transmitter)', o.a2, macb(o.a2));
  w.f('Address 3', o.a3 === BSSID ? `${o.a3} (BSSID)` : macLabel(o.a3), macb(o.a3));
  w.f('Sequence control', `seq ${o.seq} · fragment 0`, le16(o.seq << 4));
  w.end(`${name} · ${o.a2} → ${o.a1}`);
}

const ie = (w: Writer, id: number, name: string, value: string, body: number[]) =>
  w.f(`Tag ${id} · ${name}`, value, [id, body.length, ...body]);
const ssidIE = (w: Writer, ssid: string) => ie(w, 0, 'SSID', ssid, ascii(ssid));
const ratesIE = (w: Writer) =>
  ie(w, 1, 'Supported rates', '1, 2, 5.5, 11, 6, 9, 12, 18 Mb/s', [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
const AKM: Record<number, string> = { 1: '802.1X (Enterprise)', 2: 'PSK (WPA2-Personal)', 8: 'SAE (WPA3-Personal)' };
const rsnBody = (akm: number, mfpr: boolean) => [
  1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, akm, mfpr ? 0xc0 : 0x00, 0,
];
const rsnIE = (w: Writer, akm: number, mfpr = false) =>
  ie(w, 48, 'RSN', `CCMP-128 · ${AKM[akm]}${mfpr ? ' · protected management frames required' : ''}`, rsnBody(akm, mfpr));

function beaconish(ssid: string, akm: number, mfpr: boolean, to: string, kind: 'beacon' | 'probe-resp') {
  return (w: Writer) => {
    wlan(w, kind, { a1: to, a2: BSSID, a3: BSSID, seq: kind === 'beacon' ? 1234 : 1240 });
    w.begin('mgmt', 'IEEE 802.11 Wireless Management');
    w.f('Timestamp', 'AP uptime 1,532,190,004 µs', le64(1532190004));
    w.f('Beacon interval', '100 TU (102.4 ms)', le16(100));
    w.f('Capabilities', 'ESS · Privacy · Short slot time', le16(0x0411));
    ssidIE(w, ssid);
    ratesIE(w);
    ie(w, 3, 'DS parameter set', 'channel 6', [6]);
    rsnIE(w, akm, mfpr);
    w.end(`${kind === 'beacon' ? 'Beacon' : 'Probe response'} · SSID ${ssid}`);
  };
}

function probeReq(ssid: string) {
  return (w: Writer) => {
    wlan(w, 'probe-req', { a1: BCAST, a2: CL, a3: BCAST, seq: 17 });
    w.begin('mgmt', 'IEEE 802.11 Wireless Management');
    ssidIE(w, ssid);
    ratesIE(w);
    w.end(`Probe request · SSID ${ssid}`);
  };
}

function authFrame(up: boolean, alg: 0 | 3, seq: number, extra?: (w: Writer) => void, summary?: string) {
  return (w: Writer) => {
    wlan(w, 'auth', up ? { a1: BSSID, a2: CL, a3: BSSID, seq: 18 + seq } : { a1: CL, a2: BSSID, a3: BSSID, seq: 1241 + seq });
    w.begin('mgmt', 'IEEE 802.11 Wireless Management');
    w.f('Authentication algorithm', alg === 0 ? 'Open System (0)' : 'SAE (3)', le16(alg));
    w.f('Authentication sequence', alg === 3 ? `${seq} (${seq === 1 ? 'Commit' : 'Confirm'})` : seq, le16(seq));
    w.f('Status code', 'Successful (0)', le16(0));
    extra?.(w);
    w.end(summary ?? `Authentication · seq ${seq}`);
  };
}

function assocReq(ssid: string, akm: number, mfpr = false) {
  return (w: Writer) => {
    wlan(w, 'assoc-req', { a1: BSSID, a2: CL, a3: BSSID, seq: 21 });
    w.begin('mgmt', 'IEEE 802.11 Wireless Management');
    w.f('Capabilities', 'ESS · Privacy · Short slot time', le16(0x0411));
    w.f('Listen interval', '10 beacons', le16(10));
    ssidIE(w, ssid);
    ratesIE(w);
    rsnIE(w, akm, mfpr);
    w.end(`Association request · SSID ${ssid}`);
  };
}

function assocResp() {
  return (w: Writer) => {
    wlan(w, 'assoc-resp', { a1: CL, a2: BSSID, a3: BSSID, seq: 1245 });
    w.begin('mgmt', 'IEEE 802.11 Wireless Management');
    w.f('Capabilities', 'ESS · Privacy · Short slot time', le16(0x0411));
    w.f('Status code', 'Successful (0)', le16(0));
    w.f('Association ID', 'AID 1', le16(0xc001));
    ratesIE(w);
    w.end('Association response · AID 1');
  };
}

function llc(w: Writer, type: number, name: string) {
  w.begin('llc', 'Logical-Link Control (SNAP)');
  w.f('DSAP · SSAP · Control', 'SNAP (0xaa 0xaa 0x03)', [0xaa, 0xaa, 0x03]);
  w.f('Organization code', '00-00-00 (Ethernet encapsulation)', [0, 0, 0]);
  w.f('Type', `${name} (${hex(type, 4)})`, u16(type));
  w.end(`SNAP → ${name}`);
}

function dataHdr(w: Writer, up: boolean, seq: number, prot = false) {
  if (up) wlan(w, 'data', { a1: BSSID, a2: CL, a3: BSSID, seq, toDs: true, prot });
  else wlan(w, 'data', { a1: CL, a2: BSSID, a3: BSSID, seq, fromDs: true, prot });
}

/** EAPOL-Key (4-way handshake) message, carried in an 802.11 data frame. */
function eapolKey(o: { msg: 1 | 2 | 3 | 4; sae?: boolean; seed: string; kd?: [string, number[]] }) {
  const up = o.msg === 2 || o.msg === 4;
  // key descriptor version 2 (HMAC-SHA1/AES) for PSK and 802.1X, version 0 (AKM-defined) for SAE
  const base = { 1: 0x008a, 2: 0x010a, 3: 0x13ca, 4: 0x030a }[o.msg];
  const info = o.sae ? base & ~0x0007 : base;
  const desc = {
    1: 'pairwise · ACK',
    2: 'pairwise · MIC',
    3: 'pairwise · install · ACK · MIC · secure · encrypted key data',
    4: 'pairwise · MIC · secure',
  }[o.msg];
  const kd = o.kd?.[1] ?? [];
  const replay = o.msg <= 2 ? 1 : 2;
  return (w: Writer) => {
    dataHdr(w, up, up ? 30 + o.msg : 1250 + o.msg);
    llc(w, 0x888e, '802.1X Authentication');
    const len = 95 + kd.length;
    w.begin('eapol', '802.1X Authentication (EAPOL-Key)');
    w.f('Version', '802.1X-2004 (2)', [2]);
    w.f('Type', 'Key (3)', [3]);
    w.f('Length', `${len} bytes`, u16(len));
    w.f('Descriptor type', 'RSN key (2)', [2]);
    w.f('Key information', `${hex(info, 4)} (${desc})`, u16(info));
    w.f('Key length', o.msg === 1 || o.msg === 3 ? '16 (CCMP)' : '0', u16(o.msg === 1 || o.msg === 3 ? 16 : 0));
    w.f('Replay counter', replay, [0, 0, 0, 0, 0, 0, 0, replay]);
    w.f(
      'Key nonce',
      o.msg === 1 || o.msg === 3 ? 'ANonce (AP’s 32 random bytes)' : o.msg === 2 ? 'SNonce (client’s 32 random bytes)' : '0 (not used)',
      o.msg === 4 ? zeros(32) : rand((o.msg === 2 ? 'snonce' : 'anonce') + o.seed, 32),
    );
    w.f('Key IV', '0', zeros(16));
    w.f('Key RSC', o.msg === 3 ? 'group key starts at 0' : '0', zeros(8));
    w.f('Key ID', '0 (reserved)', zeros(8));
    w.f('Key MIC', o.msg === 1 ? '0 (no keys yet)' : 'present — proves the sender knows the PMK', o.msg === 1 ? zeros(16) : rand('mic' + o.msg + o.seed, 16));
    w.f('Key data length', `${kd.length} bytes`, u16(kd.length));
    if (kd.length) w.f('Key data', o.kd![0], kd);
    w.end(`Message ${o.msg} of 4`);
  };
}

const fourWay = (seed: string, sae = false, colorAll: PacketColor = 'teal') => {
  const mk = (msg: 1 | 2 | 3 | 4, kd?: [string, number[]]) =>
    rawPkt({
      from: msg % 2 ? 'ap' : 'client',
      to: msg % 2 ? 'client' : 'ap',
      color: colorAll,
      label: `MSG ${msg}`,
      proto: 'EAPOL',
      info: `Key (Message ${msg} of 4)`,
      src: msg % 2 ? BSSID : CL,
      dst: msg % 2 ? CL : BSSID,
      write: eapolKey({ msg, sae, seed, kd }),
    });
  return [
    mk(1),
    mk(2, ['RSN element (the client’s cipher choice, for checking)', [48, 20, ...rsnBody(sae ? 8 : 2, sae)]]),
    mk(3, ['Encrypted: RSN element + group key (GTK)' + (sae ? ' + IGTK' : ''), rand('gtk' + seed, sae ? 80 : 56)]),
    mk(4),
  ];
};

/* ---------- EAP / EAPOL */

const EAP_CODES: Record<number, string> = { 1: 'Request', 2: 'Response', 3: 'Success', 4: 'Failure' };
const EAP_TYPES: Record<number, string> = { 1: 'Identity', 25: 'PEAP' };

interface EapSpec {
  code: 1 | 2 | 3 | 4;
  id: number;
  type?: number;
  data?: number[];
  dataName?: string;
  dataValue?: string;
}
const eapBytes = (e: EapSpec) => {
  const body = e.type !== undefined ? [e.type, ...(e.data ?? [])] : [];
  return [e.code, e.id, ...u16(4 + body.length), ...body];
};
const eapLabel = (e: EapSpec) => `${EAP_CODES[e.code]}${e.type !== undefined ? `/${EAP_TYPES[e.type]}` : ''}`;

function eapOverWlan(up: boolean, seq: number, e: EapSpec) {
  return (w: Writer) => {
    dataHdr(w, up, seq);
    llc(w, 0x888e, '802.1X Authentication');
    const total = eapBytes(e).length;
    w.begin('eapol', '802.1X Authentication');
    w.f('Version', '802.1X-2004 (2)', [2]);
    w.f('Type', 'EAP packet (0)', [0]);
    w.f('Length', `${total} bytes`, u16(total));
    w.end('EAP packet');
    w.begin('eap', 'Extensible Authentication Protocol');
    w.f('Code', `${EAP_CODES[e.code]} (${e.code})`, [e.code]);
    w.f('Identifier', e.id, [e.id]);
    w.f('Length', `${total} bytes`, u16(total));
    if (e.type !== undefined) w.f('Type', `${EAP_TYPES[e.type]} (${e.type})`, [e.type]);
    if (e.data?.length) w.f(e.dataName ?? 'Data', e.dataValue ?? `${e.data.length} bytes`, e.data);
    w.end(eapLabel(e));
  };
}

/* ---------- RADIUS */

type Avp = [string, string, number, number[]];
const RADIUS_CODES: Record<number, string> = { 1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject', 11: 'Access-Challenge' };

function radius(code: number, id: number, attrs: Avp[]) {
  return (w: Writer) => {
    const total = 20 + attrs.reduce((s, a) => s + 2 + a[3].length, 0);
    w.begin('app', 'RADIUS');
    w.f('Code', `${RADIUS_CODES[code]} (${code})`, [code]);
    w.f('Identifier', id, [id]);
    w.f('Length', `${total} bytes`, u16(total));
    w.f(
      'Authenticator',
      code === 1 ? 'Request Authenticator (16 random bytes)' : 'Response Authenticator (MD5 over the packet + shared secret)',
      rand(`rad${code}${id}`, 16),
    );
    for (const [n, v, t, b] of attrs) w.f(`AVP ${t} · ${n}`, v, [t, b.length + 2, ...b]);
    w.end(`${RADIUS_CODES[code]} · id ${id}`);
  };
}

/* ---------- PPPoE / PPP */

const RT_WAN = 'a4:91:b1:0c:22:09';
const BRAS_MAC = '00:1d:aa:4f:10:01';
const SID = 0x2a1f;
type Tag = [string, string, number, number[]];

function pppoeDisc(code: number, name: string, sid: number, dst: string, src: string, tags: Tag[]) {
  return (w: Writer) => {
    ethHeader(w, dst, src, 0x8863, 'PPPoE Discovery');
    const len = tags.reduce((s, t) => s + 4 + t[3].length, 0);
    w.begin('pppoe', 'PPPoE Discovery');
    w.f('Version · Type', '1 · 1', [0x11]);
    w.f('Code', `${name} (${hex(code)})`, [code]);
    w.f('Session ID', sid ? `${hex(sid, 4)} (assigned)` : '0x0000 (no session yet)', u16(sid));
    w.f('Payload length', `${len} bytes`, u16(len));
    for (const [n, v, t, b] of tags) w.f(`Tag ${hex(t, 4)} · ${n}`, v, [...u16(t), ...u16(b.length), ...b]);
    w.end(name);
  };
}

type Opt = [string, string, number[]];
function pppCtrl(o: { up: boolean; proto: number; protoName: string; code: number; codeName: string; id: number; opts: Opt[] }) {
  return (w: Writer) => {
    ethHeader(w, o.up ? BRAS_MAC : RT_WAN, o.up ? RT_WAN : BRAS_MAC, 0x8864, 'PPPoE Session');
    const ctrlLen = 4 + o.opts.reduce((s, x) => s + x[2].length, 0);
    w.begin('pppoe', 'PPPoE Session');
    w.f('Version · Type', '1 · 1', [0x11]);
    w.f('Code', '0x00 (session data)', [0]);
    w.f('Session ID', hex(SID, 4), u16(SID));
    w.f('Payload length', `${ctrlLen + 2} bytes`, u16(ctrlLen + 2));
    w.end(`Session ${hex(SID, 4)}`);
    w.begin('ppp', `PPP ${o.protoName}`);
    w.f('Protocol', `${o.protoName} (${hex(o.proto, 4)})`, u16(o.proto));
    w.f('Code', `${o.codeName} (${o.code})`, [o.code]);
    w.f('Identifier', o.id, [o.id]);
    w.f('Length', `${ctrlLen} bytes`, u16(ctrlLen));
    for (const [n, v, b] of o.opts) w.f(n, v, b);
    w.end(`${o.protoName} ${o.codeName}`);
  };
}

const pppPkt = (up: boolean, color: PacketColor, label: string, info: string, write: (w: Writer) => void) =>
  rawPkt({
    from: up ? 'router' : 'bras',
    to: up ? 'bras' : 'router',
    color,
    label,
    proto: info.split(' ')[0],
    info,
    src: up ? RT_WAN : BRAS_MAC,
    dst: up ? BRAS_MAC : RT_WAN,
    write,
  });

/* ================================================================ Ethernet */

function buildEthernet() {
  const arpReqWrite = (w: Writer) => arp(w, 1, CL, '192.168.1.10', ZERO_MAC, '192.168.1.20', BCAST);
  const arpReq = (from: string, to: string, label: string) =>
    rawPkt({
      from, to, color: 'amber', label, proto: 'ARP',
      info: 'Who has 192.168.1.20? Tell 192.168.1.10', src: CL, dst: 'Broadcast', write: arpReqWrite,
    });
  const arpRep = rawPkt({
    from: 'nas', to: 'client', color: 'violet', label: 'ARP REPLY', proto: 'ARP',
    info: `192.168.1.20 is at ${NAS_MAC}`, src: NAS_MAC, dst: CL,
    write: (w) => arp(w, 2, NAS_MAC, '192.168.1.20', CL, '192.168.1.10', CL),
  });
  const PING = ascii('abcdefghijklmnopqrstuvwabcdefghi');
  const ping = packet({
    from: 'client', to: 'nas', color: 'blue', label: 'PING', proto: 'ICMP', srcMac: CL, dstMac: NAS_MAC, ttl: 64,
    info: 'Echo (ping) request id=0x0001, seq=1, ttl=64',
    l4: { kind: 'icmp', type: 8, code: 0, id: 1, seq: 1, data: PING },
  });
  const pong = packet({
    from: 'nas', to: 'client', color: 'blue', label: 'PONG', proto: 'ICMP', srcMac: NAS_MAC, dstMac: CL, ttl: 64,
    info: 'Echo (ping) reply id=0x0001, seq=1, ttl=64',
    l4: { kind: 'icmp', type: 0, code: 0, id: 1, seq: 1, data: PING },
  });

  return lesson({
    id: 'ethernet',
    name: 'Ethernet',
    title: 'Frames & switches',
    layer: 2,
    tagline: 'How a switch learns who sits on which port.',
    nodes: [
      { id: 'client', x: 12, y: 50, sub: 'port 1' },
      { id: 'switch', x: 46, y: 50 },
      { id: 'nas', x: 82, y: 24 },
      { id: 'tv', x: 82, y: 76 },
    ],
    links: [
      ['client', 'switch'],
      ['switch', 'nas'],
      ['switch', 'tv'],
    ],
    legend: [
      ['amber', 'Broadcast (flooded)'],
      ['violet', 'ARP reply'],
      ['blue', 'Unicast data'],
    ],
    overview: {
      full: 'IEEE 802.3 Ethernet',
      description:
        'On a local network, every frame is addressed by MAC address — the 48-bit hardware address burned into each network card. A switch connects the devices and gets smarter as it goes: it remembers which MAC address it has seen on which port, so it can send each frame only where it needs to go. ARP is how a device turns an IP address into the MAC address to put on the frame.',
      facts: [
        ['Layer', 'Data link (2)'],
        ['Address', '48-bit MAC'],
        ['Header', '14 bytes (+4-byte FCS)'],
        ['Frame size', '64 – 1518 bytes'],
        ['ARP EtherType', '0x0806'],
        ['Spec', 'IEEE 802.3, RFC 826'],
      ],
    },
    steps: [
      {
        title: 'A switch that knows nothing',
        desc: 'Its MAC table starts empty',
        detail:
          'The laptop, a NAS and a smart TV are plugged into one switch. Right after power-up the switch has no idea which device is on which port. It will learn by reading the source MAC address of every frame that arrives.',
        facts: [
          ['MAC table', 'empty'],
          ['Laptop wants', '192.168.1.20 (the NAS)'],
        ],
        focus: ['switch'],
      },
      {
        title: 'Who has 192.168.1.20?',
        desc: 'An ARP request to everyone',
        detail:
          'The laptop knows the NAS’s IP address but not its MAC address, so it can’t build an Ethernet frame for it yet. It sends an ARP request to the broadcast MAC ff:ff:ff:ff:ff:ff. When it reaches the switch, the switch notes: “3c:22:fb:7a:10:4e lives on port 1.”',
        facts: [
          ['EtherType', '0x0806 (ARP)'],
          ['Destination', 'ff:ff:ff:ff:ff:ff'],
          ['Switch learns', 'laptop → port 1'],
        ],
        packets: [arpReq('client', 'switch', 'ARP WHO-HAS')],
      },
      {
        title: 'Flooding',
        desc: 'Broadcasts go out every other port',
        detail:
          'A broadcast is meant for everyone, so the switch copies the frame out of every port except the one it came in on. Both the NAS and the TV receive it. The TV sees that 192.168.1.20 isn’t its address and quietly drops it.',
        packets: [arpReq('switch', 'nas', 'FLOOD'), arpReq('switch', 'tv', 'FLOOD')],
      },
      {
        title: 'The NAS answers',
        desc: 'A unicast ARP reply',
        detail:
          'The NAS replies directly to the laptop’s MAC address: “192.168.1.20 is at 00:11:32:8a:4c:21.” The switch learns the NAS is on port 2 — and because it already knows where the laptop is, it sends the reply only out of port 1. The laptop stores the answer in its ARP cache.',
        facts: [
          ['Switch learns', 'NAS → port 2'],
          ['ARP cache', '192.168.1.20 → 00:11:32:8a:4c:21'],
        ],
        packets: [arpRep],
      },
      {
        title: 'Switched, not flooded',
        desc: 'Unicast frames go to one port only',
        detail:
          'Now the laptop pings the NAS. The Ethernet destination is the NAS’s MAC, the switch looks it up in its table and forwards the frame out of port 2 only. The TV never sees this traffic — that’s what makes a switch better than an old hub.',
        facts: [
          ['MAC table', 'port 1: laptop · port 2: NAS'],
          ['TV receives', 'nothing'],
        ],
        packets: [ping, pong],
      },
    ],
    outro: {
      title: 'Switched',
      text: 'The switch learned two addresses just by listening, flooded only the one broadcast, and delivered everything else straight to the right port. Entries age out after about five minutes if a device goes quiet.',
      facts: [
        ['Frames flooded', '1 broadcast'],
        ['Table entries', '2'],
      ],
    },
  });
}

/* ================================================================ Wi-Fi (WPA2) */

function buildWifi() {
  const SSID = 'HomeNet';
  const m = (from: string, to: string, color: PacketColor, label: string, info: string, src: string, dst: string, write: (w: Writer) => void) =>
    rawPkt({ from, to, color, label, proto: '802.11', info, src, dst, write });

  const beacon = m('ap', 'client', 'slate', 'BEACON', `Beacon frame, SSID="${SSID}"`, BSSID, 'Broadcast', beaconish(SSID, 2, false, BCAST, 'beacon'));
  const preq = m('client', 'ap', 'slate', 'PROBE', `Probe Request, SSID="${SSID}"`, CL, 'Broadcast', probeReq(SSID));
  const presp = m('ap', 'client', 'slate', 'PROBE RESP', `Probe Response, SSID="${SSID}"`, BSSID, CL, beaconish(SSID, 2, false, CL, 'probe-resp'));
  const au1 = m('client', 'ap', 'blue', 'AUTH', 'Authentication, Open System, seq 1', CL, BSSID, authFrame(true, 0, 1));
  const au2 = m('ap', 'client', 'blue', 'AUTH OK', 'Authentication, Open System, seq 2, Successful', BSSID, CL, authFrame(false, 0, 2));
  const as1 = m('client', 'ap', 'blue', 'ASSOC REQ', `Association Request, SSID="${SSID}"`, CL, BSSID, assocReq(SSID, 2));
  const as2 = m('ap', 'client', 'blue', 'ASSOC RESP', 'Association Response, AID 1, Successful', BSSID, CL, assocResp());
  const hs = fourWay('wifi');
  const enc = (up: boolean, n: number, len: number) =>
    m(up ? 'client' : 'ap', up ? 'ap' : 'client', 'violet', 'ENCRYPTED', `QoS Data, protected (CCMP), ${len} bytes`, up ? CL : BSSID, up ? BSSID : CL, (w) => {
      dataHdr(w, up, up ? 40 + n : 1260 + n, true);
      w.begin('ccmp', 'CCMP encrypted payload');
      w.f('CCMP header', `packet number ${n} · key ID 0`, [n & 255, 0, 0, 0x20, 0, 0, 0, 0]);
      w.f('Encrypted data', `${len} bytes — an IP packet only the two ends can read`, rand('ccmp' + n + up, len));
      w.f('MIC', '8 bytes (tamper check)', rand('ccmpmic' + n + up, 8));
      w.end(`CCMP · PN ${n}`);
    });

  return lesson({
    id: 'wifi',
    name: 'Wi-Fi',
    title: 'Joining a network',
    layer: 2,
    tagline: 'From “I see HomeNet” to encrypted frames in the air.',
    nodes: [
      { id: 'client', x: 14, y: 58 },
      { id: 'ap', x: 52, y: 58, label: 'Wi-Fi router' },
      { id: 'internet', x: 86, y: 58 },
    ],
    links: [
      ['client', 'ap'],
      ['ap', 'internet'],
    ],
    legend: [
      ['slate', 'Discovery'],
      ['blue', 'Auth & association'],
      ['teal', '4-way handshake'],
      ['violet', 'Encrypted data'],
    ],
    overview: {
      full: 'Wi-Fi (IEEE 802.11) with WPA2-Personal',
      description:
        'Joining Wi-Fi takes three phases. First the laptop finds the network from beacons or probes. Then it “authenticates” and associates — just a formal hello in WPA2. Finally the 4-way handshake proves both sides know the password without ever sending it, and derives fresh keys that encrypt every frame from then on.',
      facts: [
        ['Layer', 'Data link (2)'],
        ['Security', 'WPA2-PSK, AES-CCMP'],
        ['Key exchange', 'EAPOL 4-way handshake'],
        ['Header', '24 bytes (802.11 MAC)'],
        ['Spec', 'IEEE 802.11-2020'],
      ],
    },
    steps: [
      {
        title: 'Beacons',
        desc: 'The router announces itself',
        detail:
          'About ten times a second the access point broadcasts a beacon: its network name (SSID), the channel, supported speeds and an RSN element that says “WPA2, AES-CCMP, pre-shared key”. That’s how HomeNet shows up in your Wi-Fi list.',
        facts: [
          ['SSID', SSID],
          ['Interval', '102.4 ms'],
          ['Security', 'RSN: CCMP + PSK'],
        ],
        packets: [beacon],
      },
      {
        title: 'Probe',
        desc: '“Is HomeNet here?”',
        detail:
          'Rather than wait for a beacon, the laptop can actively ask. It broadcasts a probe request naming the SSID, and the access point answers with a probe response that carries the same details as a beacon.',
        packets: [preq, presp],
      },
      {
        title: 'Open authentication',
        desc: 'A formality in WPA2',
        detail:
          'The name is misleading: 802.11 “Open System” authentication checks nothing. It’s a two-frame hello left over from the original standard. The real security check comes later, in the 4-way handshake.',
        packets: [au1, au2],
      },
      {
        title: 'Associate',
        desc: 'Join and get an Association ID',
        detail:
          'The laptop asks to join HomeNet and repeats the security suite it wants (CCMP + PSK). The access point accepts and assigns Association ID 1. The laptop is now connected — but still can’t send normal traffic until keys exist.',
        facts: [['AID', '1']],
        packets: [as1, as2],
      },
      {
        title: 'Handshake: messages 1 and 2',
        desc: 'Two random numbers',
        detail:
          'Both sides already share the PMK, computed from the Wi-Fi password and SSID. The AP sends a random ANonce; the laptop picks its own SNonce, combines PMK + both nonces + both MAC addresses into the session key (PTK), and sends SNonce back with a MIC that proves it knows the password.',
        facts: [
          ['PMK', 'PBKDF2(password, SSID)'],
          ['PTK from', 'PMK + ANonce + SNonce + MACs'],
        ],
        packets: hs.slice(0, 2),
      },
      {
        title: 'Handshake: messages 3 and 4',
        desc: 'Install the keys',
        detail:
          'The AP derives the same PTK, checks the laptop’s MIC, then sends message 3 with the group key (GTK, for broadcasts) encrypted inside. Message 4 confirms. Both sides install the keys. The password itself never crossed the air.',
        facts: [
          ['Pairwise key', 'PTK (unicast)'],
          ['Group key', 'GTK (broadcast)'],
        ],
        packets: hs.slice(2),
      },
      {
        title: 'Encrypted from now on',
        desc: 'AES-CCMP protects every frame',
        detail:
          'Every data frame now carries the “protected” flag, a packet number to stop replays, ciphertext and an 8-byte MIC. Someone nearby can still see the MAC addresses and frame sizes — but not the content.',
        packets: [enc(true, 1, 96), enc(false, 1, 320)],
      },
    ],
    outro: {
      title: 'Connected',
      text: 'Discover, authenticate, associate, then four EAPOL-Key messages — and the laptop is on HomeNet with keys that are unique to this session. Next it will use DHCP to get an IP address.',
      facts: [['Frames to connect', '12']],
    },
  });
}

/* ================================================================ WPA3 */

function buildWpa3() {
  const SSID = 'HomeNet';
  const m = (from: string, to: string, color: PacketColor, label: string, info: string, src: string, dst: string, write: (w: Writer) => void) =>
    rawPkt({ from, to, color, label, proto: '802.11', info, src, dst, write });
  const commit = (up: boolean) =>
    authFrame(
      up,
      3,
      1,
      (w) => {
        w.f('Finite cyclic group', 'NIST P-256 (19)', le16(19));
        w.f('Scalar', '32 bytes (random, derived for this attempt)', rand('scalar' + up, 32));
        w.f('Element', '64 bytes — a point (x, y) on the curve', rand('element' + up, 64));
      },
      'SAE Commit',
    );
  const confirm = (up: boolean) =>
    authFrame(
      up,
      3,
      2,
      (w) => {
        w.f('Send-confirm counter', 1, le16(1));
        w.f('Confirm', '32 bytes — proof of the same shared secret', rand('confirm' + up, 32));
      },
      'SAE Confirm',
    );
  const hs = fourWay('wpa3', true);

  return lesson({
    id: 'wpa3',
    name: 'WPA3',
    title: 'Safer Wi-Fi',
    layer: 2,
    tagline: 'SAE replaces password-derived keys with a real key exchange.',
    nodes: [
      { id: 'client', x: 14, y: 58 },
      { id: 'ap', x: 52, y: 58, label: 'Wi-Fi router' },
      { id: 'internet', x: 86, y: 58 },
    ],
    links: [
      ['client', 'ap'],
      ['ap', 'internet'],
    ],
    legend: [
      ['slate', 'Beacon'],
      ['pink', 'SAE exchange'],
      ['blue', 'Association'],
      ['teal', '4-way handshake'],
    ],
    overview: {
      full: 'Wi-Fi Protected Access 3 (SAE)',
      description:
        'With WPA2-Personal, anyone who records one handshake can try password guesses offline, as fast as their computer allows. WPA3 replaces that with SAE (“Dragonfly”), an elliptic-curve exchange where each guess requires a live attempt against the access point. It also gives forward secrecy and makes protected management frames mandatory.',
      facts: [
        ['Layer', 'Data link (2)'],
        ['Key exchange', 'SAE on NIST P-256'],
        ['AKM suite', '00-0F-AC:8'],
        ['PMF', 'required'],
        ['Spec', 'IEEE 802.11-2020, WPA3 spec'],
      ],
    },
    steps: [
      {
        title: 'A WPA3 network',
        desc: 'The beacon advertises SAE',
        detail:
          'The RSN element now lists SAE as the key management suite, and the capabilities say protected management frames are required. Older devices that only know WPA2 can’t join a WPA3-only network.',
        facts: [
          ['AKM', 'SAE (8)'],
          ['PMF', 'required + capable'],
        ],
        packets: [m('ap', 'client', 'slate', 'BEACON', `Beacon frame, SSID="${SSID}" (SAE)`, BSSID, 'Broadcast', beaconish(SSID, 8, true, BCAST, 'beacon'))],
      },
      {
        title: 'SAE Commit',
        desc: 'Both sides commit to a secret',
        detail:
          'Instead of an empty “open” authentication, each side sends a Commit: a random scalar and a curve point, both derived from the password. Either side can send first. An eavesdropper sees numbers that reveal nothing testable about the password.',
        facts: [
          ['Algorithm', 'SAE (3)'],
          ['Group', '19 (P-256)'],
        ],
        packets: [
          m('client', 'ap', 'pink', 'COMMIT', 'Authentication, SAE, seq 1 (Commit)', CL, BSSID, commit(true)),
          m('ap', 'client', 'pink', 'COMMIT', 'Authentication, SAE, seq 1 (Commit)', BSSID, CL, commit(false)),
        ],
      },
      {
        title: 'SAE Confirm',
        desc: 'Prove you got the same answer',
        detail:
          'Each side combines its own secret with the other’s commit to reach the same shared key, then sends a Confirm value proving it. Only someone with the right password gets a matching result — and a wrong guess costs a whole new exchange with the router.',
        facts: [
          ['Result', 'a fresh PMK'],
          ['Offline guessing', 'not possible'],
        ],
        packets: [
          m('client', 'ap', 'pink', 'CONFIRM', 'Authentication, SAE, seq 2 (Confirm)', CL, BSSID, confirm(true)),
          m('ap', 'client', 'pink', 'CONFIRM', 'Authentication, SAE, seq 2 (Confirm)', BSSID, CL, confirm(false)),
        ],
      },
      {
        title: 'Associate',
        desc: 'Same as WPA2',
        detail: 'With SAE done the laptop associates as usual, repeating that it wants SAE with protected management frames.',
        packets: [
          m('client', 'ap', 'blue', 'ASSOC REQ', `Association Request, SSID="${SSID}"`, CL, BSSID, assocReq(SSID, 8, true)),
          m('ap', 'client', 'blue', 'ASSOC RESP', 'Association Response, AID 1, Successful', BSSID, CL, assocResp()),
        ],
      },
      {
        title: '4-way handshake',
        desc: 'Session keys from the SAE PMK',
        detail:
          'The familiar four EAPOL-Key messages follow, but the PMK they start from came out of SAE — it’s different every time you connect. Message 3 also delivers the IGTK, the key that protects broadcast management frames.',
        packets: hs,
      },
      {
        title: 'Why it’s safer',
        desc: 'Three real improvements',
        detail:
          'A captured WPA3 handshake can’t be cracked offline. Because each connection gets a new PMK, learning the password later doesn’t decrypt old recordings (forward secrecy). And with PMF, attackers can no longer forge “deauthenticate” frames to knock you off the network.',
        facts: [
          ['Offline attacks', 'blocked'],
          ['Forward secrecy', 'yes'],
          ['Forged deauth', 'rejected (PMF)'],
        ],
        focus: ['client', 'ap'],
      },
    ],
    outro: {
      title: 'Connected with WPA3',
      text: 'Four SAE frames replaced the empty open-auth exchange and turned the password into a proper key agreement. Everything after that looks just like WPA2 — only much harder to attack.',
      facts: [['SAE frames', '4']],
    },
  });
}

/* ================================================================ PPPoE */

function buildPppoe() {
  const HU = [0x5a, 0x11, 0x0c, 0x93];
  const COOKIE = rand('accookie', 16);
  const user = 'home123@isp.example';
  const pass = 'S3cret!';
  const magicR = [0x1c, 0x9e, 0x4b, 0x07];
  const magicB = [0x7f, 0x22, 0x31, 0xa8];
  const IP = '198.51.100.77';

  const sname: Tag = ['Service-Name', 'any service (empty)', 0x0101, []];
  const huniq: Tag = ['Host-Uniq', hex(0x5a110c93, 8), 0x0103, HU];
  const acname: Tag = ['AC-Name', 'BRAS-KHI-01', 0x0102, ascii('BRAS-KHI-01')];
  const cookie: Tag = ['AC-Cookie', '16 bytes (echo this back)', 0x0104, COOKIE];

  const disc = (up: boolean, code: number, name: string, sid: number, dst: string, tags: Tag[], label: string, color: PacketColor) =>
    rawPkt({
      from: up ? 'router' : 'bras', to: up ? 'bras' : 'router', color, label, proto: 'PPPoED',
      info: `${name.split(' ')[0]}${sid ? ` Session ID ${hex(sid, 4)}` : ''}`,
      src: up ? RT_WAN : BRAS_MAC, dst: dst === BCAST ? 'Broadcast' : dst,
      write: pppoeDisc(code, name, sid, dst, up ? RT_WAN : BRAS_MAC, tags),
    });

  const mru: Opt = ['Option · MRU', '1492 bytes', [1, 4, ...u16(1492)]];
  const lcp = (up: boolean, code: number, codeName: string, id: number, opts: Opt[]) =>
    pppPkt(up, 'green', `LCP ${codeName.split('-')[1]?.toUpperCase() ?? codeName}`, `PPP LCP ${codeName}`, pppCtrl({ up, proto: 0xc021, protoName: 'LCP', code, codeName, id, opts }));
  const lcpR = [mru, ['Option · Magic number', hex(0x1c9e4b07, 8), [5, 6, ...magicR]] as Opt];
  const lcpB = [mru, ['Option · Auth protocol', 'PAP (0xc023)', [3, 4, 0xc0, 0x23]] as Opt, ['Option · Magic number', hex(0x7f2231a8, 8), [5, 6, ...magicB]] as Opt];

  const ipOpt = (ip: string): Opt => ['Option · IP address', ip, [3, 6, ...ipb(ip)]];
  const dnsOpts = (a: string, b: string): Opt[] => [
    ['Option · Primary DNS', a, [129, 6, ...ipb(a)]],
    ['Option · Secondary DNS', b, [131, 6, ...ipb(b)]],
  ];
  const ipcp = (up: boolean, code: number, codeName: string, id: number, opts: Opt[], label: string) =>
    pppPkt(up, 'teal', label, `PPP IPCP ${codeName}`, pppCtrl({ up, proto: 0x8021, protoName: 'IPCP', code, codeName, id, opts }));

  // a real IPv4/UDP/DNS packet carried inside the PPPoE session
  const inner = frame({
    srcMac: RT_WAN, dstMac: BRAS_MAC, src: IP, dst: '8.8.8.8', ttl: 64,
    l4: { kind: 'udp', sport: 53011, dport: 53 },
    app: dns({ id: 0x1d7a, rd: true, q: ['www.example.com', 'A'] }),
  }).bytes.slice(14);
  const dataPkt = rawPkt({
    from: 'router', to: 'bras', color: 'blue', label: 'IP DATA', proto: 'PPP',
    info: `IPv4 ${IP} → 8.8.8.8 DNS query (inside PPPoE)`, src: IP, dst: '8.8.8.8',
    write: (w) => {
      ethHeader(w, BRAS_MAC, RT_WAN, 0x8864, 'PPPoE Session');
      w.begin('pppoe', 'PPPoE Session');
      w.f('Version · Type', '1 · 1', [0x11]);
      w.f('Code', '0x00 (session data)', [0]);
      w.f('Session ID', hex(SID, 4), u16(SID));
      w.f('Payload length', `${inner.length + 2} bytes`, u16(inner.length + 2));
      w.end(`Session ${hex(SID, 4)}`);
      w.begin('ppp', 'Point-to-Point Protocol');
      w.f('Protocol', 'IPv4 (0x0021)', u16(0x0021));
      w.end('IPv4');
      w.begin('ipdata', 'IPv4 packet (inside PPP)');
      w.f('IPv4 + UDP + DNS', `${inner.length} bytes · ${IP} → 8.8.8.8 · DNS query`, inner);
      w.end(`${IP} → 8.8.8.8`);
    },
  });

  return lesson({
    id: 'pppoe',
    name: 'PPPoE',
    title: 'Broadband logins',
    layer: 2,
    tagline: 'How a DSL or fibre router logs in to the ISP and gets a public IP.',
    nodes: [
      { id: 'router', x: 14, y: 58, label: 'Your router' },
      { id: 'bras', x: 52, y: 58 },
      { id: 'internet', x: 86, y: 58 },
    ],
    links: [
      ['router', 'bras'],
      ['bras', 'internet'],
    ],
    legend: [
      ['amber', 'Discovery'],
      ['green', 'LCP'],
      ['pink', 'Login (PAP)'],
      ['teal', 'IPCP'],
      ['blue', 'Data'],
    ],
    overview: {
      full: 'Point-to-Point Protocol over Ethernet',
      description:
        'Many DSL and fibre ISPs want each customer to log in with a username and password, just like old dial-up. PPPoE makes that work over Ethernet: the router discovers the ISP’s access concentrator, opens a session, runs PPP inside it to log in, and is handed a public IP address. Every packet afterwards carries an 8-byte PPPoE+PPP header.',
      facts: [
        ['Layer', 'Data link (2)'],
        ['EtherTypes', '0x8863 discovery, 0x8864 session'],
        ['Overhead', '8 bytes → MTU 1492'],
        ['Login', 'PAP or CHAP'],
        ['Spec', 'RFC 2516, RFC 1661'],
      ],
    },
    steps: [
      {
        title: 'PADI',
        desc: '“Any access concentrators out there?”',
        detail:
          'The router broadcasts a PPPoE Active Discovery Initiation. It asks for any service and includes a random Host-Uniq tag so it can match the replies to this request.',
        facts: [
          ['Code', '0x09 (PADI)'],
          ['Destination', 'broadcast'],
        ],
        packets: [disc(true, 0x09, 'PADI (Initiation)', 0, BCAST, [sname, huniq], 'PADI', 'amber')],
      },
      {
        title: 'PADO',
        desc: 'The ISP’s concentrator offers',
        detail:
          'The ISP’s Broadband Remote Access Server (BRAS) answers with an Offer, giving its name and a cookie the router must send back. If several answer, the router picks one.',
        packets: [disc(false, 0x07, 'PADO (Offer)', 0, RT_WAN, [acname, sname, huniq, cookie], 'PADO', 'amber')],
      },
      {
        title: 'PADR and PADS',
        desc: 'Request a session — get an ID',
        detail:
          'The router requests a session from that BRAS (echoing the cookie), and the Session-confirmation assigns session ID 0x2a1f. From here on every frame uses EtherType 0x8864 and carries that ID.',
        facts: [['Session ID', hex(SID, 4)]],
        packets: [
          disc(true, 0x19, 'PADR (Request)', 0, BRAS_MAC, [sname, huniq, cookie], 'PADR', 'amber'),
          disc(false, 0x65, 'PADS (Session-confirmation)', SID, RT_WAN, [sname, huniq], 'PADS', 'amber'),
        ],
      },
      {
        title: 'LCP',
        desc: 'Agree on the link',
        detail:
          'PPP starts with the Link Control Protocol. Each side proposes options — a 1492-byte MRU, a random magic number to detect loops — and the BRAS says it wants PAP for the login. Each side acknowledges the other’s request.',
        facts: [
          ['MRU', '1492'],
          ['Auth', 'PAP'],
        ],
        packets: [
          lcp(true, 1, 'Configure-Request', 1, lcpR),
          lcp(false, 1, 'Configure-Request', 1, lcpB),
          lcp(true, 2, 'Configure-Ack', 1, lcpB),
          lcp(false, 2, 'Configure-Ack', 1, lcpR),
        ],
      },
      {
        title: 'Log in',
        desc: 'Username and password (PAP)',
        detail:
          'The router sends the account name and password from your ISP. With PAP they travel in plain text — open the packet and you can read them. It’s only acceptable because this link is the private line between you and the ISP; CHAP avoids sending the password at all.',
        facts: [
          ['Username', user],
          ['Password', 'visible in PAP!'],
        ],
        packets: [
          pppPkt(true, 'pink', 'PAP LOGIN', `PPP PAP Authenticate-Request (Peer-ID='${user}')`, pppCtrl({
            up: true, proto: 0xc023, protoName: 'PAP', code: 1, codeName: 'Authenticate-Request', id: 1,
            opts: [
              ['Peer-ID length', `${user.length}`, [user.length]],
              ['Peer-ID', user, ascii(user)],
              ['Password length', `${pass.length}`, [pass.length]],
              ['Password', `${pass} (clear text!)`, ascii(pass)],
            ],
          })),
          pppPkt(false, 'pink', 'PAP OK', 'PPP PAP Authenticate-Ack', pppCtrl({
            up: false, proto: 0xc023, protoName: 'PAP', code: 2, codeName: 'Authenticate-Ack', id: 1,
            opts: [
              ['Message length', '8', [8]],
              ['Message', 'Login ok', ascii('Login ok')],
            ],
          })),
        ],
      },
      {
        title: 'Get an address (IPCP)',
        desc: 'Ask for 0.0.0.0, get a real IP',
        detail:
          'IPCP configures IP over the link. The router asks for address 0.0.0.0 (“please give me one”) plus DNS servers. The BRAS rejects that with a Configure-Nak containing the values to use — 198.51.100.77 — and the router asks again with those, which is acknowledged.',
        facts: [
          ['Public IP', IP],
          ['DNS', '8.8.8.8, 1.1.1.1'],
        ],
        packets: [
          ipcp(true, 1, 'Configure-Request', 1, [ipOpt('0.0.0.0'), ...dnsOpts('0.0.0.0', '0.0.0.0')], 'IPCP REQ'),
          ipcp(false, 3, 'Configure-Nak', 1, [ipOpt(IP), ...dnsOpts('8.8.8.8', '1.1.1.1')], 'IPCP NAK'),
          ipcp(true, 1, 'Configure-Request', 2, [ipOpt(IP), ...dnsOpts('8.8.8.8', '1.1.1.1')], 'IPCP REQ'),
          ipcp(false, 2, 'Configure-Ack', 2, [ipOpt(IP), ...dnsOpts('8.8.8.8', '1.1.1.1')], 'IPCP ACK'),
        ],
      },
      {
        title: 'Online',
        desc: 'IP packets inside PPP inside Ethernet',
        detail:
          'Now ordinary IP traffic flows. Each packet is wrapped in a 6-byte PPPoE header and a 2-byte PPP protocol field, which is why PPPoE links use an MTU of 1492 instead of 1500.',
        facts: [['Overhead', '8 bytes per packet']],
        packets: [dataPkt],
      },
    ],
    outro: {
      title: 'Logged in',
      text: 'Four discovery frames found the ISP, LCP set up the link, PAP logged in and IPCP handed out a public address. If the router stops answering LCP echo requests, the ISP tears the session down with a PADT.',
      facts: [
        ['Session', hex(SID, 4)],
        ['Public IP', IP],
      ],
    },
  });
}

/* ================================================================ RADIUS / 802.1X */

function buildRadius() {
  const SSID = 'CorpWiFi';
  const userId = 'alice@corp.example';
  const AP_IP = '10.0.0.2';
  const RAD_IP = '10.0.0.5';
  const AP_WIRED = '02:5e:a1:44:9c:01';
  const RAD_MAC = '00:50:56:a3:12:7f';
  const STATE = rand('radstate', 16);

  const air = (up: boolean, color: PacketColor, label: string, info: string, write: (w: Writer) => void, proto = 'EAP') =>
    rawPkt({ from: up ? 'client' : 'ap', to: up ? 'ap' : 'client', color, label, proto, info, src: up ? CL : BSSID, dst: up ? BSSID : CL, write });

  const eapReqId: EapSpec = { code: 1, id: 1, type: 1 };
  const eapRespId: EapSpec = { code: 2, id: 1, type: 1, data: ascii(userId), dataName: 'Identity', dataValue: userId };
  const peapStart: EapSpec = { code: 1, id: 2, type: 25, data: [0x20], dataName: 'Flags', dataValue: '0x20 (Start)' };
  const tlsHello = [0x00, ...rand('peaphello', 160)];
  const peapHello: EapSpec = { code: 2, id: 2, type: 25, data: tlsHello, dataName: 'TLS data', dataValue: 'Flags 0x00 + TLS Client Hello (161 bytes)' };
  const eapSuccess: EapSpec = { code: 3, id: 9 };

  const common = (id: number): Avp[] => [
    ['User-Name', userId, 1, ascii(userId)],
    ['NAS-IP-Address', AP_IP, 4, ipb(AP_IP)],
    ['NAS-Port-Type', 'Wireless-802.11 (19)', 61, [0, 0, 0, 19]],
    ['Called-Station-Id', `02-5E-A1-44-9C-10:${SSID}`, 30, ascii(`02-5E-A1-44-9C-10:${SSID}`)],
    ['Calling-Station-Id', '3C-22-FB-7A-10-4E', 31, ascii('3C-22-FB-7A-10-4E')],
    ['Framed-MTU', '1400', 12, [0, 0, 0x05, 0x78]],
  ];
  const msgAuth: Avp = ['Message-Authenticator', 'HMAC-MD5 (16 bytes)', 80, rand('msgauth', 16)];
  const eapAvp = (e: EapSpec): Avp => ['EAP-Message', `EAP ${eapLabel(e)}`, 79, eapBytes(e)];

  const rad = (up: boolean, code: number, id: number, attrs: Avp[], label: string, info: string) =>
    udp({
      from: up ? 'ap' : 'radius', to: up ? 'radius' : 'ap', sport: up ? 50112 : 1812, dport: up ? 1812 : 50112,
      src: up ? AP_IP : RAD_IP, dst: up ? RAD_IP : AP_IP, srcMac: up ? AP_WIRED : RAD_MAC, dstMac: up ? RAD_MAC : AP_WIRED,
      color: 'amber', label, proto: 'RADIUS', info, app: radius(code, id, attrs),
    });

  const vsa = (vendorType: number, name: string): Avp => [
    `Vendor-Specific (Microsoft) · ${name}`,
    '34 bytes, encrypted with the shared secret',
    26,
    [0, 0, 0x01, 0x37, vendorType, 34, ...rand('mppe' + vendorType, 32)],
  ];

  return lesson({
    id: 'radius',
    name: 'RADIUS',
    title: 'Wi-Fi logins',
    layer: 2,
    tagline: 'Enterprise Wi-Fi: your own username, checked by a central server.',
    nodes: [
      { id: 'client', x: 12, y: 58 },
      { id: 'ap', x: 48, y: 58, label: 'Office access point', ip: AP_IP },
      { id: 'radius', x: 84, y: 58 },
    ],
    links: [
      ['client', 'ap'],
      ['ap', 'radius'],
    ],
    legend: [
      ['blue', 'Association'],
      ['violet', 'EAP over the air'],
      ['amber', 'RADIUS'],
      ['teal', '4-way handshake'],
    ],
    overview: {
      full: 'RADIUS with IEEE 802.1X (WPA2/3-Enterprise)',
      description:
        'Offices don’t share one Wi-Fi password. With 802.1X each person logs in with their own account. The access point doesn’t check the password itself: it relays EAP messages between the laptop and a RADIUS server, which verifies the user inside a TLS tunnel and, on success, hands the access point a unique key for that user.',
      facts: [
        ['Layer', 'Data link (2) + UDP'],
        ['RADIUS port', 'UDP 1812'],
        ['Method here', 'PEAP (EAP inside TLS)'],
        ['AKM', '802.1X (00-0F-AC:1)'],
        ['Spec', 'RFC 2865, RFC 3579, IEEE 802.1X'],
      ],
    },
    steps: [
      {
        title: 'Join CorpWiFi',
        desc: 'Associate with an Enterprise network',
        detail:
          'The laptop associates as usual, but the RSN element says the key management is 802.1X rather than a pre-shared key. The access point now blocks every frame from the laptop except EAPOL until a login succeeds.',
        facts: [
          ['AKM', '802.1X (Enterprise)'],
          ['Port state', 'blocked except EAPOL'],
        ],
        packets: [
          air(true, 'blue', 'ASSOC REQ', `Association Request, SSID="${SSID}"`, assocReq(SSID, 1), '802.11'),
          air(false, 'blue', 'ASSOC RESP', 'Association Response, AID 1, Successful', assocResp(), '802.11'),
        ],
      },
      {
        title: 'Who are you?',
        desc: 'EAP Identity',
        detail:
          'The access point (the “authenticator”) sends EAP Request/Identity. The laptop answers with the user name. This outer identity is visible on the air; many setups send just “anonymous@corp.example” here and the real name only inside the tunnel.',
        packets: [
          air(false, 'violet', 'IDENTITY?', 'Request, Identity', eapOverWlan(false, 1270, eapReqId)),
          air(true, 'violet', 'IDENTITY', `Response, Identity (${userId})`, eapOverWlan(true, 50, eapRespId)),
        ],
      },
      {
        title: 'Ask the RADIUS server',
        desc: 'Access-Request → Access-Challenge',
        detail:
          'The access point wraps the EAP message in a RADIUS Access-Request to UDP 1812, adding who and where: its own IP, the SSID and the laptop’s MAC. The two share a secret that signs every packet. The server picks PEAP and replies with a Challenge plus a State value to keep track of this login.',
        facts: [
          ['Shared secret', 'between AP and server'],
          ['Method chosen', 'PEAP'],
        ],
        packets: [
          rad(true, 1, 41, [...common(41), eapAvp(eapRespId), msgAuth], 'ACCESS-REQ', 'Access-Request id=41'),
          rad(false, 11, 41, [eapAvp(peapStart), ['State', '16 bytes (login session)', 24, STATE], msgAuth], 'CHALLENGE', 'Access-Challenge id=41'),
        ],
      },
      {
        title: 'Build a TLS tunnel',
        desc: 'PEAP start, TLS hello',
        detail:
          'The access point passes the PEAP start to the laptop, which begins a TLS handshake with the RADIUS server — relayed one EAP message at a time. The laptop checks the server’s certificate, so it won’t hand a password to a fake access point. (Several more round trips finish the tunnel.)',
        packets: [
          air(false, 'violet', 'PEAP START', 'Request, PEAP (Start)', eapOverWlan(false, 1271, peapStart)),
          air(true, 'violet', 'TLS HELLO', 'Response, PEAP (TLS Client Hello)', eapOverWlan(true, 51, peapHello)),
          rad(true, 1, 42, [...common(42), eapAvp(peapHello), ['State', '16 bytes (echoed)', 24, STATE], msgAuth], 'ACCESS-REQ', 'Access-Request id=42'),
        ],
      },
      {
        title: 'Access-Accept',
        desc: 'Password checked, key delivered',
        detail:
          'Inside the tunnel the laptop proves the password (with MSCHAPv2). The server answers Access-Accept carrying EAP-Success and, encrypted with the shared secret, the PMK for this user in the MS-MPPE key attributes. The access point forwards the EAP-Success to the laptop.',
        facts: [
          ['Result', 'Access-Accept'],
          ['Per-user key', 'MS-MPPE-Recv/Send-Key'],
        ],
        packets: [
          rad(false, 2, 48, [eapAvp(eapSuccess), vsa(17, 'MS-MPPE-Recv-Key'), vsa(16, 'MS-MPPE-Send-Key'), ['Session-Timeout', '28800 s', 27, [0, 0, 0x70, 0x80]], msgAuth], 'ACCEPT', 'Access-Accept id=48'),
          air(false, 'violet', 'SUCCESS', 'Success', eapOverWlan(false, 1278, eapSuccess)),
        ],
      },
      {
        title: '4-way handshake',
        desc: 'Keys unique to Alice',
        detail:
          'Both laptop and access point now hold the same PMK — the laptop derived it from the TLS session, the AP received it from RADIUS. The usual 4-way handshake turns it into session keys, and the port opens. Nobody else on CorpWiFi shares these keys.',
        packets: fourWay('radius'),
      },
    ],
    outro: {
      title: 'Logged in to CorpWiFi',
      text: 'The access point never saw Alice’s password: it only relayed EAP and trusted the RADIUS server’s verdict. Disable her account on the server and she can’t connect anywhere in the building.',
      facts: [
        ['RADIUS packets', '4 shown'],
        ['Per-user keys', 'yes'],
      ],
    },
  });
}

/* ================================================================ Captive portal */

function buildPortal() {
  // 1. the OS connectivity check, intercepted by the hotspot gateway
  const c1 = tcp('client', 'detect', 51010, 80);
  const [syn, synack, ack] = c1.handshake();
  syn.to = 'router';
  synack.from = 'router';
  ack.to = 'router';
  const check = c1.send('a', http(['GET /generate_204 HTTP/1.1', 'Host: connectivitycheck.example.com', 'User-Agent: ConnectivityCheck/1.0']), {
    label: 'CHECK', proto: 'HTTP', info: 'GET /generate_204 HTTP/1.1', color: 'amber',
  });
  check.to = 'router';
  const redirect = c1.send(
    'b',
    http([
      'HTTP/1.1 302 Found',
      'Location: http://192.168.1.1/login?return=http%3A%2F%2Fconnectivitycheck.example.com%2F',
      'Cache-Control: no-store',
      'Content-Length: 0',
    ]),
    { label: '302', proto: 'HTTP', info: 'HTTP/1.1 302 Found (Location: http://192.168.1.1/login)', color: 'red' },
  );
  redirect.from = 'router';

  // 2. the login page on the gateway
  const c2 = tcp('client', 'router', 51012, 80);
  const hs2 = c2.handshake();
  const page = '<form method="post" action="/login"><h1>Welcome to Cafe WiFi</h1><label><input type="checkbox" name="accept"> I accept the terms</label><button>Connect</button></form>';
  const getLogin = c2.send('a', http(['GET /login?return=http%3A%2F%2Fconnectivitycheck.example.com%2F HTTP/1.1', 'Host: 192.168.1.1']), {
    label: 'GET /login', proto: 'HTTP', info: 'GET /login HTTP/1.1', color: 'amber',
  });
  const loginPage = c2.send('b', http(['HTTP/1.1 200 OK', 'Content-Type: text/html', `Content-Length: ${page.length}`], page), {
    label: 'LOGIN PAGE', proto: 'HTTP', info: 'HTTP/1.1 200 OK (text/html)', color: 'violet',
  });
  const body = 'accept=on&mac=3c%3A22%3Afb%3A7a%3A10%3A4e';
  const post = c2.send(
    'a',
    http(['POST /login HTTP/1.1', 'Host: 192.168.1.1', 'Content-Type: application/x-www-form-urlencoded', `Content-Length: ${body.length}`], body),
    { label: 'POST /login', proto: 'HTTP', info: 'POST /login HTTP/1.1 (accept=on)', color: 'amber' },
  );
  const welcome = '<h1>You are online</h1>';
  const ok = c2.send('b', http(['HTTP/1.1 200 OK', 'Content-Type: text/html', `Content-Length: ${welcome.length}`], welcome), {
    label: 'ONLINE', proto: 'HTTP', info: 'HTTP/1.1 200 OK (You are online)', color: 'green',
  });

  // 3. the check again — now it really reaches the internet
  const c3 = tcp('client', 'detect', 51014, 80);
  const hs3 = c3.handshake();
  const check2 = c3.send('a', http(['GET /generate_204 HTTP/1.1', 'Host: connectivitycheck.example.com', 'User-Agent: ConnectivityCheck/1.0']), {
    label: 'CHECK', proto: 'HTTP', info: 'GET /generate_204 HTTP/1.1', color: 'amber',
  });
  const r204 = c3.send('b', http(['HTTP/1.1 204 No Content', 'Content-Length: 0']), {
    label: '204', proto: 'HTTP', info: 'HTTP/1.1 204 No Content', color: 'green',
  });

  return lesson({
    id: 'portal',
    name: 'Captive Portal',
    title: 'Hotspot sign-in',
    layer: 7,
    tagline: 'Why café Wi-Fi pops up a login page.',
    nodes: [
      { id: 'client', x: 9, y: 62 },
      { id: 'router', x: 31, y: 62, label: 'Hotspot gateway' },
      { id: 'internet', x: 55, y: 62 },
      { id: 'detect', x: 84, y: 40 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
      ['internet', 'detect'],
    ],
    legend: [
      ['green', 'TCP / success'],
      ['amber', 'Request'],
      ['red', 'Redirect'],
      ['violet', 'Login page'],
    ],
    overview: {
      full: 'Captive portals (Wi-Fi sign-in pages)',
      description:
        'Public hotspots let you join the Wi-Fi freely but hold your traffic hostage until you accept their terms. The gateway intercepts web requests and redirects them to its own login page. Phones and laptops detect this automatically by fetching a known URL that should return “204 No Content” — if anything else comes back, they show a “Sign in to network” prompt.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Detection', 'HTTP probe expecting 204'],
        ['Trick', 'gateway answers for any site'],
        ['Allow-list by', 'client MAC address'],
        ['Spec', 'RFC 8952, RFC 8910'],
      ],
    },
    steps: [
      {
        title: 'Joined, but offline',
        desc: 'Wi-Fi works, the internet doesn’t',
        detail:
          'The laptop joined “Cafe WiFi” (an open network), got an address with DHCP and can resolve names. But the gateway drops or intercepts everything until this MAC address is on its allow-list.',
        facts: [
          ['IP address', '192.168.1.10'],
          ['Allow-listed', 'no'],
        ],
        focus: ['client', 'router'],
      },
      {
        title: 'Connectivity check',
        desc: 'Fetch a page that should be empty',
        detail:
          'As soon as it joins, the operating system requests http://connectivitycheck.example.com/generate_204, a page that always answers 204 with no body. It must be plain HTTP: the gateway needs to be able to tamper with it. The TCP handshake already gets answered by the gateway, pretending to be the real server.',
        packets: [syn, synack, ack, check],
      },
      {
        title: 'Redirected',
        desc: 'A 302 instead of a 204',
        detail:
          'The gateway replies — with the real server’s IP address as the source — “302 Found, go to http://192.168.1.1/login”. The OS sees it didn’t get its 204, concludes there’s a captive portal and opens a mini-browser.',
        facts: [
          ['Expected', '204 No Content'],
          ['Got', '302 → /login'],
        ],
        packets: [redirect],
      },
      {
        title: 'The login page',
        desc: 'Served by the gateway itself',
        detail:
          'The mini-browser follows the redirect to the gateway’s own web server and loads the sign-in page with the terms and conditions.',
        packets: [...hs2, getLogin, loginPage],
      },
      {
        title: 'Accept the terms',
        desc: 'POST, and your MAC is allow-listed',
        detail:
          'Ticking the box and pressing Connect sends a form POST. The gateway adds the laptop’s MAC address to its allow-list (often for a few hours) and stops intercepting its traffic.',
        facts: [['Allow-listed', '3c:22:fb:7a:10:4e']],
        packets: [post, ok],
      },
      {
        title: 'Online',
        desc: 'The check finally gets its 204',
        detail:
          'The OS repeats the connectivity check. This time the connection really travels to the internet and the server answers 204 No Content. The “Sign in” prompt disappears and apps start working.',
        packets: [...hs3, check2, r204],
      },
    ],
    outro: {
      title: 'Online',
      text: 'One redirected probe told the laptop it was behind a portal, one form submission put its MAC on the allow-list, and a clean 204 confirmed real internet access. Newer networks can announce the portal URL via DHCP (RFC 8910) instead of hijacking requests.',
      facts: [
        ['Hijacked requests', '1'],
        ['Final check', '204 No Content'],
      ],
    },
  });
}

export const PACK: Lesson[] = [buildEthernet(), buildWifi(), buildWpa3(), buildPppoe(), buildRadius(), buildPortal()];
