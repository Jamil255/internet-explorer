// Pack C — network-layer lessons: IP, IPv6, BGP, IGMP, WireGuard, IPsec.
import {
  ascii,
  checksum,
  ethHeader,
  hex,
  hexStr,
  ip6b,
  ipb,
  macb,
  rand,
  rawFrame,
  u16,
  u32,
  zeros,
  type AppWriter,
  type L4,
} from '@/engine/bytes';
import { registerNodes } from '@/engine/nodes';
import type { Lesson } from '@/engine/types';
import { IP, MAC, lesson, packet, tcp, udp } from './kit';

registerNodes({
  web6: { label: 'www.example.com', icon: 'globe', ip: '2001:db8:200::10' },
  edge: { label: 'Your edge router', icon: 'building', ip: '192.0.2.1' },
  ispa: { label: 'ISP-A · AS 64510', icon: 'router', ip: '192.0.2.2' },
  ispb: { label: 'ISP-B · AS 64520', icon: 'router', ip: '198.51.100.9' },
  origin: { label: 'AS 64496 · 203.0.113.0/24', icon: 'globe', ip: '203.0.113.1' },
  stb: { label: 'TV box', icon: 'tv', ip: '192.168.1.20' },
  iptv: { label: 'IPTV headend', icon: 'video', ip: '203.0.113.80' },
  wg: { label: 'WireGuard server', icon: 'shieldcheck', ip: '203.0.113.60' },
  vpngw: { label: 'Office VPN gateway', icon: 'shield', ip: '203.0.113.70' },
  files: { label: 'Office file server', icon: 'hdd', ip: '10.20.0.5' },
});

type F = [string, string, number[]];
const ROUTER_WAN_MAC = 'a4:91:b1:0c:22:02';
const WAN_IP = '198.51.100.7';

/** One app-layer block made of pre-built fields. */
const block =
  (name: string, summary: string, fields: F[]): AppWriter =>
  (w) => {
    w.begin('app', name);
    for (const [n, v, b] of fields) w.f(n, v, b);
    w.end(summary);
  };

/** A TCP handshake segment written by hand (for packets that cross a NAT or tunnel). */
const tcpL4 = (sport: number, dport: number, flags: 'S' | 'SA', seq: number, ack = 0): L4 => ({
  kind: 'tcp',
  sport,
  dport,
  flags,
  mss: true,
  seq,
  ack,
  relSeq: 0,
  relAck: flags === 'SA' ? 1 : undefined,
});

/* ================================================================== IP */

function arpFrame(op: 1 | 2, sMac: string, sIp: string, tMac: string, tIp: string, dstMac: string, pad = false) {
  return rawFrame((w) => {
    ethHeader(w, dstMac, sMac, 0x0806, 'ARP');
    w.begin('arp', 'Address Resolution Protocol');
    w.f('Hardware type', 'Ethernet (1)', u16(1));
    w.f('Protocol type', 'IPv4 (0x0800)', u16(0x0800));
    w.f('Hardware size', 6, [6]);
    w.f('Protocol size', 4, [4]);
    w.f('Opcode', op === 1 ? 'request (1)' : 'reply (2)', u16(op));
    w.f('Sender MAC', sMac, macb(sMac));
    w.f('Sender IP', sIp, ipb(sIp));
    w.f('Target MAC', op === 1 ? '00:00:00:00:00:00 (unknown)' : tMac, macb(tMac));
    w.f('Target IP', tIp, ipb(tIp));
    if (pad) w.f('Ethernet padding', '18 zero bytes (60-byte minimum frame)', zeros(18));
    w.end(op === 1 ? `Who has ${tIp}? Tell ${sIp}` : `${sIp} is at ${sMac}`);
  });
}

function buildIp(): Lesson {
  const ISN_C = 0x1f2e3d4c;
  const ISN_S = 0x7a6b5c4d;
  const C = IP('client');
  const S = IP('web');

  const arpReq = packet({
    from: 'client', to: 'router', color: 'slate', label: 'ARP WHO-HAS', proto: 'ARP',
    src: MAC.client, dst: 'Broadcast',
    info: `Who has ${IP('router')}? Tell ${C}`,
    raw: arpFrame(1, MAC.client, C, '00:00:00:00:00:00', IP('router'), MAC.bcast),
  });
  const arpRep = packet({
    from: 'router', to: 'client', color: 'slate', label: 'ARP REPLY', proto: 'ARP',
    src: MAC.router, dst: MAC.client,
    info: `${IP('router')} is at ${MAC.router}`,
    raw: arpFrame(2, MAC.router, IP('router'), MAC.client, C, MAC.client, true),
  });
  const synOut = packet({
    from: 'client', to: 'router', color: 'blue', label: 'SYN → GW', proto: 'TCP',
    src: C, dst: S, ttl: 64,
    info: '50432 → 443 [SYN] Seq=0 Len=0 (to the gateway’s MAC)',
    l4: tcpL4(50432, 443, 'S', ISN_C),
  });
  const synNat = packet({
    from: 'router', to: 'isp', color: 'amber', label: 'SYN (NAT)', proto: 'TCP',
    src: WAN_IP, dst: S, ttl: 63, srcMac: ROUTER_WAN_MAC, dstMac: MAC.isp,
    info: `61001 → 443 [SYN] Seq=0 Len=0 (source rewritten to ${WAN_IP}:61001)`,
    l4: tcpL4(61001, 443, 'S', ISN_C),
  });
  const synArrive = packet({
    from: 'isp', to: 'web', color: 'amber', label: 'SYN TTL 58', proto: 'TCP',
    src: WAN_IP, dst: S, ttl: 58, srcMac: '00:1b:21:9e:44:11', dstMac: '00:50:56:aa:10:01',
    info: '61001 → 443 [SYN] Seq=0 Len=0 (arrived after 6 routers)',
    l4: tcpL4(61001, 443, 'S', ISN_C),
  });
  const synAckWan = packet({
    from: 'web', to: 'router', color: 'violet', label: 'SYN-ACK', proto: 'TCP',
    src: S, dst: WAN_IP, ttl: 52, srcMac: MAC.isp, dstMac: ROUTER_WAN_MAC,
    info: '443 → 61001 [SYN, ACK] Seq=0 Ack=1 Len=0',
    l4: tcpL4(443, 61001, 'SA', ISN_S, ISN_C + 1),
  });
  const synAckLan = packet({
    from: 'router', to: 'client', color: 'violet', label: 'SYN-ACK (UN-NAT)', proto: 'TCP',
    src: S, dst: C, ttl: 51,
    info: `443 → 50432 [SYN, ACK] Seq=0 Ack=1 Len=0 (destination restored to ${C})`,
    l4: tcpL4(443, 50432, 'SA', ISN_S, ISN_C + 1),
  });

  return lesson({
    id: 'ip',
    name: 'IP',
    title: 'Addressing & routing',
    layer: 3,
    tagline: 'How a packet finds a computer on the other side of the world.',
    nodes: [
      { id: 'client', x: 8, y: 60 },
      { id: 'router', x: 28, y: 60, label: 'Home router (NAT)' },
      { id: 'isp', x: 48, y: 60 },
      { id: 'internet', x: 68, y: 60 },
      { id: 'web', x: 89, y: 60 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'isp'],
      ['isp', 'internet'],
      ['internet', 'web'],
    ],
    legend: [
      ['slate', 'ARP'],
      ['blue', 'Inside the LAN'],
      ['amber', 'After NAT'],
      ['violet', 'Reply'],
    ],
    overview: {
      full: 'Internet Protocol (version 4)',
      description:
        'IP gives every device an address and moves packets between networks one hop at a time. Each router only decides the next hop; nobody plans the whole route. Along the way the Ethernet addresses change at every hop, the TTL counts down, and a home router quietly swaps your private address for its public one (NAT).',
      facts: [
        ['Layer', 'Network (3)'],
        ['Address size', '32 bits (4.3 billion)'],
        ['Header', '20–60 bytes'],
        ['Delivery', 'Best effort, hop by hop'],
        ['Helpers', 'ARP, ICMP, NAT'],
        ['Spec', 'RFC 791'],
      ],
    },
    steps: [
      {
        title: 'Local or remote?',
        desc: 'Compare the network parts of two addresses',
        detail:
          'The laptop is 192.168.1.10 with mask 255.255.255.0, so its network is 192.168.1.0/24. The server 203.0.113.10 is outside that range. Rule: anything not on my own network goes to the default gateway, 192.168.1.1.',
        facts: [
          ['My network', '192.168.1.0/24'],
          ['Destination', S],
          ['Verdict', 'Remote → use the gateway'],
        ],
        focus: ['client'],
      },
      {
        title: 'ARP: who is the gateway?',
        desc: 'IP address → MAC address',
        detail:
          'Ethernet frames are delivered by MAC address, but the laptop only knows the router’s IP. It broadcasts an ARP request to everyone on the LAN; only the router answers with its MAC. The answer is cached for a few minutes.',
        facts: [
          ['Request to', 'ff:ff:ff:ff:ff:ff'],
          ['Answer', MAC.router],
          ['EtherType', '0x0806'],
        ],
        packets: [arpReq, arpRep],
      },
      {
        title: 'Send the packet',
        desc: 'IP to the server, Ethernet to the router',
        detail:
          'Here is the key trick of routing: the IP header says “to 203.0.113.10”, but the Ethernet header says “to the router’s MAC”. The packet starts with a TTL of 64. (It’s the first TCP segment of an HTTPS connection.)',
        facts: [
          ['IP destination', S],
          ['MAC destination', MAC.router],
          ['TTL', '64'],
        ],
        packets: [synOut],
      },
      {
        title: 'NAT at the router',
        desc: 'A private address can’t travel the internet',
        detail:
          '192.168.x.x addresses are private and are reused in millions of homes. The router rewrites the source to its own public address and a free port, remembers the mapping in its NAT table, recomputes the checksums and lowers the TTL to 63.',
        facts: [
          ['Inside', `${C}:50432`],
          ['Outside', `${WAN_IP}:61001`],
          ['TTL', '63'],
        ],
        packets: [synNat],
      },
      {
        title: 'Hop by hop',
        desc: 'Each router picks only the next step',
        detail:
          'Every router looks up the destination in its routing table, chooses the most specific matching route, wraps the packet in a new link-layer frame and subtracts one from the TTL. After six routers the packet reaches the server with TTL 58. If TTL ever hit 0, the packet would be dropped.',
        facts: [
          ['Routers crossed', '6'],
          ['TTL on arrival', '58'],
          ['Lookup rule', 'Longest prefix match'],
        ],
        packets: [synArrive],
      },
      {
        title: 'The reply comes home',
        desc: 'NAT runs in reverse',
        detail:
          'The server answers 198.51.100.7:61001 — it never learns the laptop’s private address. The router finds that port in its NAT table, rewrites the destination back to 192.168.1.10:50432 and forwards it on the LAN.',
        packets: [synAckWan, synAckLan],
      },
    ],
    outro: {
      title: 'There and back',
      text: 'The IP addresses stayed (almost) the same end to end, while MAC addresses changed at every hop and NAT swapped the private address at the edge. No router knew the full path — each one just knew the next hop.',
      facts: [
        ['Hops', '7 each way'],
        ['Address rewrites', '2 (NAT out and back)'],
      ],
    },
  });
}

/* ================================================================== IPv6 */

const C_LL = 'fe80::3e22:fbff:fe7a:104e';
const C_GUA = '2001:db8:1:0:8d2f:41c7:9b3e:1a02';
const R_LL = 'fe80::1';
const WEB6 = '2001:db8:200::10';

const sll = (mac: string): F => ['Option: source link-layer address', mac, [1, 1, ...macb(mac)]];

function buildIpv6(): Lesson {
  const ns = (target: string, solicited: string, mcastMac: string, label: string) =>
    packet({
      from: 'client', to: 'router', color: 'slate', label, proto: 'ICMPv6',
      src: '::', dst: solicited, ttl: 255, srcMac: MAC.client, dstMac: mcastMac,
      info: `Neighbor Solicitation for ${target} (duplicate address check)`,
      l4: { kind: 'icmp', type: 135, code: 0 },
      app: block('Neighbor Discovery', `Is anyone using ${target}?`, [
        ['Reserved', '0', zeros(4)],
        ['Target address', target, ip6b(target)],
      ]),
    });

  const dad1 = ns(C_LL, 'ff02::1:ff7a:104e', '33:33:ff:7a:10:4e', 'DAD (LINK-LOCAL)');
  const rs = packet({
    from: 'client', to: 'router', color: 'blue', label: 'ROUTER SOLICIT', proto: 'ICMPv6',
    src: C_LL, dst: 'ff02::2', ttl: 255, srcMac: MAC.client, dstMac: '33:33:00:00:00:02',
    info: `Router Solicitation from ${MAC.client}`,
    l4: { kind: 'icmp', type: 133, code: 0 },
    app: block('Neighbor Discovery', 'Any routers here?', [['Reserved', '0', zeros(4)], sll(MAC.client)]),
  });
  const ra = packet({
    from: 'router', to: 'client', color: 'violet', label: 'ROUTER ADVERT', proto: 'ICMPv6',
    src: R_LL, dst: 'ff02::1', ttl: 255, srcMac: MAC.router, dstMac: '33:33:00:00:00:01',
    info: 'Router Advertisement from a4:91:b1:0c:22:01 · prefix 2001:db8:1::/64',
    l4: { kind: 'icmp', type: 134, code: 0 },
    app: block('Neighbor Discovery', 'Prefix 2001:db8:1::/64, router fe80::1, DNS 2001:db8:1::53', [
      ['Current hop limit', '64', [64]],
      ['Flags', '0x00 (M=0, O=0: no DHCPv6 needed)', [0]],
      ['Router lifetime', '1800 s', u16(1800)],
      ['Reachable time', '0 (unspecified)', u32(0)],
      ['Retransmit timer', '0 (unspecified)', u32(0)],
      sll(MAC.router),
      ['Option: MTU', '1500 bytes', [5, 1, 0, 0, ...u32(1500)]],
      [
        'Option: prefix information',
        '2001:db8:1::/64 · on-link + autonomous · valid 1 day',
        [3, 4, 64, 0xc0, ...u32(86400), ...u32(14400), ...zeros(4), ...ip6b('2001:db8:1::')],
      ],
      ['Option: recursive DNS server', '2001:db8:1::53 · 1800 s', [25, 3, 0, 0, ...u32(1800), ...ip6b('2001:db8:1::53')]],
    ]),
  });
  const dad2 = ns(C_GUA, 'ff02::1:ff3e:1a02', '33:33:ff:3e:1a:02', 'DAD (GLOBAL)');
  const data = ascii('abcdefghijklmnopqrstuvwabcdefghi');
  const echo = packet({
    from: 'client', to: 'web6', color: 'amber', label: 'PING6', proto: 'ICMPv6',
    src: C_GUA, dst: WEB6, ttl: 64,
    info: 'Echo (ping) request id=0x0007, seq=1, hop limit=64',
    l4: { kind: 'icmp', type: 128, code: 0, id: 7, seq: 1, data },
  });
  const reply = packet({
    from: 'web6', to: 'client', color: 'amber', label: 'PONG6', proto: 'ICMPv6',
    src: WEB6, dst: C_GUA, ttl: 57,
    info: 'Echo (ping) reply id=0x0007, seq=1, hop limit=57',
    l4: { kind: 'icmp', type: 129, code: 0, id: 7, seq: 1, data },
  });

  return lesson({
    id: 'ipv6',
    name: 'IPv6',
    title: 'Address setup',
    layer: 3,
    tagline: 'A device configures its own global address — no DHCP, no NAT.',
    nodes: [
      { id: 'client', x: 10, y: 58, ip: C_GUA },
      { id: 'router', x: 36, y: 58, label: 'IPv6 router', ip: R_LL },
      { id: 'internet', x: 62, y: 58 },
      { id: 'web6', x: 88, y: 58 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
      ['internet', 'web6'],
    ],
    legend: [
      ['slate', 'Duplicate check'],
      ['blue', 'Solicitation'],
      ['violet', 'Advertisement'],
      ['amber', 'Ping over IPv6'],
    ],
    overview: {
      full: 'Internet Protocol version 6',
      description:
        'IPv6 has 128-bit addresses — enough that every device can have a public one. A new device builds a link-local address itself, asks the router for the network prefix, invents the rest of its address, checks nobody else has it, and is online. ARP and broadcast are gone; Neighbor Discovery (ICMPv6) and multicast replace them.',
      facts: [
        ['Layer', 'Network (3)'],
        ['Address size', '128 bits'],
        ['Header', '40 bytes, fixed'],
        ['Auto-config', 'SLAAC (RFC 4862)'],
        ['Replaces ARP', 'Neighbor Discovery'],
        ['Spec', 'RFC 8200'],
      ],
    },
    steps: [
      {
        title: 'A link-local address',
        desc: 'Made from the MAC, valid on this link only',
        detail:
          'Every IPv6 interface first gives itself an fe80:: address. This laptop builds it from its MAC 3c:22:fb:7a:10:4e: flip one bit (3c → 3e) and insert ff:fe in the middle, giving fe80::3e22:fbff:fe7a:104e. Routers never forward these addresses.',
        facts: [
          ['MAC', MAC.client],
          ['Link-local', C_LL],
        ],
        focus: ['client'],
      },
      {
        title: 'Is it taken?',
        desc: 'Duplicate Address Detection',
        detail:
          'Before using the address, the laptop sends a Neighbor Solicitation for it from the unspecified address :: to a “solicited-node” multicast group that only devices with a similar address listen to. If nobody answers within a second, the address is unique.',
        facts: [
          ['From', ':: (no address yet)'],
          ['To', 'ff02::1:ff7a:104e'],
          ['Hop limit', '255 (must be local)'],
        ],
        packets: [dad1],
      },
      {
        title: 'Router Solicitation',
        desc: '“Any routers here?”',
        detail: 'Rather than wait for the next periodic announcement, the laptop multicasts a Router Solicitation to ff02::2, the all-routers group.',
        packets: [rs],
      },
      {
        title: 'Router Advertisement',
        desc: 'Prefix, gateway, MTU and DNS in one message',
        detail:
          'The router replies to all nodes with its prefix 2001:db8:1::/64 and the “autonomous” flag, meaning “build your own address from this”. Its own link-local address becomes the default gateway, and the RDNSS option even names a DNS server.',
        facts: [
          ['Prefix', '2001:db8:1::/64'],
          ['Gateway', R_LL],
          ['DNS', '2001:db8:1::53'],
          ['MTU', '1500'],
        ],
        packets: [ra],
      },
      {
        title: 'A global address',
        desc: 'Prefix + random interface ID',
        detail:
          'The laptop combines the 64-bit prefix with a random 64-bit interface ID (random, for privacy, so it can’t be tracked by its MAC) and runs the duplicate check once more for the new global address.',
        facts: [['Global address', C_GUA]],
        packets: [dad2],
      },
      {
        title: 'Straight to the internet',
        desc: 'Ping a server over IPv6',
        detail:
          'The laptop can now reach any IPv6 host directly with its own public address — no NAT, no port mapping. The 40-byte IPv6 header has no checksum and no fragmentation fields, which keeps routers fast.',
        facts: [
          ['Destination', WEB6],
          ['NAT', 'none'],
        ],
        packets: [echo, reply],
      },
    ],
    outro: {
      title: 'Online with IPv6',
      text: 'Four multicast messages gave the laptop a unique global address, a gateway and a DNS server, without any DHCP server — and its packets reach the internet unchanged.',
      facts: [
        ['Addresses', 'link-local + global'],
        ['Config messages', '4'],
      ],
    },
  });
}

/* ================================================================== BGP */

function bgpMsg(type: number, typeName: string, body: F[], summary: string): AppWriter {
  const len = 19 + body.reduce((s, f) => s + f[2].length, 0);
  return block('Border Gateway Protocol', summary, [
    ['Marker', '16 × 0xff', new Array(16).fill(255)],
    ['Length', `${len} bytes`, u16(len)],
    ['Type', `${typeName} (${type})`, [type]],
    ...body,
  ]);
}

const bgpOpen = (as: number, id: string) =>
  bgpMsg(
    1,
    'OPEN',
    [
      ['Version', '4', [4]],
      ['My AS', String(as), u16(as)],
      ['Hold time', '90 s', u16(90)],
      ['BGP identifier', id, ipb(id)],
      ['Optional parameters length', '16 bytes', [16]],
      ['Capability: multiprotocol', 'IPv4 unicast (AFI 1, SAFI 1)', [2, 6, 1, 4, 0, 1, 0, 1]],
      ['Capability: 4-octet AS numbers', String(as), [2, 6, 65, 4, ...u32(as)]],
    ],
    `OPEN · AS ${as} · hold time 90 s`,
  );

const bgpKeepalive = () => bgpMsg(4, 'KEEPALIVE', [], 'KEEPALIVE');

function bgpUpdate(path: number[], nextHop: string) {
  const asPath = [2, path.length, ...path.flatMap((a) => u32(a))];
  const attrs: F[] = [
    ['Path attribute: ORIGIN', 'IGP', [0x40, 1, 1, 0]],
    ['Path attribute: AS_PATH', `${path.join(' ')} (${path.length} AS hops)`, [0x40, 2, asPath.length, ...asPath]],
    ['Path attribute: NEXT_HOP', nextHop, [0x40, 3, 4, ...ipb(nextHop)]],
  ];
  const attrLen = attrs.reduce((s, f) => s + f[2].length, 0);
  return bgpMsg(
    2,
    'UPDATE',
    [
      ['Withdrawn routes length', '0', u16(0)],
      ['Path attributes length', `${attrLen} bytes`, u16(attrLen)],
      ...attrs,
      ['NLRI (announced prefix)', '203.0.113.0/24', [24, 203, 0, 113]],
    ],
    `UPDATE · 203.0.113.0/24 · AS_PATH ${path.join(' ')}`,
  );
}

const bgpWithdraw = () =>
  bgpMsg(
    2,
    'UPDATE',
    [
      ['Withdrawn routes length', '4 bytes', u16(4)],
      ['Withdrawn route', '203.0.113.0/24', [24, 203, 0, 113]],
      ['Path attributes length', '0', u16(0)],
    ],
    'UPDATE · withdraw 203.0.113.0/24',
  );

function buildBgp(): Lesson {
  const a = tcp('edge', 'ispa', 50211, 179);
  const b = tcp('edge', 'ispb', 50212, 179);
  const opt = (label: string, info: string, color: 'amber' | 'slate' | 'violet' | 'red') => ({
    label,
    proto: 'BGP',
    info,
    color,
  });

  const s1 = a.handshake();
  const s2 = [
    a.send('a', bgpOpen(64500, '192.0.2.1'), opt('OPEN', 'OPEN Message · AS 64500 · ID 192.0.2.1', 'amber')),
    a.send('b', bgpOpen(64510, '192.0.2.2'), opt('OPEN', 'OPEN Message · AS 64510 · ID 192.0.2.2', 'amber')),
    a.send('a', bgpKeepalive(), opt('KEEPALIVE', 'KEEPALIVE Message', 'slate')),
    a.send('b', bgpKeepalive(), opt('KEEPALIVE', 'KEEPALIVE Message', 'slate')),
  ];
  const s3 = [
    ...b.handshake(),
    b.send('a', bgpOpen(64500, '192.0.2.1'), opt('OPEN', 'OPEN Message · AS 64500 · ID 192.0.2.1', 'amber')),
    b.send('b', bgpOpen(64520, '198.51.100.9'), opt('OPEN', 'OPEN Message · AS 64520 · ID 198.51.100.9', 'amber')),
    b.send('a', bgpKeepalive(), opt('KEEPALIVE', 'KEEPALIVE Message', 'slate')),
    b.send('b', bgpKeepalive(), opt('KEEPALIVE', 'KEEPALIVE Message', 'slate')),
  ];
  const s4 = [
    a.send('b', bgpUpdate([64510, 64496], '192.0.2.2'), opt('UPDATE', 'UPDATE Message · 203.0.113.0/24 · AS_PATH 64510 64496', 'violet')),
    b.send('b', bgpUpdate([64520, 64530, 64496], '198.51.100.9'), opt('UPDATE', 'UPDATE Message · 203.0.113.0/24 · AS_PATH 64520 64530 64496', 'violet')),
    a.ack('a'),
    b.ack('a'),
  ];
  const s6 = [a.send('b', bgpWithdraw(), opt('WITHDRAW', 'UPDATE Message · withdrawn 203.0.113.0/24', 'red')), a.ack('a')];
  const s7 = [
    b.send('a', bgpKeepalive(), opt('KEEPALIVE', 'KEEPALIVE Message', 'slate')),
    b.send('b', bgpKeepalive(), opt('KEEPALIVE', 'KEEPALIVE Message', 'slate')),
  ];

  return lesson({
    id: 'bgp',
    name: 'BGP',
    title: 'Internet routes',
    layer: 7,
    tagline: 'How networks tell each other which addresses they can reach.',
    nodes: [
      { id: 'edge', x: 14, y: 52, label: 'Your router · AS 64500' },
      { id: 'ispa', x: 50, y: 22 },
      { id: 'ispb', x: 50, y: 80 },
      { id: 'origin', x: 86, y: 52 },
    ],
    links: [
      ['edge', 'ispa'],
      ['edge', 'ispb'],
      ['ispa', 'origin'],
      ['ispb', 'origin'],
    ],
    legend: [
      ['green', 'TCP'],
      ['amber', 'OPEN'],
      ['slate', 'KEEPALIVE'],
      ['violet', 'UPDATE (announce)'],
      ['red', 'UPDATE (withdraw)'],
    ],
    overview: {
      full: 'Border Gateway Protocol',
      description:
        'The internet is about 75,000 independent networks, each with an AS number. BGP is how their border routers exchange reachability: “I can reach 203.0.113.0/24, and here is the chain of networks it goes through.” Each router picks one best path per prefix — usually the shortest AS path — and passes it on.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', 'TCP 179'],
        ['Messages', 'OPEN, UPDATE, KEEPALIVE, NOTIFICATION'],
        ['Table size', '~1 million IPv4 prefixes'],
        ['Spec', 'RFC 4271'],
      ],
    },
    steps: [
      {
        title: 'Connect to ISP-A',
        desc: 'BGP runs over plain TCP',
        detail:
          'Your network (AS 64500) buys transit from two ISPs. Its border router opens a TCP connection to ISP-A’s router on port 179. Neighbours are configured by hand — BGP never discovers peers on its own.',
        packets: s1,
      },
      {
        title: 'OPEN and KEEPALIVE',
        desc: 'Agree on the session',
        detail:
          'Each side sends OPEN with its AS number, a router ID, a hold time (90 s) and capabilities such as 4-byte AS numbers. A KEEPALIVE in each direction confirms the parameters and the session moves to Established.',
        facts: [
          ['Our AS', '64500'],
          ['Peer AS', '64510'],
          ['Hold time', '90 s'],
        ],
        packets: s2,
      },
      {
        title: 'A second neighbour',
        desc: 'Same dance with ISP-B',
        detail: 'Having two upstreams means the network stays reachable if one fails. The router builds an identical session with ISP-B (AS 64520).',
        packets: s3,
      },
      {
        title: 'Routes arrive',
        desc: 'Two UPDATEs for the same prefix',
        detail:
          'Both ISPs announce 203.0.113.0/24, which belongs to AS 64496. Via ISP-A the AS_PATH is 64510 64496; via ISP-B it is 64520 64530 64496. Every network a route passes through prepends its AS number, which also prevents loops.',
        facts: [
          ['Via ISP-A', 'AS_PATH 64510 64496'],
          ['Via ISP-B', 'AS_PATH 64520 64530 64496'],
        ],
        packets: s4,
      },
      {
        title: 'Choose the best path',
        desc: 'Shortest AS path wins (all else equal)',
        detail:
          'BGP compares candidate routes in a fixed order: local preference, then AS-path length, origin, MED and more. With no special policy, the 2-hop path through ISP-A beats the 3-hop path, so traffic to 203.0.113.0/24 leaves via ISP-A. The other route is kept as a backup.',
        facts: [
          ['Best', 'via ISP-A (2 AS hops)'],
          ['Backup', 'via ISP-B (3 AS hops)'],
        ],
        focus: ['edge', 'ispa'],
      },
      {
        title: 'A route disappears',
        desc: 'Withdrawal and instant failover',
        detail:
          'ISP-A loses its link towards AS 64496 and sends an UPDATE that withdraws the prefix. Your router immediately promotes the backup route through ISP-B — no packets to that network are lost for long.',
        facts: [['New best', 'via ISP-B']],
        packets: s6,
      },
      {
        title: 'Staying alive',
        desc: 'KEEPALIVE every 30 seconds',
        detail:
          'With nothing to update, neighbours still send KEEPALIVEs, typically every third of the hold time. If none arrives for 90 seconds, the session is torn down and every route learned over it is withdrawn.',
        packets: s7,
      },
    ],
    outro: {
      title: 'Routes in place',
      text: 'Two sessions, two announcements and one withdrawal: BGP picked the shortest path, kept a backup and switched in a moment when the first path vanished. The whole internet’s routing works this way, built on trust between neighbours.',
      facts: [
        ['Sessions', '2'],
        ['Failover', '1 withdrawal'],
      ],
    },
  });
}

/* ================================================================== IGMP */

const STB_MAC = 'b8:27:eb:44:21:9a';
const GROUP = '239.1.1.5';
const REC: Record<number, string> = { 2: 'MODE_IS_EXCLUDE', 3: 'CHANGE_TO_INCLUDE (leave)', 4: 'CHANGE_TO_EXCLUDE (join)' };

/** IGMPv3 message with a correct checksum. */
function igmp(summary: string, fields: F[]): AppWriter {
  const ck = checksum(fields.flatMap((f) => f[2]));
  return block(
    'Internet Group Management Protocol v3',
    summary,
    fields.map(([n, v, b]) => (n === 'Checksum' ? [n, hex(ck, 4), u16(ck)] : [n, v, b])),
  );
}

const igmpReport = (recType: number) =>
  igmp(`Report · ${REC[recType]} ${GROUP}`, [
    ['Type', 'Membership Report (0x22)', [0x22]],
    ['Reserved', '0', [0]],
    ['Checksum', 'pending', [0, 0]],
    ['Reserved', '0', [0, 0]],
    ['Number of group records', '1', u16(1)],
    ['Group record', `${REC[recType]} · ${GROUP} · 0 sources`, [recType, 0, 0, 0, ...ipb(GROUP)]],
  ]);

const igmpQuery = () =>
  igmp('General query', [
    ['Type', 'Membership Query (0x11)', [0x11]],
    ['Max response time', '10.0 s', [100]],
    ['Checksum', 'pending', [0, 0]],
    ['Group address', '0.0.0.0 (general query)', ipb('0.0.0.0')],
    ['S · QRV', '0 · 2', [0x02]],
    ['Query interval (QQIC)', '125 s', [125]],
    ['Number of sources', '0', u16(0)],
  ]);

function tsBurst(n: number): AppWriter {
  return (w) => {
    w.begin('app', 'MPEG transport stream');
    for (let i = 0; i < 7; i++) {
      const cc = (n * 7 + i) & 15;
      w.f(`TS packet ${i + 1}`, `sync 0x47 · PID 0x0100 (video) · CC ${cc}`, [0x47, 0x01, 0x00, 0x10 | cc, ...rand(`ts${n}-${i}`, 184)]);
    }
    w.end('7 × 188-byte TS packets of video');
  };
}

function buildIgmp(): Lesson {
  const raw: L4 = { kind: 'raw', proto: 2, name: 'IGMP' };
  const report = (from: 'stb' | 'router', recType: number, label: string, info: string) =>
    packet({
      from, to: from === 'stb' ? 'router' : 'isp', color: recType === 3 ? 'red' : 'blue', label, proto: 'IGMPv3',
      src: from === 'stb' ? IP('stb') : WAN_IP, dst: '224.0.0.22', ttl: 1, df: false,
      srcMac: from === 'stb' ? STB_MAC : ROUTER_WAN_MAC, dstMac: '01:00:5e:00:00:16',
      info, l4: raw, app: igmpReport(recType),
    });
  const stream = (n: number) =>
    udp({
      from: 'iptv', to: 'stb', sport: 5000, dport: 5004, color: 'violet', label: `VIDEO ${n}`, proto: 'MPEG TS',
      src: IP('iptv'), dst: GROUP, ttl: 58, df: false, srcMac: MAC.router, dstMac: '01:00:5e:01:01:05',
      info: `${IP('iptv')} → ${GROUP} · 1316 bytes of video (7 TS packets)`,
      app: tsBurst(n),
    });
  const query = packet({
    from: 'router', to: 'stb', color: 'slate', label: 'QUERY', proto: 'IGMPv3',
    src: IP('router'), dst: '224.0.0.1', ttl: 1, df: false, srcMac: MAC.router, dstMac: '01:00:5e:00:00:01',
    info: 'Membership Query, general', l4: raw, app: igmpQuery(),
  });

  return lesson({
    id: 'igmp',
    name: 'IGMP',
    title: 'Multicast TV',
    layer: 3,
    tagline: 'One stream, sent once, watched by many.',
    nodes: [
      { id: 'stb', x: 10, y: 58 },
      { id: 'router', x: 36, y: 58, label: 'Home router (IGMP proxy)' },
      { id: 'isp', x: 62, y: 58 },
      { id: 'iptv', x: 88, y: 58 },
    ],
    links: [
      ['stb', 'router'],
      ['router', 'isp'],
      ['isp', 'iptv'],
    ],
    legend: [
      ['blue', 'Join / report'],
      ['slate', 'Query'],
      ['violet', 'Multicast video'],
      ['red', 'Leave'],
    ],
    overview: {
      full: 'Internet Group Management Protocol',
      description:
        'IPTV channels are sent as multicast: the headend sends each packet once to a group address like 239.1.1.5, and routers copy it only towards networks where somebody is watching. IGMP is how a TV box tells its local router “I want this group” — and later “I’m done”.',
      facts: [
        ['Layer', 'Network (3)'],
        ['IP protocol', '2'],
        ['Group range', '224.0.0.0/4'],
        ['Reports go to', '224.0.0.22'],
        ['Spec', 'RFC 3376 (IGMPv3)'],
      ],
    },
    steps: [
      {
        title: 'One to many',
        desc: 'Group addresses, not host addresses',
        detail:
          'Sending a separate stream to every viewer would melt the ISP’s network. Instead the channel has a group address, 239.1.1.5, and the stream follows a tree of routers that copy packets only where needed. Joining a channel means joining that group.',
        facts: [
          ['Channel', GROUP],
          ['Multicast MAC', '01:00:5e:01:01:05'],
        ],
        focus: ['stb', 'iptv'],
      },
      {
        title: 'Join the group',
        desc: 'The TV box sends a membership report',
        detail:
          'Switching to the channel, the TV box sends an IGMPv3 report with a CHANGE_TO_EXCLUDE record and no sources — meaning “send me 239.1.1.5 from any source”. It goes to 224.0.0.22 with TTL 1, so it never leaves the LAN.',
        facts: [
          ['To', '224.0.0.22 (IGMPv3 routers)'],
          ['TTL', '1'],
        ],
        packets: [report('stb', 4, 'JOIN', `Membership Report / Join group ${GROUP} for any sources`)],
      },
      {
        title: 'The router joins upstream',
        desc: 'Acting as a proxy for the house',
        detail:
          'The home router has no stream for that group yet, so it sends its own report towards the ISP. The ISP’s multicast routers graft a branch onto the distribution tree that ends at this house.',
        packets: [report('router', 4, 'JOIN ↑', `Membership Report / Join group ${GROUP} (proxied upstream)`)],
      },
      {
        title: 'The stream flows',
        desc: 'UDP datagrams to the group',
        detail:
          'Video arrives as UDP datagrams addressed to 239.1.1.5, each carrying seven 188-byte MPEG transport-stream packets. There is no acknowledgement and no retransmission — a lost packet is a glitch on screen, not a delay.',
        facts: [
          ['Payload', '7 × 188 = 1316 bytes'],
          ['Transport', 'UDP, no retransmits'],
        ],
        packets: [stream(1), stream(2), stream(3)],
      },
      {
        title: 'Still watching?',
        desc: 'Periodic general query',
        detail:
          'Every 125 seconds the router asks all hosts (224.0.0.1) which groups they want, allowing up to 10 seconds to reply. The TV box answers with its current state. A group nobody reports is pruned.',
        packets: [query, report('stb', 2, 'REPORT', `Membership Report / ${GROUP} is still wanted`)],
      },
      {
        title: 'Change channel',
        desc: 'Leave, and the stream stops',
        detail:
          'Zapping away, the TV box reports CHANGE_TO_INCLUDE with an empty source list — IGMPv3’s way of saying “leave”. The router, seeing no other viewers, leaves upstream too and the stream stops crossing the ISP link.',
        packets: [
          report('stb', 3, 'LEAVE', `Membership Report / Leave group ${GROUP}`),
          report('router', 3, 'LEAVE ↑', `Membership Report / Leave group ${GROUP} (proxied upstream)`),
        ],
      },
    ],
    outro: {
      title: 'Channel changed',
      text: 'IGMP let one small box pull a multicast stream into the house and push it away again, while the headend sent each video packet only once for everyone watching.',
      facts: [
        ['Group', GROUP],
        ['IGMP messages', '6'],
      ],
    },
  });
}

/* ================================================================== WireGuard */

const WG_I = 0x8a1c3f02;
const WG_R = 0x4f77d910;
const pad16 = (n: number) => Math.ceil(n / 16) * 16;

const wgInit = () =>
  block('WireGuard', 'Handshake Initiation', [
    ['Type', 'Handshake Initiation (1)', [1]],
    ['Reserved', '0', zeros(3)],
    ['Sender index', hex(WG_I, 8), u32(WG_I)],
    ['Unencrypted ephemeral', 'X25519 public key (32 bytes)', rand('wg-ei', 32)],
    ['Encrypted static', 'laptop’s static public key (32 + 16-byte tag)', rand('wg-st', 48)],
    ['Encrypted timestamp', 'TAI64N time (12 + 16-byte tag)', rand('wg-ts', 28)],
    ['MAC1', '16 bytes, keyed with the server’s public key', rand('wg-m1', 16)],
    ['MAC2', 'zeros (no cookie needed)', zeros(16)],
  ]);

const wgResp = () =>
  block('WireGuard', 'Handshake Response', [
    ['Type', 'Handshake Response (2)', [2]],
    ['Reserved', '0', zeros(3)],
    ['Sender index', hex(WG_R, 8), u32(WG_R)],
    ['Receiver index', hex(WG_I, 8), u32(WG_I)],
    ['Unencrypted ephemeral', 'X25519 public key (32 bytes)', rand('wg-er', 32)],
    ['Encrypted nothing', 'empty payload + 16-byte tag', rand('wg-en', 16)],
    ['MAC1', '16 bytes, keyed with the laptop’s public key', rand('wg-m1r', 16)],
    ['MAC2', 'zeros (no cookie needed)', zeros(16)],
  ]);

const wgData = (receiver: number, counter: number, plain: number, what: string, seed: string) =>
  block('WireGuard', plain ? `Transport Data · counter ${counter}` : `Keepalive · counter ${counter}`, [
    ['Type', 'Transport Data (4)', [4]],
    ['Reserved', '0', zeros(3)],
    ['Receiver index', hex(receiver, 8), u32(receiver)],
    ['Counter', String(counter), [...u32(0), ...u32(counter)]],
    ['Encrypted packet', what, rand(seed, pad16(plain) + 16)],
  ]);

function buildWireguard(): Lesson {
  const ISN = 0x33a1c0de;
  const ISN_S = 0x51e0aa17;
  const wgPkt = (from: 'client' | 'wg', label: string, info: string, color: 'teal' | 'amber' | 'violet' | 'slate', app: AppWriter) =>
    udp({
      from, to: from === 'client' ? 'wg' : 'client', sport: from === 'client' ? 41414 : 51820,
      dport: from === 'client' ? 51820 : 41414, color, label, proto: 'WireGuard', info, app,
    });

  const init = wgPkt('client', 'INITIATION', `Handshake Initiation, sender=${hex(WG_I, 8)}`, 'teal', wgInit());
  const resp = wgPkt('wg', 'RESPONSE', `Handshake Response, sender=${hex(WG_R, 8)}, receiver=${hex(WG_I, 8)}`, 'teal', wgResp());
  const out = wgPkt(
    'client', 'DATA 🔒', `Transport Data, receiver=${hex(WG_R, 8)}, counter=0`, 'amber',
    wgData(WG_R, 0, 60, 'inner IPv4 packet: TCP SYN 10.8.0.2 → 203.0.113.10:443 (encrypted)', 'wg-d0'),
  );
  const innerSyn = packet({
    from: 'wg', to: 'web', color: 'green', label: 'SYN (DECRYPTED)', proto: 'TCP',
    src: IP('wg'), dst: IP('web'),
    info: '50311 → 443 [SYN] Seq=0 Len=0 (decrypted, then NATed by the server)',
    l4: tcpL4(50311, 443, 'S', ISN),
  });
  const innerSynAck = packet({
    from: 'web', to: 'wg', color: 'green', label: 'SYN-ACK', proto: 'TCP',
    src: IP('web'), dst: IP('wg'),
    info: '443 → 50311 [SYN, ACK] Seq=0 Ack=1 Len=0',
    l4: tcpL4(443, 50311, 'SA', ISN_S, ISN + 1),
  });
  const back = wgPkt(
    'wg', 'DATA 🔒', `Transport Data, receiver=${hex(WG_I, 8)}, counter=0`, 'violet',
    wgData(WG_I, 0, 60, 'inner IPv4 packet: TCP SYN-ACK 203.0.113.10 → 10.8.0.2 (encrypted)', 'wg-d1'),
  );
  const keep = wgPkt('client', 'KEEPALIVE', `Keepalive, receiver=${hex(WG_R, 8)}, counter=1`, 'slate', wgData(WG_R, 1, 0, 'empty (just the 16-byte tag)', 'wg-k'));

  return lesson({
    id: 'wireguard',
    name: 'WireGuard',
    title: 'A modern VPN',
    layer: 3,
    tagline: 'One round trip, then every packet travels sealed inside UDP.',
    nodes: [
      { id: 'client', x: 8, y: 60, label: 'Laptop (café Wi-Fi)', ip: '10.8.0.2 in the tunnel' },
      { id: 'router', x: 28, y: 60, label: 'Café router' },
      { id: 'internet', x: 49, y: 60 },
      { id: 'wg', x: 70, y: 34 },
      { id: 'web', x: 89, y: 72 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
      ['internet', 'wg'],
      ['wg', 'web'],
    ],
    legend: [
      ['teal', 'Handshake'],
      ['amber', 'Encrypted, outbound'],
      ['violet', 'Encrypted, inbound'],
      ['green', 'Decrypted inner packet'],
      ['slate', 'Keepalive'],
    ],
    overview: {
      full: 'WireGuard VPN',
      description:
        'WireGuard tunnels whole IP packets inside encrypted UDP datagrams. Peers are identified purely by public keys — no usernames, no certificates, no negotiation of cipher suites. A one-round-trip handshake derives fresh keys, and the café network sees only UDP to one address.',
      facts: [
        ['Layer', 'Network (3) tunnel'],
        ['Port', 'UDP 51820'],
        ['Crypto', 'Curve25519, ChaCha20-Poly1305, BLAKE2s'],
        ['Handshake', '1 round trip (Noise IK)'],
        ['Code size', '~4,000 lines in Linux'],
      ],
    },
    steps: [
      {
        title: 'Keys, not logins',
        desc: 'Both sides know each other’s public key',
        detail:
          'The laptop’s config lists the server’s public key and endpoint, and “AllowedIPs = 0.0.0.0/0”, meaning send everything through the tunnel. The server lists the laptop’s public key and the tunnel address 10.8.0.2. That is the whole setup.',
        facts: [
          ['Tunnel IP', '10.8.0.2/32'],
          ['AllowedIPs', '0.0.0.0/0'],
          ['Endpoint', '203.0.113.60:51820'],
        ],
        focus: ['client', 'wg'],
      },
      {
        title: 'Handshake initiation',
        desc: '148 bytes: ephemeral key, encrypted identity',
        detail:
          'The first time the laptop has a packet to send, it starts a handshake: a fresh ephemeral key, its static key encrypted to the server, and an encrypted timestamp that stops replays. MAC1 lets the server discard junk without doing any expensive crypto.',
        facts: [
          ['Size', '148 bytes'],
          ['Sender index', hex(WG_I, 8)],
        ],
        packets: [init],
      },
      {
        title: 'Handshake response',
        desc: '92 bytes and the keys are ready',
        detail:
          'The server checks the laptop’s key against its list, replies with its own ephemeral key, and both sides mix four Diffie-Hellman results into a pair of session keys. If the server doesn’t recognise the key, it stays completely silent.',
        facts: [
          ['Size', '92 bytes'],
          ['Round trips', '1'],
        ],
        packets: [resp],
      },
      {
        title: 'Packets go in the tunnel',
        desc: 'Encrypt, wrap in UDP, unwrap, forward',
        detail:
          'The laptop’s TCP SYN to www.example.com is encrypted whole — addresses, ports and all — and sent as Transport Data with a counter. The server decrypts it, sees an inner packet from 10.8.0.2, NATs it to its own address and forwards it.',
        facts: [
          ['Outer', 'UDP 192.168.1.10 → 203.0.113.60'],
          ['Inner', 'TCP 10.8.0.2 → 203.0.113.10:443'],
        ],
        packets: [out, innerSyn],
      },
      {
        title: 'The reply comes back',
        desc: 'Encrypted with the other key',
        detail: 'The website answers the VPN server; the server encrypts the reply for the laptop. The café router and anyone on the Wi-Fi only ever see opaque UDP between the laptop and 203.0.113.60.',
        packets: [innerSynAck, back],
      },
      {
        title: 'Keepalive and rekey',
        desc: 'Quiet by default, fresh keys every 2 minutes',
        detail:
          'With “PersistentKeepalive = 25” the laptop sends an empty 32-byte data packet every 25 s so the café NAT doesn’t forget the mapping. Every 2 minutes a new handshake replaces the keys, so a stolen key can’t decrypt old traffic.',
        facts: [
          ['Keepalive', '25 s (optional)'],
          ['Rekey', 'every 120 s'],
        ],
        packets: [keep],
      },
    ],
    outro: {
      title: 'Tunnel up',
      text: 'Two handshake messages and the laptop’s traffic was sealed inside UDP to one server. Compared with older VPNs there was nothing to negotiate and very little to get wrong.',
      facts: [
        ['Handshake', '148 + 92 bytes'],
        ['Overhead', '32 bytes + padding per packet'],
      ],
    },
  });
}

/* ================================================================== IPsec */

const SPI_I = rand('ike-spi-i', 8);
const SPI_R = rand('ike-spi-r', 8);
/** Generic IKEv2 payload: next payload, critical bit, length, body. */
const gen = (next: number, body: number[]) => [next, 0, ...u16(4 + body.length), ...body];

function ike(o: {
  exch: number;
  exchName: string;
  flags: number;
  msgId: number;
  knowR: boolean;
  next: [number, string];
  payloads: F[];
  natt: boolean;
  summary: string;
}): AppWriter {
  const len = 28 + o.payloads.reduce((s, f) => s + f[2].length, 0);
  const flagName = o.flags === 0x08 ? 'Initiator, request (0x08)' : o.flags === 0x20 ? 'Response (0x20)' : hex(o.flags);
  return block('Internet Key Exchange v2', o.summary, [
    ...(o.natt ? ([['Non-ESP marker', '0x00000000 (this is IKE, not ESP)', zeros(4)]] as F[]) : []),
    ['Initiator SPI', hexStr(SPI_I), SPI_I],
    ['Responder SPI', o.knowR ? hexStr(SPI_R) : '0 (not known yet)', o.knowR ? SPI_R : zeros(8)],
    ['Next payload', `${o.next[1]} (${o.next[0]})`, [o.next[0]]],
    ['Version', '2.0', [0x20]],
    ['Exchange type', `${o.exchName} (${o.exch})`, [o.exch]],
    ['Flags', flagName, [o.flags]],
    ['Message ID', String(o.msgId), u32(o.msgId)],
    ['Length', `${len} bytes`, u32(len)],
    ...o.payloads,
  ]);
}

function saInit(resp: boolean): AppWriter {
  const tr = (last: boolean, type: number, id: number, keyLen?: number) => {
    const attr = keyLen ? [0x80, 0x0e, ...u16(keyLen)] : [];
    return [last ? 0 : 3, 0, ...u16(8 + attr.length), type, 0, ...u16(id), ...attr];
  };
  const transforms = [...tr(false, 1, 20, 256), ...tr(false, 2, 5), ...tr(true, 4, 31)];
  const proposal = [0, 0, ...u16(8 + transforms.length), 1, 1, 0, 3, ...transforms];
  const who = resp ? 'r' : 'i';
  return ike({
    exch: 34,
    exchName: 'IKE_SA_INIT',
    flags: resp ? 0x20 : 0x08,
    msgId: 0,
    knowR: resp,
    next: [33, 'Security Association'],
    natt: false,
    summary: `IKE_SA_INIT ${resp ? 'response' : 'request'}`,
    payloads: [
      ['Payload: Security Association', resp ? 'chosen: AES-GCM-256, PRF-SHA256, Curve25519' : 'offer: AES-GCM-256, PRF-SHA256, Curve25519', gen(34, proposal)],
      ['Payload: Key Exchange', 'Curve25519 public key (32 bytes)', gen(40, [...u16(31), 0, 0, ...rand(`ike-ke-${who}`, 32)])],
      ['Payload: Nonce', '32 random bytes', gen(41, rand(`ike-n-${who}`, 32))],
      ['Payload: Notify', 'NAT_DETECTION_SOURCE_IP (hash of address + port)', gen(41, [0, 0, ...u16(16388), ...rand(`ike-nds-${who}`, 20)])],
      ['Payload: Notify', 'NAT_DETECTION_DESTINATION_IP (hash of address + port)', gen(0, [0, 0, ...u16(16389), ...rand(`ike-ndd-${who}`, 20)])],
    ],
  });
}

function sk(o: { exch: number; exchName: string; flags: number; msgId: number; inner: [number, string]; encLen: number; what: string; summary: string }): AppWriter {
  return ike({
    exch: o.exch,
    exchName: o.exchName,
    flags: o.flags,
    msgId: o.msgId,
    knowR: true,
    next: [46, 'Encrypted and Authenticated'],
    natt: true,
    summary: o.summary,
    payloads: [
      [
        'Payload: Encrypted (SK)',
        `${o.what} — first inner payload: ${o.inner[1]} (8-byte IV, ${o.encLen} bytes ciphertext, 16-byte ICV)`,
        gen(o.inner[0], [...rand(`sk-iv-${o.msgId}-${o.flags}`, 8), ...rand(`sk-${o.msgId}-${o.flags}`, o.encLen), ...rand(`sk-icv-${o.msgId}-${o.flags}`, 16)]),
      ],
    ],
  });
}

const esp = (spi: number, seq: number, encLen: number, what: string): AppWriter =>
  block('Encapsulating Security Payload', `ESP · SPI ${hex(spi, 8)} · seq ${seq}`, [
    ['SPI', hex(spi, 8), u32(spi)],
    ['Sequence number', String(seq), u32(seq)],
    ['IV', '8 bytes', rand(`esp-iv-${spi}-${seq}`, 8)],
    ['Encrypted data', what, rand(`esp-${spi}-${seq}`, encLen)],
    ['Integrity check value', '16 bytes (AES-GCM tag)', rand(`esp-icv-${spi}-${seq}`, 16)],
  ]);

function buildIpsec(): Lesson {
  const SPI_OUT = 0xc1a2b3d4;
  const SPI_IN = 0x7e55aa01;
  const ISN = 0x0badf00d;
  const ISN_S = 0x2468ace0;
  const VIP = '10.30.0.2';
  const u = (from: 'client' | 'vpngw', port: 500 | 4500, color: 'teal' | 'amber' | 'violet' | 'slate', label: string, proto: string, info: string, app: AppWriter) =>
    udp({ from, to: from === 'client' ? 'vpngw' : 'client', sport: port, dport: port, color, label, proto, info, app });

  const initReq = u('client', 500, 'teal', 'IKE_SA_INIT', 'ISAKMP', 'IKE_SA_INIT MID=00 Initiator Request', saInit(false));
  const initResp = u('vpngw', 500, 'teal', 'IKE_SA_INIT', 'ISAKMP', 'IKE_SA_INIT MID=00 Responder Response', saInit(true));
  const authReq = u('client', 4500, 'teal', 'IKE_AUTH 🔒', 'ISAKMP', 'IKE_AUTH MID=01 Initiator Request (UDP 4500)',
    sk({ exch: 35, exchName: 'IKE_AUTH', flags: 0x08, msgId: 1, inner: [35, 'Identification - Initiator'], encLen: 352, what: 'IDi, CERT, AUTH, CP (request address), SA, TSi, TSr', summary: 'IKE_AUTH request (encrypted)' }));
  const authResp = u('vpngw', 4500, 'teal', 'IKE_AUTH 🔒', 'ISAKMP', 'IKE_AUTH MID=01 Responder Response',
    sk({ exch: 35, exchName: 'IKE_AUTH', flags: 0x20, msgId: 1, inner: [36, 'Identification - Responder'], encLen: 304, what: 'IDr, CERT, AUTH, CP (10.30.0.2), SA, TSi, TSr', summary: 'IKE_AUTH response (encrypted)' }));
  const espOut = u('client', 4500, 'amber', 'ESP 🔒', 'ESP', `ESP (SPI=${hex(SPI_OUT, 8)}) seq=1`, esp(SPI_OUT, 1, 62, `inner packet: TCP SYN ${VIP} → 10.20.0.5:445, padding, next header 4 (IPv4)`));
  const innerSyn = packet({
    from: 'vpngw', to: 'files', color: 'green', label: 'SYN (DECRYPTED)', proto: 'TCP',
    src: VIP, dst: IP('files'), ttl: 63,
    info: '50544 → 445 [SYN] Seq=0 Len=0 (decrypted by the gateway)',
    l4: tcpL4(50544, 445, 'S', ISN),
  });
  const innerSynAck = packet({
    from: 'files', to: 'vpngw', color: 'green', label: 'SYN-ACK', proto: 'TCP',
    src: IP('files'), dst: VIP,
    info: '445 → 50544 [SYN, ACK] Seq=0 Ack=1 Len=0',
    l4: tcpL4(445, 50544, 'SA', ISN_S, ISN + 1),
  });
  const espIn = u('vpngw', 4500, 'violet', 'ESP 🔒', 'ESP', `ESP (SPI=${hex(SPI_IN, 8)}) seq=1`, esp(SPI_IN, 1, 62, `inner packet: TCP SYN-ACK 10.20.0.5 → ${VIP}, padding, next header 4 (IPv4)`));
  const nattKeep = u('client', 4500, 'slate', 'NAT KEEPALIVE', 'UDPENCAP', 'NAT-keepalive', block('NAT-T keepalive', 'One 0xff byte', [['Keepalive', '0xff', [0xff]]]));
  const dpdReq = u('client', 4500, 'slate', 'DPD 🔒', 'ISAKMP', 'INFORMATIONAL MID=02 Initiator Request (liveness check)',
    sk({ exch: 37, exchName: 'INFORMATIONAL', flags: 0x08, msgId: 2, inner: [0, 'none'], encLen: 16, what: 'empty — “are you still there?”', summary: 'INFORMATIONAL request (dead peer detection)' }));
  const dpdResp = u('vpngw', 4500, 'slate', 'DPD 🔒', 'ISAKMP', 'INFORMATIONAL MID=02 Responder Response',
    sk({ exch: 37, exchName: 'INFORMATIONAL', flags: 0x20, msgId: 2, inner: [0, 'none'], encLen: 16, what: 'empty — “yes”', summary: 'INFORMATIONAL response' }));

  return lesson({
    id: 'ipsec',
    name: 'IPsec',
    title: 'IKEv2 and ESP',
    layer: 3,
    tagline: 'Negotiate keys with IKE, then seal every packet with ESP.',
    nodes: [
      { id: 'client', x: 8, y: 60, label: 'Laptop (home)', ip: `${VIP} in the tunnel` },
      { id: 'router', x: 28, y: 60, label: 'Home router (NAT)' },
      { id: 'internet', x: 49, y: 60 },
      { id: 'vpngw', x: 70, y: 34 },
      { id: 'files', x: 89, y: 72 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
      ['internet', 'vpngw'],
      ['vpngw', 'files'],
    ],
    legend: [
      ['teal', 'IKEv2'],
      ['amber', 'ESP outbound'],
      ['violet', 'ESP inbound'],
      ['green', 'Inner packet'],
      ['slate', 'Keepalive / DPD'],
    ],
    overview: {
      full: 'IP Security (IKEv2 + ESP)',
      description:
        'IPsec is the classic standard for company VPNs. It has two parts: IKEv2, a control protocol that authenticates both ends and agrees on keys, and ESP, which encrypts and authenticates each IP packet. When a NAT sits in the way, both are carried in UDP port 4500.',
      facts: [
        ['Layer', 'Network (3)'],
        ['Ports', 'UDP 500 (IKE), 4500 (NAT-T)'],
        ['ESP', 'IP protocol 50, or inside UDP 4500'],
        ['Setup', '2 exchanges, 4 messages'],
        ['Spec', 'RFC 7296, RFC 4303'],
      ],
    },
    steps: [
      {
        title: 'Two protocols',
        desc: 'IKE for keys, ESP for data',
        detail:
          'The laptop wants to reach the office file server 10.20.0.5. First IKEv2 must build a secure control channel (the IKE SA), authenticate both ends and set up a pair of one-way ESP tunnels (Child SAs). Only then does any office traffic flow.',
        focus: ['client', 'vpngw'],
      },
      {
        title: 'IKE_SA_INIT',
        desc: 'Algorithms, key exchange, nonces',
        detail:
          'In one round trip the two ends agree on algorithms, swap Curve25519 public keys and random nonces, and derive shared keys. Each side also sends hashes of the address and port it thinks it is using — the gateway’s hashes won’t match, revealing the home NAT.',
        facts: [
          ['Port', 'UDP 500'],
          ['Cipher', 'AES-GCM-256'],
          ['NAT detected', 'yes'],
        ],
        packets: [initReq, initResp],
      },
      {
        title: 'IKE_AUTH',
        desc: 'Prove identities, get an inner address',
        detail:
          'Because of the NAT, IKE moves to port 4500 and everything is now encrypted. The laptop proves who it is (here with a certificate), asks for a configuration, and the gateway assigns 10.30.0.2. The same exchange creates the first pair of ESP SAs.',
        facts: [
          ['Port', 'UDP 4500 (NAT traversal)'],
          ['Virtual IP', VIP],
          ['ESP SPIs', `${hex(SPI_OUT, 8)} / ${hex(SPI_IN, 8)}`],
        ],
        packets: [authReq, authResp],
      },
      {
        title: 'Data in ESP',
        desc: 'Encrypted packet, sequence number, tag',
        detail:
          'The laptop’s TCP SYN to the file server is encrypted inside an ESP packet: an SPI says which SA it belongs to, a sequence number blocks replays, and a 16-byte tag detects tampering. The gateway decrypts it and forwards the plain packet into the office network.',
        facts: [
          ['SPI', hex(SPI_OUT, 8)],
          ['Sequence', '1'],
        ],
        packets: [espOut, innerSyn],
      },
      {
        title: 'The reply',
        desc: 'A separate SA for the other direction',
        detail: 'Each ESP SA is one-way, so the reply uses the gateway’s own SPI and sequence counter. The laptop decrypts it and hands the SYN-ACK to its TCP stack as if the server were on the local network.',
        packets: [innerSynAck, espIn],
      },
      {
        title: 'Keep it alive',
        desc: 'NAT keepalives and dead peer detection',
        detail:
          'Every 20 seconds the laptop sends a 1-byte NAT-keepalive so the home router keeps the UDP mapping open. Now and then an empty encrypted INFORMATIONAL exchange checks the other side is still alive; CREATE_CHILD_SA later replaces the keys before they expire.',
        packets: [nattKeep, dpdReq, dpdResp],
      },
    ],
    outro: {
      title: 'Tunnel established',
      text: 'Four IKE messages authenticated both ends and created the ESP tunnels; from then on every packet to the office was sealed, numbered and checked — even through a home NAT.',
      facts: [
        ['IKE messages', '4 to set up'],
        ['ESP overhead', '~50–60 bytes per packet'],
      ],
    },
  });
}

export const PACK: Lesson[] = [buildIp(), buildIpv6(), buildBgp(), buildIgmp(), buildWireguard(), buildIpsec()];
