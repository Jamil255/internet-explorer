import { ascii, hex } from '@/engine/bytes';
import { data, dhcp, dns, http, lines, ntp } from '@/engine/protocols';
import { IP, MAC, dnsPair, lesson, packet, tcp, udp, webNodes } from './kit';

/* ------------------------------------------------------------------ DNS */

function buildDns() {
  const name = 'www.example.com';
  const answer = '203.0.113.10';
  const q = (from: string, to: string, id: number, sport: number, rd: boolean, label: string, info: string) =>
    udp({ from, to, sport, dport: 53, color: 'blue', label, proto: 'DNS', info, app: dns({ id, rd, q: [name, 'A'] }) });

  const ask = q('client', 'dns', 0x51a0, 60211, true, 'QUERY', `Standard query ${hex(0x51a0, 4)} A ${name}`);
  const toRoot = q('dns', 'root', 0x0e11, 41870, false, 'ASK ROOT', `Standard query ${hex(0x0e11, 4)} A ${name}`);
  const rootRef = udp({
    from: 'root', to: 'dns', sport: 53, dport: 41870, color: 'violet', label: 'TRY .COM', proto: 'DNS',
    info: `Standard query response ${hex(0x0e11, 4)} NS a.gtld-servers.net`,
    app: dns({
      id: 0x0e11, response: true, q: [name, 'A'],
      ns: [{ name: 'com', type: 'NS', ttl: 172800, data: 'a.gtld-servers.net' }],
      ar: [{ name: 'a.gtld-servers.net', type: 'A', ttl: 172800, data: IP('tld') }],
    }),
  });
  const toTld = q('dns', 'tld', 0x7d42, 41871, false, 'ASK .COM', `Standard query ${hex(0x7d42, 4)} A ${name}`);
  const tldRef = udp({
    from: 'tld', to: 'dns', sport: 53, dport: 41871, color: 'violet', label: 'TRY NS', proto: 'DNS',
    info: `Standard query response ${hex(0x7d42, 4)} NS a.iana-servers.net`,
    app: dns({
      id: 0x7d42, response: true, q: [name, 'A'],
      ns: [{ name: 'example.com', type: 'NS', ttl: 172800, data: 'a.iana-servers.net' }],
      ar: [{ name: 'a.iana-servers.net', type: 'A', ttl: 172800, data: IP('auth') }],
    }),
  });
  const toAuth = q('dns', 'auth', 0x2b9c, 41872, false, 'ASK NS', `Standard query ${hex(0x2b9c, 4)} A ${name}`);
  const authAns = udp({
    from: 'auth', to: 'dns', sport: 53, dport: 41872, color: 'amber', label: 'ANSWER', proto: 'DNS',
    info: `Standard query response ${hex(0x2b9c, 4)} A ${name} A ${answer}`,
    app: dns({ id: 0x2b9c, response: true, aa: true, q: [name, 'A'], an: [{ name, type: 'A', ttl: 3600, data: answer }] }),
  });
  const reply = udp({
    from: 'dns', to: 'client', sport: 53, dport: 60211, color: 'amber', label: 'ANSWER', proto: 'DNS',
    info: `Standard query response ${hex(0x51a0, 4)} A ${name} A ${answer}`,
    app: dns({ id: 0x51a0, response: true, rd: true, ra: true, q: [name, 'A'], an: [{ name, type: 'A', ttl: 3600, data: answer }] }),
  });
  const cached = dnsPair(name, answer, 0x6e03, 60390);
  cached[1] = udp({
    from: 'dns', to: 'client', sport: 53, dport: 60390, color: 'amber', label: 'CACHED', proto: 'DNS',
    info: `Standard query response ${hex(0x6e03, 4)} A ${name} A ${answer}`,
    app: dns({ id: 0x6e03, response: true, rd: true, ra: true, q: [name, 'A'], an: [{ name, type: 'A', ttl: 3412, data: answer }] }),
  });

  return lesson({
    id: 'dns',
    name: 'DNS',
    title: 'Names to numbers',
    layer: 7,
    tagline: 'How www.example.com becomes 203.0.113.10.',
    nodes: [
      { id: 'client', x: 8, y: 58 },
      { id: 'router', x: 27, y: 58 },
      { id: 'dns', x: 49, y: 58 },
      { id: 'root', x: 80, y: 16 },
      { id: 'tld', x: 86, y: 52 },
      { id: 'auth', x: 76, y: 86 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'dns'],
      ['dns', 'root'],
      ['dns', 'tld'],
      ['dns', 'auth'],
    ],
    legend: [
      ['blue', 'Question'],
      ['violet', 'Referral'],
      ['amber', 'Answer'],
    ],
    overview: {
      full: 'Domain Name System',
      description:
        'DNS is the internet’s phone book. Your laptop asks one recursive resolver, and the resolver does the legwork: it asks a root server, then the .com servers, then the domain’s own nameserver — each pointing one step closer — and finally caches the answer so the next lookup is instant.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', '53'],
        ['Runs over', 'UDP (TCP for big answers)'],
        ['Record types', 'A, AAAA, MX, NS, TXT…'],
        ['Spec', 'RFC 1034 / 1035'],
      ],
    },
    steps: [
      {
        title: 'Ask the resolver',
        desc: 'One recursive question',
        detail:
          'The laptop sends a single query with the “recursion desired” flag set: “please find the A record for www.example.com and give me the final answer.” The resolver’s cache is empty, so it starts at the top.',
        packets: [ask],
      },
      {
        title: 'Ask a root server',
        desc: 'The top of the tree',
        detail:
          'Root servers don’t know every name, but they know who runs each top-level domain. The reply is a referral: “I don’t know, but the .com servers do — here is a.gtld-servers.net and its address.”',
        facts: [
          ['Root servers', '13 names, 1,900+ sites'],
          ['Reply', 'NS referral + glue'],
        ],
        packets: [toRoot, rootRef],
      },
      {
        title: 'Ask the .com server',
        desc: 'One level down',
        detail: 'The .com server knows which nameservers are responsible for example.com and refers the resolver there, again including their IP address as “glue”.',
        packets: [toTld, tldRef],
      },
      {
        title: 'Ask the authoritative server',
        desc: 'The source of truth',
        detail:
          'example.com’s own nameserver holds the real records. Its answer has the AA (authoritative answer) flag set and the A record 203.0.113.10 with a TTL of 3600 seconds.',
        facts: [
          ['Flag', 'AA (authoritative)'],
          ['A record', answer],
          ['TTL', '3600 s'],
        ],
        packets: [toAuth, authAns],
      },
      {
        title: 'Answer the laptop',
        desc: 'And cache it',
        detail: 'The resolver hands the final answer to the laptop and stores it for up to an hour (the TTL). The laptop caches it too.',
        packets: [reply],
      },
      {
        title: 'A second lookup',
        desc: 'Straight from the cache',
        detail:
          'A few minutes later another device asks the same question. The resolver answers instantly from cache — no root, no .com. Notice the TTL has counted down: 3412 seconds remain.',
        facts: [['Remaining TTL', '3412 s']],
        packets: cached,
      },
    ],
    outro: {
      title: 'Name resolved',
      text: 'Four round trips walked the tree from the root to the authoritative server; caching means most lookups skip all of that.',
      facts: [
        ['Cold lookup', '4 queries'],
        ['Warm lookup', '1 query'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ TCP */

const NOTES = 'TCP turns an unreliable network into a reliable stream. '.repeat(12);

function buildTcp() {
  const c = tcp('client', 'web', 51500, 8080);
  const hs = c.handshake();
  const req = c.send('a', http(['GET /notes.txt HTTP/1.1', 'Host: www.example.com']), {
    label: 'REQUEST',
    proto: 'HTTP',
    info: 'GET /notes.txt HTTP/1.1',
    color: 'amber',
  });
  const s1 = c.send(
    'b',
    http(['HTTP/1.1 200 OK', 'Content-Type: text/plain', `Content-Length: ${NOTES.length * 2}`], NOTES),
    { label: 'SEG 1', proto: 'TCP', color: 'violet' },
  );
  const s2lost = c.send('b', data('Continuation', NOTES), { label: 'SEG 2', proto: 'TCP', color: 'violet', lost: true });
  const a1 = c.ack('a', 'ACK 1');
  const s2 = c.send('b', data('Continuation', NOTES), { label: 'RETRANSMIT', proto: 'TCP', color: 'red' });
  s2.info = `[TCP Retransmission] ${s2.info}`;
  const a2 = c.ack('a', 'ACK 2');
  const close = c.close();

  return lesson({
    id: 'tcp',
    name: 'TCP',
    title: 'Reliable delivery',
    layer: 4,
    tagline: 'Handshakes, sequence numbers and retransmission.',
    ...webNodes('web', false),
    legend: [
      ['green', 'Control / ACK'],
      ['amber', 'Request'],
      ['violet', 'Data'],
      ['red', 'Retransmission'],
    ],
    overview: {
      full: 'Transmission Control Protocol',
      description:
        'IP may drop, duplicate or reorder packets. TCP numbers every byte it sends, waits for the receiver to acknowledge them, and resends anything that goes missing — so applications see a clean, ordered stream of bytes.',
      facts: [
        ['Layer', 'Transport (4)'],
        ['Header', '20–60 bytes'],
        ['Connection', 'Yes (handshake)'],
        ['Guarantees', 'Order, delivery, no duplicates'],
        ['Spec', 'RFC 9293'],
      ],
    },
    steps: [
      {
        title: 'SYN',
        desc: '“Can we talk? My numbers start here.”',
        detail:
          'The client picks a random initial sequence number (ISN) and sends a SYN. It also advertises its Maximum Segment Size: 1460 bytes, the most data it wants per segment. Wireshark shows sequence numbers relative to the ISN, so this is Seq=0.',
        packets: [hs[0]],
      },
      {
        title: 'SYN-ACK',
        desc: '“Yes — and here are mine.”',
        detail: 'The server picks its own ISN and acknowledges the client’s SYN with Ack=1: “the next byte I expect from you is number 1.” A SYN counts as one byte.',
        packets: [hs[1]],
      },
      {
        title: 'ACK',
        desc: 'Connection established',
        detail: 'The client acknowledges the server’s SYN. Three packets, one round trip — both sides are now synchronised.',
        packets: [hs[2]],
      },
      {
        title: 'Request and first segment',
        desc: 'Data flows, counted in bytes',
        detail:
          'The client sends a small request. The server’s file is larger than one segment, so it splits it. Segment 1 carries the headers plus the first part of the file; its sequence number says exactly where in the stream it belongs.',
        facts: [['Segment size', `≤ 1460 bytes`]],
        packets: [req, s1],
      },
      {
        title: 'A segment is lost',
        desc: 'Somewhere on the internet',
        detail:
          'Segment 2 is dropped by a congested router. The client only received segment 1, so its ACK only covers those bytes. The server notices that segment 2 is never acknowledged.',
        packets: [s2lost, a1],
      },
      {
        title: 'Retransmission',
        desc: 'Same bytes, same sequence number',
        detail:
          'When its retransmission timer fires, the server sends segment 2 again with the very same sequence number. The client now has everything in order and acknowledges the whole file.',
        facts: [
          ['Trigger', 'Retransmission timeout'],
          ['Seq', 'unchanged'],
        ],
        packets: [s2, a2],
      },
      {
        title: 'Close',
        desc: 'FIN, FIN-ACK, ACK',
        detail: 'Each direction is closed separately with FIN. Like SYN, FIN consumes one sequence number so it can be acknowledged too.',
        packets: close,
      },
    ],
    outro: {
      title: 'Every byte delivered',
      text: 'Even though the network lost a packet, the application received the complete file in the right order — TCP quietly repaired it.',
      facts: [
        ['Packets lost', '1'],
        ['Bytes lost', '0'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ NTP */

function buildNtp() {
  const req = (lost: boolean, t1: number, label: string) =>
    udp({
      from: 'client', to: 'ntp', sport: 123, dport: 123, color: 'blue', label, proto: 'NTP', lost,
      info: 'NTP Version 4, client', app: ntp({ mode: 3, t1 }),
    });
  const first = req(true, 0, 'REQUEST');
  const retry = req(false, 2000, 'RETRY');
  const reply = udp({
    from: 'ntp', to: 'client', sport: 123, dport: 123, color: 'violet', label: 'TIME', proto: 'NTP',
    info: 'NTP Version 4, server', app: ntp({ mode: 4, t1: 2000, t2: 2011, t3: 2011 }),
  });

  return lesson({
    id: 'ntp',
    name: 'NTP',
    title: 'Setting the clock',
    layer: 7,
    tagline: 'Four timestamps over UDP keep every clock in step.',
    ...webNodes('ntp', false),
    legend: [
      ['blue', 'Request'],
      ['violet', 'Reply'],
    ],
    overview: {
      full: 'Network Time Protocol',
      description:
        'Computers drift by seconds a day. NTP fixes that: the laptop asks a time server for the time, and by recording when each message was sent and received it can cancel out the network delay and set its clock to within milliseconds. It runs over UDP, so a lost message is simply retried.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', 'UDP 123'],
        ['Message', '48 bytes'],
        ['Accuracy', '~1–10 ms over the internet'],
        ['Spec', 'RFC 5905'],
      ],
    },
    steps: [
      {
        title: 'Just send it',
        desc: 'No handshake at all',
        detail:
          'The laptop wants the exact time. It immediately sends one 48-byte NTP request in a UDP datagram to port 123 — compare that with TCP’s three-packet handshake before any data could move.',
        facts: [
          ['UDP header', '8 bytes'],
          ['NTP message', '48 bytes'],
        ],
        packets: [],
      },
      {
        title: 'The datagram is lost',
        desc: 'Nobody notices — except the app',
        detail:
          'The request is dropped on the way. UDP itself will never know and never resend it. The NTP client simply waits for a reply that doesn’t come.',
        packets: [first],
      },
      {
        title: 'The app retries',
        desc: 'Reliability is the application’s job',
        detail: 'After a two-second timeout the NTP client sends a fresh request with a new transmit timestamp (T1).',
        packets: [retry],
      },
      {
        title: 'The time arrives',
        desc: 'Four timestamps',
        detail:
          'The server replies with when it received the request (T2) and when it sent the reply (T3), plus the client’s T1. With its own arrival time T4, the laptop computes the network delay and its clock offset, then adjusts.',
        facts: [
          ['Delay', '(T4 − T1) − (T3 − T2)'],
          ['Offset', '((T2 − T1) + (T3 − T4)) / 2'],
        ],
        packets: [reply],
      },
    ],
    outro: {
      title: 'Clock set',
      text: 'Two datagrams did the job with no setup. When you need speed and can handle loss yourself — time sync, DNS, voice, games — UDP is the right tool.',
      facts: [['Overhead', '8 bytes per datagram']],
    },
  });
}

/* ------------------------------------------------------------------ DHCP */

function buildDhcp() {
  const xid = 0x3903f326;
  const base = { from: 'client', to: 'router', sport: 68, dport: 67, proto: 'DHCP', df: false } as const;
  const discover = udp({
    ...base, color: 'blue', label: 'DISCOVER', src: '0.0.0.0', dst: '255.255.255.255', dstMac: MAC.bcast,
    info: `DHCP Discover - Transaction ID ${hex(xid, 8)}`,
    app: dhcp({ op: 1, xid, type: 'DISCOVER', chaddr: MAC.client, hostname: 'laptop', params: true }),
  });
  const offerOpts = { server: IP('router'), lease: 86400, subnet: '255.255.255.0', router: IP('router'), dnsServer: '8.8.8.8' };
  const offer = udp({
    from: 'router', to: 'client', sport: 67, dport: 68, proto: 'DHCP', df: false, color: 'violet', label: 'OFFER',
    info: `DHCP Offer - Transaction ID ${hex(xid, 8)}`,
    app: dhcp({ op: 2, xid, type: 'OFFER', chaddr: MAC.client, yiaddr: IP('client'), siaddr: IP('router'), ...offerOpts }),
  });
  const request = udp({
    ...base, color: 'blue', label: 'REQUEST', src: '0.0.0.0', dst: '255.255.255.255', dstMac: MAC.bcast,
    info: `DHCP Request - Transaction ID ${hex(xid, 8)}`,
    app: dhcp({ op: 1, xid, type: 'REQUEST', chaddr: MAC.client, requested: IP('client'), server: IP('router'), hostname: 'laptop', params: true }),
  });
  const ack = udp({
    from: 'router', to: 'client', sport: 67, dport: 68, proto: 'DHCP', df: false, color: 'amber', label: 'ACK',
    info: `DHCP ACK - Transaction ID ${hex(xid, 8)}`,
    app: dhcp({ op: 2, xid, type: 'ACK', chaddr: MAC.client, yiaddr: IP('client'), siaddr: IP('router'), ...offerOpts }),
  });

  return lesson({
    id: 'dhcp',
    name: 'DHCP',
    title: 'Getting an address',
    layer: 7,
    tagline: 'Discover, Offer, Request, Acknowledge.',
    nodes: [
      { id: 'client', x: 14, y: 58 },
      { id: 'router', x: 50, y: 58, label: 'Router (DHCP server)' },
      { id: 'internet', x: 84, y: 58 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
    ],
    legend: [
      ['blue', 'Client broadcast'],
      ['violet', 'Offer'],
      ['amber', 'Acknowledge'],
    ],
    overview: {
      full: 'Dynamic Host Configuration Protocol',
      description:
        'A device that just joined a network has no IP address, doesn’t know the router and doesn’t know a DNS server. DHCP hands all of that out automatically in four messages, remembered as DORA: Discover, Offer, Request, Acknowledge.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Ports', 'UDP 67 (server), 68 (client)'],
        ['Messages', 'Discover, Offer, Request, ACK'],
        ['Gives out', 'IP, mask, router, DNS, lease'],
        ['Spec', 'RFC 2131'],
      ],
    },
    steps: [
      {
        title: 'Joined, but no address',
        desc: 'The laptop is on the Wi-Fi',
        detail: 'The link is up, but the laptop has no IP address yet. It can’t address anyone directly, so it will shout to everyone on the local network.',
        focus: ['client'],
      },
      {
        title: 'Discover',
        desc: '“Is there a DHCP server here?”',
        detail:
          'Sent from 0.0.0.0 to the broadcast address 255.255.255.255 and the broadcast MAC ff:ff:ff:ff:ff:ff, so every device on the network receives it. The laptop includes its MAC address and a random transaction ID.',
        facts: [
          ['From', '0.0.0.0 : 68'],
          ['To', '255.255.255.255 : 67'],
        ],
        packets: [discover],
      },
      {
        title: 'Offer',
        desc: '“You can have 192.168.1.10”',
        detail:
          'The router’s DHCP server picks a free address and offers it together with the subnet mask, the router (default gateway), a DNS server and how long the lease lasts.',
        facts: [
          ['Offered IP', IP('client')],
          ['Gateway', IP('router')],
          ['DNS', '8.8.8.8'],
          ['Lease', '24 hours'],
        ],
        packets: [offer],
      },
      {
        title: 'Request',
        desc: '“I’ll take it”',
        detail:
          'The laptop broadcasts again, formally requesting the offered address and naming the server it chose. Broadcasting lets any other DHCP servers that also made an offer know they weren’t picked.',
        packets: [request],
      },
      {
        title: 'Acknowledge',
        desc: 'The lease is confirmed',
        detail:
          'The server confirms. The laptop configures 192.168.1.10/24, sets 192.168.1.1 as its default route and 8.8.8.8 as its resolver. Halfway through the lease it will quietly renew it.',
        packets: [ack],
      },
    ],
    outro: {
      title: 'Online',
      text: 'Four messages turned a device with no address into a configured member of the network — ready for DNS and everything else.',
      facts: [
        ['Address', '192.168.1.10/24'],
        ['Renews after', '12 hours'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ ICMP */

const PING_DATA = ascii('abcdefghijklmnopqrstuvwabcdefghi');

function buildIcmp() {
  const echo = (seq: number, ttl = 64, label = 'PING') =>
    packet({
      from: 'client', to: 'dns', color: 'blue', label, proto: 'ICMP', ttl,
      info: `Echo (ping) request id=0x0001, seq=${seq}, ttl=${ttl}`,
      l4: { kind: 'icmp', type: 8, code: 0, id: 1, seq, data: PING_DATA },
    });
  const reply = (seq: number) =>
    packet({
      from: 'dns', to: 'client', color: 'violet', label: 'PONG', proto: 'ICMP', ttl: 117,
      info: `Echo (ping) reply id=0x0001, seq=${seq}, ttl=117`,
      l4: { kind: 'icmp', type: 0, code: 0, id: 1, seq, data: PING_DATA },
    });
  const exceeded = (from: string, original: ReturnType<typeof echo>) =>
    packet({
      from, to: 'client', color: 'red', label: 'TTL EXPIRED', proto: 'ICMP', src: IP(from), ttl: 64,
      info: 'Time-to-live exceeded (Time to live exceeded in transit)',
      l4: {
        kind: 'icmp', type: 11, code: 0,
        data: original.frame.bytes.slice(14, 14 + 28),
        dataName: 'Original IP header + first 8 bytes',
      },
    });

  const t1 = echo(10, 1, 'TTL=1');
  const t2 = echo(11, 2, 'TTL=2');
  const t3 = echo(12, 3, 'TTL=3');

  return lesson({
    id: 'icmp',
    name: 'ICMP',
    title: 'Ping and traceroute',
    layer: 3,
    tagline: 'The network’s own messages for testing and errors.',
    nodes: [
      { id: 'client', x: 8, y: 58 },
      { id: 'router', x: 33, y: 58 },
      { id: 'isp', x: 59, y: 58 },
      { id: 'dns', x: 87, y: 58, label: 'dns.google' },
    ],
    links: [
      ['client', 'router'],
      ['router', 'isp'],
      ['isp', 'dns'],
    ],
    legend: [
      ['blue', 'Echo request'],
      ['violet', 'Echo reply'],
      ['red', 'Time exceeded'],
    ],
    overview: {
      full: 'Internet Control Message Protocol',
      description:
        'ICMP carries control messages for IP itself: “are you there?”, “that host is unreachable”, “this packet ran out of hops”. The ping and traceroute tools are built entirely on it.',
      facts: [
        ['Layer', 'Network (3)'],
        ['Ports', 'none — carried directly in IP'],
        ['IP protocol', '1'],
        ['Common types', '0, 3, 8, 11'],
        ['Spec', 'RFC 792'],
      ],
    },
    steps: [
      {
        title: 'Ping',
        desc: 'Echo request → echo reply',
        detail:
          'ping 8.8.8.8 sends an ICMP Echo Request (type 8) with an identifier, a sequence number and some filler data. The target copies the data back in an Echo Reply (type 0). The time between them is the round-trip time.',
        facts: [
          ['Request', 'type 8'],
          ['Reply', 'type 0'],
        ],
        packets: [echo(1), reply(1), echo(2), reply(2)],
      },
      {
        title: 'What TTL means',
        desc: 'Every router subtracts one',
        detail:
          'Look at the replies: they arrive with TTL 117. Each router that forwards an IP packet decrements its Time-To-Live; when it hits zero the router drops the packet and reports back with ICMP “Time exceeded”. This stops packets looping forever — and traceroute exploits it.',
        focus: ['router', 'isp'],
      },
      {
        title: 'Traceroute: TTL = 1',
        desc: 'The first router answers',
        detail: 'traceroute sends a probe with TTL 1. Your home router decrements it to 0, drops it and sends back Time exceeded — revealing its own address as hop 1.',
        facts: [['Hop 1', IP('router')]],
        packets: [t1, exceeded('router', t1)],
      },
      {
        title: 'Traceroute: TTL = 2',
        desc: 'One hop further',
        detail: 'The next probe survives the home router but dies at the ISP’s router, which reports itself as hop 2. The error includes the start of the original packet so the sender can match it up.',
        facts: [['Hop 2', IP('isp')]],
        packets: [t2, exceeded('isp', t2)],
      },
      {
        title: 'Traceroute: TTL = 3',
        desc: 'The destination replies',
        detail: 'With TTL 3 the probe reaches 8.8.8.8 itself, which answers with a normal Echo Reply. The full path is now mapped.',
        facts: [['Hop 3', '8.8.8.8']],
        packets: [t3, reply(12)],
      },
    ],
    outro: {
      title: 'Path mapped',
      text: 'Ping measures reachability and delay; traceroute walks the path one TTL at a time, letting each router introduce itself through an error message.',
      facts: [['Hops', '3']],
    },
  });
}

/* ------------------------------------------------------------------ SMTP */

function buildSmtp() {
  const c = tcp('client', 'mail', 50877, 25);
  const hs = c.handshake();
  const S = (ls: string[], label: string, info = ls[0]) =>
    c.send('b', lines('Simple Mail Transfer Protocol', ls, () => 'Reply'), { label, proto: 'SMTP', info: `S: ${info}`, color: 'violet' });
  const C = (ls: string[], label: string, info = ls[0], name = 'Command') =>
    c.send('a', lines('Simple Mail Transfer Protocol', ls, () => name), { label, proto: 'SMTP', info: `C: ${info}`, color: 'amber' });

  const greet = S(['220 mail.example.net ESMTP ready'], '220');
  const ehlo = C(['EHLO laptop.home'], 'EHLO');
  const caps = S(['250-mail.example.net Hello', '250-SIZE 35882577', '250-8BITMIME', '250 SMTPUTF8'], '250');
  const from = C(['MAIL FROM:<amir@example.org>'], 'MAIL FROM');
  const ok1 = S(['250 2.1.0 Ok'], '250');
  const rcpt = C(['RCPT TO:<sara@example.net>'], 'RCPT TO');
  const ok2 = S(['250 2.1.5 Ok'], '250');
  const dataCmd = C(['DATA'], 'DATA');
  const go = S(['354 End data with <CR><LF>.<CR><LF>'], '354');
  const msg = C(
    [
      'From: Amir <amir@example.org>',
      'To: Sara <sara@example.net>',
      'Subject: Lunch tomorrow?',
      'Date: Wed, 11 Nov 2026 12:00:00 +0000',
      '',
      'Hi Sara, are you free for lunch tomorrow at 1pm?',
      '.',
    ],
    'MESSAGE',
    'Message body, ends with "."',
    'Message line',
  );
  const queued = S(['250 2.0.0 Ok: queued as 4F2A1C'], '250');
  const quit = C(['QUIT'], 'QUIT');
  const bye = S(['221 2.0.0 Bye'], '221');
  const close = c.close();

  return lesson({
    id: 'smtp',
    name: 'SMTP',
    title: 'Sending email',
    layer: 7,
    tagline: 'A polite text conversation that delivers your mail.',
    ...webNodes('mail', false),
    legend: [
      ['green', 'TCP control'],
      ['amber', 'Client command'],
      ['violet', 'Server reply'],
    ],
    overview: {
      full: 'Simple Mail Transfer Protocol',
      description:
        'SMTP moves email from a sender to a mail server, and between mail servers. It is a turn-by-turn text dialogue: the client sends a command, the server answers with a three-digit code. 2xx means OK, 3xx means “go on”, 4xx/5xx mean errors.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Ports', '25 (relay), 587 (submission)'],
        ['Runs over', 'TCP'],
        ['Format', 'Text commands + reply codes'],
        ['Spec', 'RFC 5321'],
      ],
    },
    steps: [
      {
        title: 'Connect and greet',
        desc: 'The server speaks first',
        detail:
          'After the TCP handshake the server introduces itself with code 220. (Real mail apps use port 587 and switch to TLS with STARTTLS first — this lesson shows the classic plain-text conversation.)',
        packets: [...hs, greet],
      },
      {
        title: 'EHLO',
        desc: 'Introductions and capabilities',
        detail: 'The client says hello with its name. The server lists the extensions it supports, one per line; the last line uses a space instead of a dash after 250.',
        packets: [ehlo, caps],
      },
      {
        title: 'The envelope',
        desc: 'MAIL FROM and RCPT TO',
        detail:
          'Like writing on an envelope, the client states the sender and each recipient. These envelope addresses are what servers use for delivery — they can differ from the From/To lines inside the message.',
        packets: [from, ok1, rcpt, ok2],
      },
      {
        title: 'The message',
        desc: 'DATA, then a lone dot',
        detail: 'DATA gets a 354 “go ahead”. The client sends headers, a blank line and the body, and ends with a line containing only a dot. The server accepts it and queues it for delivery.',
        facts: [
          ['End marker', '<CR><LF>.<CR><LF>'],
          ['Queue ID', '4F2A1C'],
        ],
        packets: [dataCmd, go, msg, queued],
      },
      {
        title: 'Goodbye',
        desc: 'QUIT, 221, FIN',
        detail: 'The client says QUIT, the server says Bye, and TCP closes. The server will now look up the MX record for example.net and pass the message on.',
        packets: [quit, bye, ...close],
      },
    ],
    outro: {
      title: 'Mail queued',
      text: 'Eight small exchanges delivered one email. Every command and reply was readable — which is why modern SMTP always upgrades to TLS.',
      facts: [['Status', '250 queued']],
    },
  });
}

export const dnsLesson = buildDns();
export const tcpLesson = buildTcp();
export const ntpLesson = buildNtp();
export const dhcpLesson = buildDhcp();
export const icmpLesson = buildIcmp();
export const smtpLesson = buildSmtp();
