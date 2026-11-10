// Pack D: proxies, private/secure DNS and QUIC.
import { ascii, flagNames, hex, hexStr, ipb, rand, u16, u32, type AppWriter, type Writer } from '@/engine/bytes';
import { registerNodes } from '@/engine/nodes';
import { clientFinished, clientHello, dns, encrypted, http, serverHello } from '@/engine/protocols';
import type { Lesson, NodeId, Packet, PacketColor } from '@/engine/types';
import { IP, lesson, packet, udp, webNodes } from './kit';

registerNodes({
  proxy: { label: 'Forward proxy', icon: 'shield', ip: '198.51.100.20' },
  socks: { label: 'SOCKS5 server', icon: 'shield', ip: '198.51.100.30' },
  lb: { label: 'Reverse proxy', icon: 'shieldcheck', ip: '203.0.113.80' },
  backend1: { label: 'App server 1', icon: 'server', ip: '10.0.0.21' },
  backend2: { label: 'App server 2', icon: 'server', ip: '10.0.0.22' },
  ispdns: { label: 'ISP resolver', icon: 'server', ip: '100.64.0.53' },
  doh: { label: 'dns.google', icon: 'lock', ip: '8.8.8.8' },
  spoofer: { label: 'Spoofer', icon: 'radio', ip: '198.51.100.66' },
});

const HTML =
  '<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is reserved for documentation examples.</p></body></html>\n';
const UA = 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/132.0';

/* ------------------------------------------------------------------ helpers */

type F = [string, string | number, number[]];

/** A binary application layer from a list of [name, value, bytes]. */
const bin =
  (name: string, fields: F[], summary: string): AppWriter =>
  (w) => {
    w.begin('app', name);
    for (const [n, v, b] of fields) w.f(n, v, b);
    w.end(summary);
  };

interface SegOpts {
  label: string;
  color?: PacketColor;
  proto?: string;
  info?: string;
  app?: AppWriter;
  lost?: boolean;
  mss?: boolean;
}

/** Like kit.tcp, but lets each side use an address other than its node's default (e.g. a private back-end address). */
function tcpx(a: NodeId, b: NodeId, aPort: number, bPort: number, ips: { a?: string; b?: string } = {}) {
  const isn = { a: (0x5a17c0de + aPort * 7919 + bPort) >>> 0, b: (0x1e2f3a4b + bPort * 104729 + aPort) >>> 0 };
  const seq = { a: 0, b: 0 };
  const seg = (side: 'a' | 'b', flags: string, o: SegOpts): Packet => {
    const other = side === 'a' ? 'b' : 'a';
    const sport = side === 'a' ? aPort : bPort;
    const dport = side === 'a' ? bPort : aPort;
    const hasAck = flags.includes('A');
    const p = packet({
      from: side === 'a' ? a : b,
      to: side === 'a' ? b : a,
      src: ips[side],
      dst: ips[other],
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
  };
}

const okHeaders = (extra: string[] = []) => [
  'HTTP/1.1 200 OK',
  'Content-Type: text/html; charset=utf-8',
  `Content-Length: ${HTML.length}`,
  'Cache-Control: public, max-age=600',
  ...extra,
];

/* ------------------------------------------------------------------ Forward proxy */

function buildProxy() {
  const sni = 'www.example.com';
  const c = tcpx('client', 'proxy', 51010, 3128);
  const hs1 = c.handshake();
  const get = c.send(
    'a',
    http(['GET http://www.example.com/ HTTP/1.1', 'Host: www.example.com', UA, 'Accept: text/html', 'Proxy-Connection: keep-alive']),
    { label: 'GET http://…', proto: 'HTTP', info: 'GET http://www.example.com/ HTTP/1.1', color: 'amber' },
  );
  const lookup = [
    udp({
      from: 'proxy', to: 'dns', sport: 40112, dport: 53, color: 'blue', label: 'DNS QUERY', proto: 'DNS',
      info: 'Standard query 0x1c2d A www.example.com',
      app: dns({ id: 0x1c2d, rd: true, q: ['www.example.com', 'A'] }),
    }),
    udp({
      from: 'dns', to: 'proxy', sport: 53, dport: 40112, color: 'blue', label: 'DNS REPLY', proto: 'DNS',
      info: 'Standard query response 0x1c2d A www.example.com A 203.0.113.10',
      app: dns({ id: 0x1c2d, response: true, rd: true, ra: true, q: ['www.example.com', 'A'], an: [{ name: 'www.example.com', type: 'A', ttl: 3600, data: '203.0.113.10' }] }),
    }),
  ];
  const o = tcpx('proxy', 'web', 40500, 80);
  const hs2 = o.handshake();
  const oget = o.send(
    'a',
    http(['GET / HTTP/1.1', 'Host: www.example.com', UA, 'Accept: text/html', 'Via: 1.1 proxy.corp.example', 'X-Forwarded-For: 192.168.1.10']),
    { label: 'GET /', proto: 'HTTP', info: 'GET / HTTP/1.1 (sent by the proxy)', color: 'amber' },
  );
  const oresp = o.send('b', http(okHeaders(), HTML), { label: '200 OK', proto: 'HTTP', info: 'HTTP/1.1 200 OK (text/html)', color: 'violet' });
  const presp = c.send('b', http(okHeaders(['Via: 1.1 proxy.corp.example', 'X-Cache: MISS']), HTML), {
    label: '200 OK', proto: 'HTTP', info: 'HTTP/1.1 200 OK (text/html, via proxy)', color: 'violet',
  });

  const conn = c.send('a', http(['CONNECT www.example.com:443 HTTP/1.1', 'Host: www.example.com:443', UA]), {
    label: 'CONNECT', proto: 'HTTP', info: 'CONNECT www.example.com:443 HTTP/1.1', color: 'amber',
  });
  const t = tcpx('proxy', 'web', 40502, 443);
  const hs3 = t.handshake();
  const est = c.send('b', http(['HTTP/1.1 200 Connection established']), {
    label: '200 TUNNEL', proto: 'HTTP', info: 'HTTP/1.1 200 Connection established', color: 'violet',
  });
  const tls = (s: typeof c, side: 'a' | 'b', app: AppWriter, label: string, info: string, color: PacketColor = 'teal') =>
    s.send(side, app, { label, proto: 'TLSv1.3', info, color });
  const ch1 = tls(c, 'a', clientHello(sni), 'CLIENT HELLO', 'Client Hello (SNI=www.example.com), into the tunnel');
  const ch2 = tls(t, 'a', clientHello(sni), 'CLIENT HELLO', 'Client Hello, relayed byte for byte');
  const sh2 = tls(t, 'b', serverHello(sni), 'SERVER HELLO', 'Server Hello, Change Cipher Spec, Application Data');
  const sh1 = tls(c, 'b', serverHello(sni), 'SERVER HELLO', 'Server Hello, relayed byte for byte');
  const f1 = tls(c, 'a', clientFinished(sni), 'FINISHED', 'Change Cipher Spec, Application Data');
  const f2 = tls(t, 'a', clientFinished(sni), 'FINISHED', 'Change Cipher Spec, relayed');
  const e1 = tls(c, 'a', encrypted(96, 'GET / HTTP/1.1 … (encrypted)', 'pxget'), 'GET 🔒', 'Application Data', 'amber');
  const e2 = tls(t, 'a', encrypted(96, 'GET / HTTP/1.1 … (encrypted)', 'pxget'), 'GET 🔒', 'Application Data (relayed)', 'amber');
  const r2 = tls(t, 'b', encrypted(412, '200 OK + page (encrypted)', 'pxresp'), '200 OK 🔒', 'Application Data', 'violet');
  const r1 = tls(c, 'b', encrypted(412, '200 OK + page (encrypted)', 'pxresp'), '200 OK 🔒', 'Application Data (relayed)', 'violet');

  return lesson({
    id: 'proxy',
    name: 'HTTP Proxy',
    title: 'Via a proxy',
    layer: 7,
    tagline: 'A middleman that fetches pages for you — or just tunnels them.',
    nodes: [
      { id: 'client', x: 8, y: 62 },
      { id: 'router', x: 24, y: 62 },
      { id: 'proxy', x: 44, y: 62, label: 'proxy.corp.example' },
      { id: 'internet', x: 62, y: 62 },
      { id: 'dns', x: 84, y: 24 },
      { id: 'web', x: 86, y: 72 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'proxy'],
      ['proxy', 'internet'],
      ['internet', 'dns'],
      ['internet', 'web'],
    ],
    legend: [
      ['green', 'TCP control'],
      ['blue', 'DNS'],
      ['amber', 'Request'],
      ['violet', 'Response'],
      ['teal', 'TLS (tunnelled)'],
    ],
    overview: {
      full: 'Forward proxy, and CONNECT for HTTPS',
      description:
        'Many offices and schools send all web traffic through a forward proxy. For plain HTTP the browser hands the proxy the whole URL and the proxy fetches the page itself — so it can filter, log and cache. For HTTPS the browser asks the proxy to open a raw tunnel with CONNECT, and the proxy just copies encrypted bytes it cannot read.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Typical ports', '3128, 8080'],
        ['Plain HTTP', 'Absolute URL in the request'],
        ['HTTPS', 'CONNECT host:443 tunnel'],
        ['Spec', 'RFC 9110 §9.3.6'],
      ],
    },
    steps: [
      {
        title: 'Proxy settings',
        desc: 'The browser is told to use a proxy',
        detail:
          'The laptop’s network settings (or a PAC file) say “send web traffic to proxy.corp.example on port 3128”. From now on the browser never connects to websites directly — not even to look up their names.',
        facts: [
          ['Proxy', '198.51.100.20:3128'],
          ['Configured by', 'OS settings or PAC file'],
        ],
        focus: ['client', 'proxy'],
      },
      {
        title: 'Ask the proxy',
        desc: 'The full URL goes in the request line',
        detail:
          'The browser opens a TCP connection to the proxy — not to the website — and sends GET with the absolute URL http://www.example.com/. That is how the proxy knows where to go. Notice the laptop did no DNS lookup: resolving the name is the proxy’s job.',
        facts: [
          ['Request line', 'GET http://www.example.com/'],
          ['Client DNS lookup', 'none'],
        ],
        packets: [...hs1, get],
      },
      {
        title: 'The proxy fetches it',
        desc: 'Its own lookup, its own connection',
        detail:
          'The proxy resolves www.example.com, opens its own TCP connection to the server and sends a normal request with just the path “/”. It adds a Via header and usually X-Forwarded-For, so the server can tell a proxy was involved. The website sees the proxy’s address, not the laptop’s.',
        facts: [
          ['Server sees', '198.51.100.20 (the proxy)'],
          ['Added headers', 'Via, X-Forwarded-For'],
        ],
        packets: [...lookup, ...hs2, oget],
      },
      {
        title: 'The page comes back',
        desc: 'Checked, maybe cached, then passed on',
        detail:
          'The server answers the proxy. Because everything is plain text, the proxy can scan it, block it or store it: X-Cache: MISS says it wasn’t cached yet, and the next person asking for this page could get it straight from the proxy.',
        facts: [
          ['X-Cache', 'MISS (stored now)'],
          ['Can inspect', 'URL, headers, body'],
        ],
        packets: [oresp, presp],
      },
      {
        title: 'HTTPS: ask for a tunnel',
        desc: 'CONNECT www.example.com:443',
        detail:
          'For https:// the browser can’t let the proxy read the request, so it sends CONNECT with only a host name and port. The proxy opens a TCP connection to port 443 and answers “200 Connection established”. From now on it stops speaking HTTP and just copies bytes both ways.',
        facts: [
          ['Proxy learns', 'Host name and port only'],
          ['Reply', '200 Connection established'],
        ],
        packets: [conn, ...hs3, est],
      },
      {
        title: 'TLS through the tunnel',
        desc: 'End to end, the proxy just relays',
        detail:
          'The TLS handshake runs between the browser and www.example.com itself. Each record passes through the proxy unchanged — compare the Client Hello on both legs, they are identical. The proxy can read the SNI but not the keys, so it can’t see what comes next.',
        packets: [ch1, ch2, sh2, sh1, f1, f2],
      },
      {
        title: 'Encrypted traffic',
        desc: 'Opaque to the proxy',
        detail:
          'The request and the page travel as TLS Application Data. The proxy sees only sizes and timing. (Some companies install their own root certificate on laptops so the proxy can decrypt HTTPS — a choice with real privacy costs.)',
        facts: [
          ['Proxy sees', 'Sizes, timing, SNI'],
          ['Proxy can’t see', 'URL path, headers, body'],
        ],
        packets: [e1, e2, r2, r1],
      },
    ],
    outro: {
      title: 'Two ways through',
      text: 'Plain HTTP gave the proxy the whole request to fetch, filter and cache. HTTPS used CONNECT, turning the proxy into a blind relay for an end-to-end encrypted connection.',
      facts: [
        ['HTTP', 'Proxy fetches the URL'],
        ['HTTPS', 'Proxy tunnels bytes'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ SOCKS5 */

function buildSocks() {
  const s = tcpx('client', 'socks', 51200, 1080);
  const hs = s.handshake();
  const S = (side: 'a' | 'b', fields: F[], summary: string, label: string, info: string) =>
    s.send(side, bin('SOCKS Protocol v5', fields, summary), {
      label, proto: 'Socks', info, color: side === 'a' ? 'amber' : 'violet',
    });
  const greet = S('a', [
    ['Version', '5', [5]],
    ['Number of methods', 2, [2]],
    ['Method', '0x00 · No authentication', [0]],
    ['Method', '0x02 · Username/password', [2]],
  ], 'Greeting · 2 methods offered', 'HELLO', 'Version 5, offers: no auth, username/password');
  const choose = S('b', [
    ['Version', '5', [5]],
    ['Chosen method', '0x02 · Username/password', [2]],
  ], 'Method chosen · username/password', 'USE 0x02', 'Version 5, method: username/password');
  const user = 'amir';
  const pass = 'hunter2';
  const auth = S('a', [
    ['Sub-negotiation version', '1', [1]],
    ['Username length', ascii(user).length, [ascii(user).length]],
    ['Username', user, ascii(user)],
    ['Password length', ascii(pass).length, [ascii(pass).length]],
    ['Password', `${pass} (sent in clear text!)`, ascii(pass)],
  ], 'Username/password login', 'LOGIN', `Username/password: ${user}`);
  const authOk = S('b', [
    ['Sub-negotiation version', '1', [1]],
    ['Status', '0x00 · success', [0]],
  ], 'Login accepted', 'LOGIN OK', 'Authentication succeeded');
  const host = 'www.example.com';
  const req = S('a', [
    ['Version', '5', [5]],
    ['Command', '0x01 · CONNECT', [1]],
    ['Reserved', '0x00', [0]],
    ['Address type', '0x03 · Domain name', [3]],
    ['Name length', ascii(host).length, [ascii(host).length]],
    ['Destination name', host, ascii(host)],
    ['Destination port', 80, u16(80)],
  ], `CONNECT ${host}:80`, 'CONNECT', `Command: CONNECT ${host}:80`);
  const up = tcpx('socks', 'web', 40800, 80);
  const hsUp = up.handshake();
  const reply = S('b', [
    ['Version', '5', [5]],
    ['Reply', '0x00 · succeeded', [0]],
    ['Reserved', '0x00', [0]],
    ['Address type', '0x01 · IPv4', [1]],
    ['Bound address', IP('socks'), ipb(IP('socks'))],
    ['Bound port', 40800, u16(40800)],
  ], 'Connected · bound 198.51.100.30:40800', 'CONNECTED', 'Reply: succeeded, bound 198.51.100.30:40800');

  const reqLines = ['GET / HTTP/1.1', 'Host: www.example.com', UA, 'Accept: text/html'];
  const g1 = s.send('a', http(reqLines), { label: 'GET /', proto: 'HTTP', info: 'GET / HTTP/1.1 (inside SOCKS)', color: 'amber' });
  const g2 = up.send('a', http(reqLines), { label: 'GET /', proto: 'HTTP', info: 'GET / HTTP/1.1 (relayed)', color: 'amber' });
  const o2 = up.send('b', http(okHeaders(), HTML), { label: '200 OK', proto: 'HTTP', info: 'HTTP/1.1 200 OK', color: 'violet' });
  const o1 = s.send('b', http(okHeaders(), HTML), { label: '200 OK', proto: 'HTTP', info: 'HTTP/1.1 200 OK (relayed)', color: 'violet' });
  const close = [...s.close(), ...up.close()];

  return lesson({
    id: 'socks',
    name: 'SOCKS5',
    title: 'Any connection',
    layer: 5,
    tagline: 'A tiny binary handshake, then any TCP stream relayed as-is.',
    nodes: [
      { id: 'client', x: 8, y: 60 },
      { id: 'router', x: 26, y: 60 },
      { id: 'socks', x: 47, y: 60 },
      { id: 'internet', x: 67, y: 60 },
      { id: 'web', x: 88, y: 60 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'socks'],
      ['socks', 'internet'],
      ['internet', 'web'],
    ],
    legend: [
      ['green', 'TCP control'],
      ['amber', 'Client → proxy'],
      ['violet', 'Proxy → client'],
    ],
    overview: {
      full: 'SOCKS Protocol Version 5',
      description:
        'An HTTP proxy understands web requests. SOCKS doesn’t care what you speak: after a short binary handshake that says “connect me to this host and port”, it relays the raw TCP bytes in both directions. Mail apps, games, SSH and Tor all use it.',
      facts: [
        ['Layer', 'Session (5)'],
        ['Port', '1080'],
        ['Runs over', 'TCP (UDP ASSOCIATE for UDP)'],
        ['Auth', 'None, user/pass, GSS-API'],
        ['Spec', 'RFC 1928, RFC 1929'],
      ],
    },
    steps: [
      {
        title: 'Connect to the proxy',
        desc: 'A TCP connection to port 1080',
        detail: 'The app has been told to use a SOCKS5 proxy. It opens an ordinary TCP connection to it — nothing in this connection says yet where the app really wants to go.',
        packets: hs,
      },
      {
        title: 'Greeting',
        desc: 'Which login methods do we share?',
        detail:
          'The first message is three or four bytes: version 5, how many authentication methods the client supports, and the list. The proxy picks one — here username/password (0x02). If it accepted none, it would answer 0xFF and hang up.',
        facts: [
          ['Offered', '0x00, 0x02'],
          ['Chosen', '0x02 username/password'],
        ],
        packets: [greet, choose],
      },
      {
        title: 'Log in',
        desc: 'Username and password (RFC 1929)',
        detail:
          'A small sub-negotiation carries the username and password, each prefixed by its length. Open the packet: the password is right there in plain text. Over an untrusted network, SOCKS should itself run inside SSH or TLS.',
        facts: [
          ['Status', '0x00 = success'],
          ['Encrypted', 'No'],
        ],
        packets: [auth, authOk],
      },
      {
        title: 'CONNECT request',
        desc: 'Where to, by name or address',
        detail:
          'The client asks: CONNECT to the domain name www.example.com, port 80. Sending the name (address type 3) means the proxy does the DNS lookup — the client’s own network never sees it. The proxy connects out, then reports success and the address and port it used.',
        facts: [
          ['Command', '0x01 CONNECT'],
          ['Address type', '0x03 domain name'],
          ['Reply', '0x00 succeeded'],
        ],
        packets: [req, ...hsUp, reply],
      },
      {
        title: 'Relay',
        desc: 'Bytes in, bytes out',
        detail:
          'From here SOCKS is invisible. The app sends a normal HTTP request; the proxy copies it, unchanged, onto its connection to the server, and copies the answer back. It could just as well be SMTP, SSH or a game protocol.',
        packets: [g1, g2, o2, o1],
      },
      {
        title: 'Close',
        desc: 'Both legs shut down',
        detail: 'When the app closes its side, the proxy closes its connection to the server too.',
        packets: close,
      },
    ],
    outro: {
      title: 'Any connection relayed',
      text: 'Ten bytes or so of handshake told the proxy where to connect; everything after was passed through untouched, whatever the protocol.',
      facts: [
        ['Handshake', '3 small exchanges'],
        ['Protocol aware', 'No'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ Reverse proxy */

function buildReverse() {
  const sni = 'www.example.com';
  const BACK = '10.0.0.2';
  const lookup = [
    udp({
      from: 'client', to: 'dns', sport: 61777, dport: 53, color: 'blue', label: 'DNS QUERY', proto: 'DNS',
      info: 'Standard query 0x5e2a A www.example.com', app: dns({ id: 0x5e2a, rd: true, q: [sni, 'A'] }),
    }),
    udp({
      from: 'dns', to: 'client', sport: 53, dport: 61777, color: 'blue', label: 'DNS REPLY', proto: 'DNS',
      info: 'Standard query response 0x5e2a A www.example.com A 203.0.113.80',
      app: dns({ id: 0x5e2a, response: true, rd: true, ra: true, q: [sni, 'A'], an: [{ name: sni, type: 'A', ttl: 300, data: IP('lb') }] }),
    }),
  ];
  const f = tcpx('client', 'lb', 52020, 443);
  const hs = f.handshake();
  const T = (app: AppWriter, side: 'a' | 'b', label: string, info: string, color: PacketColor = 'teal') =>
    f.send(side, app, { label, proto: 'TLSv1.3', info, color });
  const ch = T(clientHello(sni), 'a', 'CLIENT HELLO', 'Client Hello (SNI=www.example.com)');
  const sh = T(serverHello(sni), 'b', 'SERVER HELLO', 'Server Hello, certificate for www.example.com');
  const fin = T(clientFinished(sni), 'a', 'FINISHED', 'Change Cipher Spec, Application Data');
  const eget = T(encrypted(110, 'GET / HTTP/1.1 (encrypted)', 'rvget'), 'a', 'GET 🔒', 'Application Data (GET /)', 'amber');

  const b1 = tcpx('lb', 'backend1', 45110, 8080, { a: BACK });
  const hsB = b1.handshake();
  const fwd = b1.send(
    'a',
    http(['GET / HTTP/1.1', 'Host: www.example.com', UA, 'X-Forwarded-For: 198.51.100.7', 'X-Forwarded-Proto: https', 'X-Request-ID: 7f3c9a12']),
    { label: 'GET /', proto: 'HTTP', info: 'GET / HTTP/1.1 (plain, inside the data centre)', color: 'amber' },
  );
  const bresp = b1.send('b', http(okHeaders(['Server: app-1']), HTML), { label: '200 OK', proto: 'HTTP', info: 'HTTP/1.1 200 OK (from app-1)', color: 'violet' });
  const eresp = T(encrypted(430, '200 OK + page (encrypted), X-Cache: MISS', 'rvresp'), 'b', '200 OK 🔒', 'Application Data (200 OK)', 'violet');

  const eget2 = T(encrypted(110, 'GET / HTTP/1.1 (encrypted, second visit)', 'rvget2'), 'a', 'GET 🔒', 'Application Data (GET / again)', 'amber');
  const cached = T(encrypted(430, '200 OK from cache (encrypted), X-Cache: HIT', 'rvhit'), 'b', 'CACHE HIT 🔒', 'Application Data (served from cache)', 'pink');

  const eapi = T(encrypted(120, 'GET /api/cart (encrypted)', 'rvapi'), 'a', 'GET /api 🔒', 'Application Data (GET /api/cart)', 'amber');
  const b2 = tcpx('lb', 'backend2', 45112, 8080, { a: BACK });
  const hsB2 = b2.handshake();
  const api = b2.send(
    'a',
    http(['GET /api/cart HTTP/1.1', 'Host: www.example.com', 'X-Forwarded-For: 198.51.100.7', 'X-Forwarded-Proto: https', 'Cookie: session=4f1d…']),
    { label: 'GET /api', proto: 'HTTP', info: 'GET /api/cart HTTP/1.1 (to app-2)', color: 'amber' },
  );
  const apiBody = '{"items":2,"total":"24.00"}';
  const apiResp = b2.send(
    'b',
    http(['HTTP/1.1 200 OK', 'Content-Type: application/json', `Content-Length: ${apiBody.length}`, 'Cache-Control: private, no-store', 'Server: app-2'], apiBody),
    { label: '200 JSON', proto: 'HTTP', info: 'HTTP/1.1 200 OK (application/json)', color: 'violet' },
  );
  const eapiResp = T(encrypted(160, '200 OK + JSON (encrypted)', 'rvapir'), 'b', '200 JSON 🔒', 'Application Data (200 OK JSON)', 'violet');

  return lesson({
    id: 'reverse',
    name: 'Reverse Proxy',
    title: 'Offloading',
    layer: 7,
    tagline: 'One public front door: TLS, caching and load balancing for many servers.',
    nodes: [
      { id: 'client', x: 8, y: 58 },
      { id: 'router', x: 23, y: 58 },
      { id: 'internet', x: 40, y: 58 },
      { id: 'dns', x: 40, y: 18 },
      { id: 'lb', x: 62, y: 58, label: 'www.example.com edge' },
      { id: 'backend1', x: 87, y: 32 },
      { id: 'backend2', x: 87, y: 80 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
      ['internet', 'dns'],
      ['internet', 'lb'],
      ['lb', 'backend1'],
      ['lb', 'backend2'],
    ],
    legend: [
      ['blue', 'DNS'],
      ['green', 'TCP control'],
      ['teal', 'TLS handshake'],
      ['amber', 'Request'],
      ['violet', 'Response'],
      ['pink', 'Cache hit'],
    ],
    overview: {
      full: 'Reverse proxy and load balancer',
      description:
        'Big sites don’t expose their application servers. A reverse proxy (nginx, HAProxy, a CDN edge) answers for the domain: it holds the certificate and ends TLS, caches what it can, and spreads the remaining requests across a pool of back-end servers over a private network.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Faces', 'The internet (port 443)'],
        ['Back end', 'Private network, often plain HTTP'],
        ['Does', 'TLS, caching, load balancing'],
        ['Examples', 'nginx, HAProxy, Envoy, CDNs'],
      ],
    },
    steps: [
      {
        title: 'The name points at the proxy',
        desc: 'DNS returns the edge, not a server',
        detail:
          'www.example.com resolves to 203.0.113.80 — the reverse proxy. The application servers have private 10.0.0.x addresses that can’t be reached from the internet at all.',
        facts: [
          ['Public address', '203.0.113.80'],
          ['App servers', '10.0.0.21, 10.0.0.22'],
        ],
        packets: lookup,
      },
      {
        title: 'TLS ends at the edge',
        desc: 'The proxy holds the certificate',
        detail:
          'The browser’s TLS handshake is with the proxy, which owns the certificate and private key for www.example.com. Doing the expensive crypto here means the app servers don’t have to — that is the “offloading”.',
        packets: [...hs, ch, sh, fin],
      },
      {
        title: 'Forward to a back end',
        desc: 'Decrypted, annotated, passed on',
        detail:
          'The proxy decrypts the request, picks a healthy app server and sends it as plain HTTP over the private network. Because the server would otherwise only see the proxy, it adds X-Forwarded-For (the visitor’s public address after NAT) and X-Forwarded-Proto: https.',
        facts: [
          ['Chosen server', 'app-1 (10.0.0.21)'],
          ['Added', 'X-Forwarded-For, X-Forwarded-Proto'],
        ],
        packets: [eget, ...hsB, fwd],
      },
      {
        title: 'Response, re-encrypted',
        desc: 'And stored in the cache',
        detail:
          'app-1 answers with Cache-Control: public, max-age=600. The proxy keeps a copy, encrypts the response with the browser’s TLS keys and sends it on.',
        packets: [bresp, eresp],
      },
      {
        title: 'Served from cache',
        desc: 'No back end involved',
        detail:
          'A moment later the same page is requested again. The proxy still has a fresh copy, so it replies immediately — nothing is sent to the app servers. Caching at the edge is how sites survive traffic spikes.',
        facts: [
          ['X-Cache', 'HIT'],
          ['Back-end load', 'none'],
        ],
        packets: [eget2, cached],
      },
      {
        title: 'Load balancing',
        desc: 'The next request goes elsewhere',
        detail:
          'A personal request like /api/cart can’t be cached (Cache-Control: private). The proxy sends it to app-2 this time — round robin or least-connections — so the work is spread across the pool.',
        facts: [
          ['Chosen server', 'app-2 (10.0.0.22)'],
          ['Cacheable', 'No (private)'],
        ],
        packets: [eapi, ...hsB2, api, apiResp, eapiResp],
      },
    ],
    outro: {
      title: 'One front door',
      text: 'The visitor only ever talked to the proxy. It ended TLS, answered from its cache when it could, and shared the rest of the work between two hidden servers.',
      facts: [
        ['Requests', '3'],
        ['Reached app servers', '2'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ DNS over HTTPS */

function buildDoh() {
  const name = 'www.example.com';
  const plain = [
    udp({
      from: 'client', to: 'ispdns', sport: 58841, dport: 53, color: 'red', label: 'PLAIN DNS', proto: 'DNS',
      info: 'Standard query 0x2f61 A www.example.com', app: dns({ id: 0x2f61, rd: true, q: [name, 'A'] }),
    }),
    udp({
      from: 'ispdns', to: 'client', sport: 53, dport: 58841, color: 'red', label: 'PLAIN REPLY', proto: 'DNS',
      info: 'Standard query response 0x2f61 A www.example.com A 203.0.113.10',
      app: dns({ id: 0x2f61, response: true, rd: true, ra: true, q: [name, 'A'], an: [{ name, type: 'A', ttl: 3600, data: '203.0.113.10' }] }),
    }),
  ];
  const c = tcpx('client', 'doh', 52990, 443);
  const hs = c.handshake();
  const T = (side: 'a' | 'b', app: AppWriter, label: string, info: string, color: PacketColor = 'teal') =>
    c.send(side, app, { label, proto: 'TLSv1.3', info, color });
  const ch = T('a', clientHello('dns.google'), 'CLIENT HELLO', 'Client Hello (SNI=dns.google)');
  const sh = T('b', serverHello('dns.google'), 'SERVER HELLO', 'Server Hello, Change Cipher Spec, Application Data');
  const fin = T('a', clientFinished('dns.google'), 'FINISHED', 'Change Cipher Spec, Application Data');
  const q1 = T('a', encrypted(141, 'HTTP/2 POST /dns-query · application/dns-message · DNS query A www.example.com', 'dohq1'), 'QUERY 🔒', 'Application Data (HTTP/2 POST /dns-query)', 'blue');
  const a1 = T('b', encrypted(166, 'HTTP/2 200 · application/dns-message · A 203.0.113.10', 'doha1'), 'ANSWER 🔒', 'Application Data (HTTP/2 200)', 'violet');
  const q2 = T('a', encrypted(138, 'HTTP/2 POST /dns-query · DNS query A img.example.com (new stream)', 'dohq2'), 'QUERY 🔒', 'Application Data (stream 3)', 'blue');
  const a2 = T('b', encrypted(163, 'HTTP/2 200 · A 203.0.113.12', 'doha2'), 'ANSWER 🔒', 'Application Data (stream 3)', 'violet');
  const ack = c.ack('a');

  return lesson({
    id: 'doh',
    name: 'DNS over HTTPS',
    title: 'Private lookups',
    layer: 7,
    tagline: 'Hide your DNS questions inside ordinary HTTPS.',
    nodes: [
      { id: 'client', x: 8, y: 60 },
      { id: 'router', x: 27, y: 60, label: 'Café Wi-Fi' },
      { id: 'internet', x: 50, y: 60 },
      { id: 'ispdns', x: 78, y: 22 },
      { id: 'doh', x: 82, y: 72 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'internet'],
      ['internet', 'ispdns'],
      ['internet', 'doh'],
    ],
    legend: [
      ['red', 'Plain DNS (readable)'],
      ['green', 'TCP control'],
      ['teal', 'TLS handshake'],
      ['blue', 'Encrypted query'],
      ['violet', 'Encrypted answer'],
    ],
    overview: {
      full: 'DNS Queries over HTTPS (DoH)',
      description:
        'Classic DNS is a postcard: anyone on the café Wi-Fi or at your ISP can read every name you look up, and even forge the answer. DoH puts the very same DNS message inside an HTTPS request to a resolver such as dns.google, so the network sees only an encrypted connection.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', 'TCP 443 (like any HTTPS)'],
        ['Media type', 'application/dns-message'],
        ['Path', 'https://dns.google/dns-query'],
        ['Spec', 'RFC 8484'],
      ],
    },
    steps: [
      {
        title: 'Plain DNS',
        desc: 'Readable — and forgeable — on the way',
        detail:
          'Without DoH the laptop sends a UDP datagram to port 53. Open it: the name www.example.com is right there. The Wi-Fi owner, other guests and the ISP can log it, and an attacker could answer first with a fake address.',
        facts: [
          ['Transport', 'UDP 53'],
          ['Encrypted', 'No'],
          ['Tamper-proof', 'No'],
        ],
        packets: plain,
      },
      {
        title: 'Connect to the DoH resolver',
        desc: 'A normal HTTPS connection',
        detail:
          'With DoH switched on, the browser opens a TCP connection to dns.google on port 443. Its address (8.8.8.8) is built into the setting, so no plain lookup is needed to find it.',
        packets: hs,
      },
      {
        title: 'TLS handshake',
        desc: 'The one name still visible',
        detail:
          'The usual TLS 1.3 handshake. The Client Hello’s SNI says “dns.google” — so the network can tell you use a DoH service, but not what you ask it. The resolver’s certificate proves no one is impersonating it.',
        facts: [['Visible SNI', 'dns.google']],
        packets: [ch, sh, fin],
      },
      {
        title: 'The query, encrypted',
        desc: 'HTTP/2 POST application/dns-message',
        detail:
          'The browser builds the exact same binary DNS query as before and sends it as the body of an HTTP/2 POST to /dns-query. On the wire it is just another TLS record.',
        packets: [q1],
      },
      {
        title: 'The answer, encrypted',
        desc: 'Same DNS answer, inside HTTPS',
        detail:
          'dns.google replies with status 200 and a DNS answer body: A 203.0.113.10. Nobody in between could read it — or change it without breaking TLS.',
        packets: [a1],
      },
      {
        title: 'More lookups, same connection',
        desc: 'No new handshakes',
        detail:
          'Every further lookup becomes a new HTTP/2 stream on the already-open connection, so DoH is barely slower than plain DNS after the first query.',
        packets: [q2, a2, ack],
      },
      {
        title: 'What is still visible',
        desc: 'Privacy has limits',
        detail:
          'DoH hides lookups from the local network, not from the resolver: dns.google still sees every name. And when the browser then connects to 203.0.113.10, that address and the website’s own SNI are visible again (Encrypted Client Hello closes that gap).',
        facts: [
          ['Hidden from', 'Wi-Fi, ISP'],
          ['Still sees names', 'The DoH resolver'],
          ['Still visible', 'Site IP and SNI'],
        ],
        focus: ['doh', 'router'],
      },
    ],
    outro: {
      title: 'Lookups kept private',
      text: 'The DNS messages never changed — only the envelope did. Wrapped in HTTPS, they were invisible and tamper-proof to everyone between the laptop and the resolver.',
      facts: [
        ['Plain queries', '1'],
        ['Encrypted queries', '2'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ DNSSEC */

const DT = { A: 1, NS: 2, OPT: 41, DS: 43, RRSIG: 46, DNSKEY: 48 } as const;
type DType = Exclude<keyof typeof DT, 'OPT'>;

interface SRR {
  name: string;
  type: DType;
  ttl: number;
  rdata: number[];
  text: string;
}

const qn = (n: string) => [...n.split('.').filter(Boolean).flatMap((p) => [p.length, ...ascii(p)]), 0];
const SIG_EXP = Date.UTC(2026, 11, 1) / 1000;
const SIG_INC = Date.UTC(2026, 10, 1) / 1000;

const rrA = (name: string, ip: string, ttl = 3600): SRR => ({ name, type: 'A', ttl, rdata: ipb(ip), text: `${name} A ${ip}` });
const rrDS = (name: string, tag: number, ttl = 86400): SRR => ({
  name, type: 'DS', ttl, rdata: [...u16(tag), 13, 2, ...rand('ds' + name, 32)],
  text: `${name} DS · key tag ${tag} · alg 13 · SHA-256 digest`,
});
const rrKEY = (name: string, ksk: boolean, tag: number, ttl = 3600): SRR => ({
  name, type: 'DNSKEY', ttl, rdata: [...u16(ksk ? 257 : 256), 3, 13, ...rand(`key${name}${ksk}`, 64)],
  text: `${name || '.'} DNSKEY ${ksk ? '257 (KSK)' : '256 (ZSK)'} · alg 13 ECDSA P-256 · tag ${tag}`,
});
const rrSIG = (name: string, covered: DType, signer: string, tag: number, ttl = 3600): SRR => ({
  name, type: 'RRSIG', ttl,
  rdata: [
    ...u16(DT[covered]), 13, name.split('.').filter(Boolean).length, ...u32(ttl), ...u32(SIG_EXP), ...u32(SIG_INC),
    ...u16(tag), ...qn(signer), ...rand(`sig${name}${covered}${tag}`, 64),
  ],
  text: `RRSIG over ${covered} · signed by ${signer || '.'} key ${tag} · valid to 2026-12-01`,
});

function sdns(o: {
  id: number;
  response?: boolean;
  aa?: boolean;
  rd?: boolean;
  ra?: boolean;
  ad?: boolean;
  rcode?: number;
  q: [string, DType];
  an?: SRR[];
  ns?: SRR[];
  ar?: SRR[];
  doBit: boolean;
}): AppWriter {
  return (w: Writer) => {
    const an = o.an ?? [];
    const ns = o.ns ?? [];
    const ar = o.ar ?? [];
    w.begin('app', 'Domain Name System');
    w.f('Transaction ID', hex(o.id, 4), u16(o.id));
    const rcode = o.rcode ?? 0;
    const fl =
      (o.response ? 0x8000 : 0) | (o.aa ? 0x0400 : 0) | (o.rd ? 0x0100 : 0) | (o.ra ? 0x0080 : 0) | (o.ad ? 0x0020 : 0) | rcode;
    const desc = [
      o.response ? 'response' : 'query',
      o.aa && 'authoritative',
      o.rd && 'recursion desired',
      o.ra && 'recursion available',
      o.ad && 'AD: authenticated data',
      rcode === 2 && 'SERVFAIL',
    ]
      .filter(Boolean)
      .join(', ');
    w.f('Flags', `${hex(fl, 4)} (${desc})`, u16(fl));
    w.f('Questions', 1, u16(1));
    w.f('Answer records', an.length, u16(an.length));
    w.f('Authority records', ns.length, u16(ns.length));
    w.f('Additional records', ar.length + 1, u16(ar.length + 1));
    w.f('Query', `${o.q[0] || '.'} · type ${o.q[1]} · class IN`, [...qn(o.q[0]), ...u16(DT[o.q[1]]), ...u16(1)]);
    const rr = (section: string, r: SRR) =>
      w.f(`${section} · ${r.type}`, `${r.text} · TTL ${r.ttl}s`, [
        ...qn(r.name), ...u16(DT[r.type]), ...u16(1), ...u32(r.ttl), ...u16(r.rdata.length), ...r.rdata,
      ]);
    an.forEach((r) => rr('Answer', r));
    ns.forEach((r) => rr('Authority', r));
    ar.forEach((r) => rr('Additional', r));
    w.f(
      'Additional · OPT (EDNS0)',
      `UDP size 1232 · DO=${o.doBit ? '1 (please include signatures)' : '0'}`,
      [0, ...u16(DT.OPT), ...u16(1232), 0, 0, o.doBit ? 0x80 : 0, 0, 0, 0],
    );
    w.end(`${o.response ? (rcode === 2 ? 'SERVFAIL' : 'Response') : 'Query'} · ${o.q[1]} ${o.q[0] || '.'}${o.ad ? ' · AD' : ''}`);
  };
}

function buildDnssec() {
  const N = 'www.example.com';
  let port = 33000;
  const ask = (to: NodeId, id: number, q: [string, DType], label: string, color: PacketColor = 'blue') => {
    const sport = ++port;
    const p = udp({
      from: 'dns', to, sport, dport: 53, color, label, proto: 'DNS',
      info: `Standard query ${hex(id, 4)} ${q[1]} ${q[0] || '<Root>'} OPT (DO)`,
      app: sdns({ id, q, doBit: true }),
    });
    return { p, sport };
  };
  const ans = (from: NodeId, id: number, sport: number, q: [string, DType], an: SRR[], label: string, color: PacketColor = 'amber') =>
    udp({
      from, to: 'dns', sport: 53, dport: sport, color, label, proto: 'DNS',
      info: `Standard query response ${hex(id, 4)} ${q[1]} ${q[0] || '<Root>'} ${an.map((r) => r.type).join(' ')}`,
      app: sdns({ id, response: true, aa: true, q, an, doBit: true }),
    });

  const q0 = udp({
    from: 'client', to: 'dns', sport: 60411, dport: 53, color: 'blue', label: 'QUERY', proto: 'DNS',
    info: `Standard query 0x4a11 A ${N}`, app: sdns({ id: 0x4a11, rd: true, q: [N, 'A'], doBit: false }),
  });

  const s1 = ask('auth', 0x91c2, [N, 'A'], 'A? +DO');
  const r1 = ans('auth', 0x91c2, s1.sport, [N, 'A'], [rrA(N, '203.0.113.10'), rrSIG(N, 'A', 'example.com', 31406)], 'A + RRSIG');
  const s2 = ask('auth', 0x91c3, ['example.com', 'DNSKEY'], 'DNSKEY?');
  const r2 = ans('auth', 0x91c3, s2.sport, ['example.com', 'DNSKEY'], [
    rrKEY('example.com', true, 2371), rrKEY('example.com', false, 31406), rrSIG('example.com', 'DNSKEY', 'example.com', 2371),
  ], 'DNSKEY SET');
  const s3 = ask('tld', 0x2210, ['example.com', 'DS'], 'DS?');
  const r3 = ans('tld', 0x2210, s3.sport, ['example.com', 'DS'], [rrDS('example.com', 2371), rrSIG('example.com', 'DS', 'com', 4534, 86400)], 'DS + RRSIG', 'violet');
  const s4 = ask('tld', 0x2211, ['com', 'DNSKEY'], 'DNSKEY?');
  const r4 = ans('tld', 0x2211, s4.sport, ['com', 'DNSKEY'], [
    rrKEY('com', true, 19718, 86400), rrKEY('com', false, 4534, 86400), rrSIG('com', 'DNSKEY', 'com', 19718, 86400),
  ], 'DNSKEY SET', 'violet');
  const s5 = ask('root', 0x7a01, ['com', 'DS'], 'DS?');
  const r5 = ans('root', 0x7a01, s5.sport, ['com', 'DS'], [rrDS('com', 19718), rrSIG('com', 'DS', '', 46780, 86400)], 'DS + RRSIG', 'pink');
  const s6 = ask('root', 0x7a02, ['', 'DNSKEY'], 'DNSKEY?');
  const r6 = ans('root', 0x7a02, s6.sport, ['', 'DNSKEY'], [
    rrKEY('', true, 20326, 172800), rrKEY('', false, 46780, 172800), rrSIG('', 'DNSKEY', '', 20326, 172800),
  ], 'ROOT KEYS', 'pink');

  const final = udp({
    from: 'dns', to: 'client', sport: 53, dport: 60411, color: 'green', label: 'AD ✓', proto: 'DNS',
    info: `Standard query response 0x4a11 A ${N} A 203.0.113.10 (authenticated)`,
    app: sdns({ id: 0x4a11, response: true, rd: true, ra: true, ad: true, q: [N, 'A'], an: [rrA(N, '203.0.113.10')], doBit: false }),
  });

  const S = 'shop.example.com';
  const q7 = udp({
    from: 'client', to: 'dns', sport: 60502, dport: 53, color: 'blue', label: 'QUERY', proto: 'DNS',
    info: `Standard query 0x4a20 A ${S}`, app: sdns({ id: 0x4a20, rd: true, q: [S, 'A'], doBit: false }),
  });
  const s7 = ask('auth', 0x91d0, [S, 'A'], 'A? +DO');
  const forged = udp({
    from: 'spoofer', to: 'dns', src: IP('auth'), sport: 53, dport: s7.sport, color: 'red', label: 'FORGED', proto: 'DNS',
    info: `Standard query response 0x91d0 A ${S} A 198.51.100.66 (spoofed source, no RRSIG)`,
    app: sdns({ id: 0x91d0, response: true, aa: true, q: [S, 'A'], an: [rrA(S, '198.51.100.66', 86400)], doBit: true }),
  });
  const fail = udp({
    from: 'dns', to: 'client', sport: 53, dport: 60502, color: 'red', label: 'SERVFAIL', proto: 'DNS',
    info: `Standard query response 0x4a20 Server failure A ${S}`,
    app: sdns({ id: 0x4a20, response: true, rd: true, ra: true, rcode: 2, q: [S, 'A'], doBit: false }),
  });

  return lesson({
    id: 'dnssec',
    name: 'DNSSEC',
    title: 'Signed answers',
    layer: 7,
    tagline: 'A chain of signatures from the root proves an answer is genuine.',
    nodes: [
      { id: 'client', x: 8, y: 54 },
      { id: 'router', x: 24, y: 54 },
      { id: 'dns', x: 45, y: 54, label: 'Validating resolver' },
      { id: 'root', x: 76, y: 16 },
      { id: 'tld', x: 89, y: 48 },
      { id: 'auth', x: 78, y: 84 },
      { id: 'spoofer', x: 45, y: 86 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'dns'],
      ['dns', 'root'],
      ['dns', 'tld'],
      ['dns', 'auth'],
      ['spoofer', 'dns'],
    ],
    legend: [
      ['blue', 'Query'],
      ['amber', 'example.com zone'],
      ['violet', '.com zone'],
      ['pink', 'Root zone'],
      ['green', 'Validated'],
      ['red', 'Forged / failed'],
    ],
    overview: {
      full: 'DNS Security Extensions',
      description:
        'Plain DNS answers carry no proof: whoever replies first wins. With DNSSEC every zone signs its records, and each parent zone vouches for its child’s key. A validating resolver follows that chain up to the root key it already trusts — and throws away anything that doesn’t check out.',
      facts: [
        ['Layer', 'Application (7)'],
        ['New records', 'RRSIG, DNSKEY, DS'],
        ['Signals', 'DO bit (ask), AD bit (validated)'],
        ['Algorithm here', '13 = ECDSA P-256'],
        ['Spec', 'RFC 4033–4035'],
      ],
    },
    steps: [
      {
        title: 'Ask the resolver',
        desc: 'An ordinary question from the laptop',
        detail:
          'The laptop sends a normal recursive query. All the cryptography happens in the resolver; the laptop just needs to trust it and read one flag in the answer.',
        packets: [q0],
      },
      {
        title: 'A signed answer',
        desc: 'The DO bit asks for signatures',
        detail:
          'The resolver sets the DO (“DNSSEC OK”) bit in the EDNS0 OPT record. example.com’s nameserver returns the A record plus an RRSIG: a signature over that record made with the zone’s signing key, tag 31406. (Referrals from earlier lessons are already cached.)',
        facts: [
          ['Record', 'A 203.0.113.10'],
          ['Signature', 'RRSIG by key 31406'],
        ],
        packets: [s1.p, r1],
      },
      {
        title: 'Fetch the zone’s keys',
        desc: 'DNSKEY: the ZSK and the KSK',
        detail:
          'To check the signature the resolver needs the public key. The DNSKEY set holds two: the zone-signing key (256, tag 31406) that signs records, and the key-signing key (257, tag 2371) that signs the key set itself.',
        facts: [
          ['ZSK', 'tag 31406, signs records'],
          ['KSK', 'tag 2371, signs keys'],
        ],
        packets: [s2.p, r2],
      },
      {
        title: 'The parent vouches',
        desc: '.com publishes a DS for example.com',
        detail:
          'Anyone can sign with a key they made up, so who vouches for 2371? The .com zone does: its DS record holds a SHA-256 digest of example.com’s KSK, and .com signs that DS with its own key. The resolver also fetches .com’s keys to check that signature.',
        facts: [
          ['DS', 'digest of key 2371'],
          ['Signed by', '.com key 4534'],
        ],
        packets: [s3.p, r3, s4.p, r4],
      },
      {
        title: 'Up to the root',
        desc: 'The trust anchor',
        detail:
          'The same again one level up: the root zone publishes a DS for .com and signs it. The root’s own key-signing key (tag 20326) is the trust anchor — it ships with the resolver software, so the chain ends here.',
        facts: [
          ['Trust anchor', 'Root KSK 20326'],
          ['Chain', 'root → com → example.com'],
        ],
        packets: [s5.p, r5, s6.p, r6],
      },
      {
        title: 'Validated',
        desc: 'The AD flag is set',
        detail:
          'Every signature checked out and every key was vouched for by its parent. The resolver answers the laptop with the AD (Authenticated Data) flag set. Next time, the keys are cached and validation costs almost nothing.',
        facts: [['Flag', 'AD = 1']],
        packets: [final],
      },
      {
        title: 'A forged answer',
        desc: 'Rejected, not believed',
        detail:
          'Later an attacker races a fake reply for shop.example.com, spoofing the real nameserver’s address. Without DNSSEC it would be cached for a day. But example.com is signed and the forgery has no valid RRSIG, so the resolver discards it and tells the laptop SERVFAIL rather than hand out a lie.',
        facts: [
          ['Forged A', '198.51.100.66'],
          ['Result', 'SERVFAIL, nothing cached'],
        ],
        packets: [q7, s7.p, forged, fail],
      },
    ],
    outro: {
      title: 'Answers you can prove',
      text: 'DNSSEC does not hide anything — every record is still readable. What it adds is proof: a chain of signatures from the root down, so a forged answer is caught instead of trusted.',
      facts: [
        ['Signatures checked', '4'],
        ['Forgeries accepted', '0'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ QUIC */

const CID_INIT = rand('quic-initial-dcid', 8);
const CID_C = rand('quic-client-cid', 8);
const CID_S = rand('quic-server-cid', 8);
const cidHex = (c: number[]) => hexStr(c).replace(/ /g, '');

function qLong(
  w: Writer,
  o: { type: 'Initial' | 'Handshake'; dcid: number[]; scid: number[]; pn: number; payload: number; what: string; seed: string },
) {
  const tbits = o.type === 'Initial' ? 0 : 2;
  w.begin('app', `QUIC ${o.type} packet`);
  w.f('Header form · Fixed bit · Type', `long header · 1 · ${o.type} (${tbits}) · low bits hidden by header protection`, [
    0xc0 | (tbits << 4) | 0x03,
  ]);
  w.f('Version', 'QUIC v1 (0x00000001)', u32(1));
  w.f('Destination CID length', 8, [8]);
  w.f('Destination connection ID', cidHex(o.dcid), o.dcid);
  w.f('Source CID length', 8, [8]);
  w.f('Source connection ID', cidHex(o.scid), o.scid);
  if (o.type === 'Initial') w.f('Token length', '0 (no retry token)', [0]);
  const len = 4 + o.payload;
  w.f('Length', `${len} bytes (packet number + payload)`, [0x40 | (len >> 8), len & 255]);
  w.f('Packet number', `${o.pn} (protected)`, rand(o.seed + 'pn', 4));
  w.f('Encrypted payload', o.what, rand(o.seed, o.payload));
  w.end(`${o.type} · PN ${o.pn}`);
}

function qShort(w: Writer, o: { dcid: number[]; pn: number; payload: number; what: string; seed: string; sum: string }) {
  w.begin('app', 'QUIC 1-RTT packet');
  w.f('Header form · Fixed · Spin · Key phase', 'short header · 1 · 0 · 0 (low bits protected)', [0x43]);
  w.f('Destination connection ID', cidHex(o.dcid), o.dcid);
  w.f('Packet number', `${o.pn} (protected)`, rand(o.seed + 'pn', 4));
  w.f('Encrypted payload', o.what, rand(o.seed, o.payload));
  w.end(`1-RTT · PN ${o.pn} · ${o.sum}`);
}

function buildQuic() {
  const cp = 54122;
  const up = (from: NodeId, to: NodeId, app: AppWriter, label: string, info: string, color: PacketColor, lost = false) =>
    udp({
      from, to, sport: from === 'client' ? cp : 443, dport: from === 'client' ? 443 : cp,
      color, label, proto: 'QUIC', info, app, lost,
    });

  const ci = up(
    'client', 'web',
    (w) => qLong(w, { type: 'Initial', dcid: CID_INIT, scid: CID_C, pn: 0, payload: 1170, what: 'CRYPTO (TLS Client Hello, SNI www.example.com) + PADDING to 1200 bytes', seed: 'qci' }),
    'INITIAL', `Initial, DCID=${cidHex(CID_INIT)}, SCID=${cidHex(CID_C)}, PKN: 0, CRYPTO, PADDING`, 'teal',
  );
  const si = up(
    'web', 'client',
    (w) => {
      qLong(w, { type: 'Initial', dcid: CID_C, scid: CID_S, pn: 0, payload: 117, what: 'ACK + CRYPTO (TLS Server Hello)', seed: 'qsi' });
      qLong(w, { type: 'Handshake', dcid: CID_C, scid: CID_S, pn: 0, payload: 1020, what: 'CRYPTO (Encrypted Extensions, Certificate, Certificate Verify, Finished)', seed: 'qsh' });
    },
    'SERVER HELLO', `Initial (ACK, CRYPTO) + Handshake (CRYPTO), SCID=${cidHex(CID_S)}`, 'teal',
  );
  const cf = up(
    'client', 'web',
    (w) => {
      qLong(w, { type: 'Initial', dcid: CID_S, scid: CID_C, pn: 1, payload: 1010, what: 'ACK + PADDING', seed: 'qci2' });
      qLong(w, { type: 'Handshake', dcid: CID_S, scid: CID_C, pn: 0, payload: 58, what: 'ACK + CRYPTO (TLS Finished)', seed: 'qch' });
      qShort(w, { dcid: CID_S, pn: 0, payload: 72, what: 'STREAM 0: HTTP/3 HEADERS (GET / · :authority www.example.com)', seed: 'q1c0', sum: 'GET /' });
    },
    'FINISHED + GET', 'Initial (ACK) + Handshake (Finished) + 1-RTT (STREAM 0: HEADERS GET /)', 'amber',
  );
  const s0 = up(
    'web', 'client',
    (w) => qShort(w, { dcid: CID_C, pn: 0, payload: 1150, what: 'HANDSHAKE_DONE + ACK + STREAM 0: HTTP/3 HEADERS (:status 200) + DATA (bytes 0–1099)', seed: 'q1s0', sum: '200 + data' }),
    '200 + DATA', 'Protected Payload (KP0), PKN: 0, HANDSHAKE_DONE, ACK, STREAM(0)', 'violet',
  );
  const s1 = up(
    'web', 'client',
    (w) => qShort(w, { dcid: CID_C, pn: 1, payload: 640, what: 'STREAM 0: DATA (bytes 1100–1719, FIN)', seed: 'q1s1', sum: 'data' }),
    'DATA', 'Protected Payload (KP0), PKN: 1, STREAM(0) FIN', 'violet', true,
  );
  const s2 = up(
    'web', 'client',
    (w) => qShort(w, { dcid: CID_C, pn: 2, payload: 60, what: 'STREAM 4: HTTP/3 HEADERS (favicon response, 204)', seed: 'q1s2', sum: 'stream 4' }),
    'STREAM 4', 'Protected Payload (KP0), PKN: 2, STREAM(4)', 'violet',
  );
  const a1 = up(
    'client', 'web',
    (w) => qShort(w, { dcid: CID_S, pn: 1, payload: 22, what: 'ACK (packets 0 and 2 — 1 is missing)', seed: 'q1c1', sum: 'ACK 0,2' }),
    'ACK 0,2', 'Protected Payload (KP0), PKN: 1, ACK ranges 0, 2', 'green',
  );
  const s3 = up(
    'web', 'client',
    (w) => qShort(w, { dcid: CID_C, pn: 3, payload: 640, what: 'STREAM 0: DATA (bytes 1100–1719, FIN) — resent in a NEW packet', seed: 'q1s3', sum: 'resent data' }),
    'RESENT', 'Protected Payload (KP0), PKN: 3, STREAM(0) FIN (retransmitted data)', 'red',
  );
  const a2 = up(
    'client', 'web',
    (w) => qShort(w, { dcid: CID_S, pn: 2, payload: 22, what: 'ACK (packets 0, 2, 3)', seed: 'q1c2', sum: 'ACK' }),
    'ACK', 'Protected Payload (KP0), PKN: 2, ACK', 'green',
  );
  const close = up(
    'client', 'web',
    (w) => qShort(w, { dcid: CID_S, pn: 3, payload: 24, what: 'CONNECTION_CLOSE (application, H3_NO_ERROR 0x100)', seed: 'q1c3', sum: 'close' }),
    'CLOSE', 'Protected Payload (KP0), PKN: 3, CONNECTION_CLOSE (H3_NO_ERROR)', 'slate',
  );

  return lesson({
    id: 'quic',
    name: 'QUIC',
    title: 'HTTP/3 over UDP',
    layer: 4,
    tagline: 'Transport and encryption in one handshake, on top of UDP.',
    ...webNodes('web', false),
    legend: [
      ['teal', 'Handshake'],
      ['amber', 'Request'],
      ['violet', 'Response'],
      ['green', 'ACK'],
      ['red', 'Resent data'],
    ],
    overview: {
      full: 'QUIC: a UDP-based multiplexed and secure transport',
      description:
        'HTTPS over TCP needs a TCP handshake and then a TLS handshake before the first request. QUIC folds both into one round trip, encrypts almost all of its own headers, and carries many independent streams, so one lost packet no longer stalls everything. It runs on UDP and powers HTTP/3.',
      facts: [
        ['Layer', 'Transport (4)'],
        ['Runs over', 'UDP 443'],
        ['Encryption', 'TLS 1.3, built in'],
        ['Setup', '1 round trip (0 on resume)'],
        ['Spec', 'RFC 9000, RFC 9114 (HTTP/3)'],
      ],
    },
    steps: [
      {
        title: 'Why a new transport',
        desc: 'TCP + TLS costs two round trips',
        detail:
          'The browser has learned (from an Alt-Svc header or a DNS HTTPS record) that www.example.com speaks HTTP/3. Instead of TCP to port 443 it will send UDP datagrams to port 443, and run its own reliability, congestion control and TLS inside them.',
        facts: [
          ['TCP + TLS 1.3', '2 RTT before the request'],
          ['QUIC', '1 RTT'],
        ],
        focus: ['client', 'web'],
      },
      {
        title: 'Client Initial',
        desc: 'TLS Client Hello in a long-header packet',
        detail:
          'The first datagram carries a TLS Client Hello in a CRYPTO frame. Its long header is readable — version 1 and the connection IDs — but the payload is encrypted with keys derived from the destination connection ID, and header protection hides the packet number. It is padded to 1200 bytes so the server may reply without amplification worries.',
        facts: [
          ['Packet type', 'Initial'],
          ['Datagram size', '≥ 1200 bytes'],
          ['Readable', 'Version, connection IDs'],
        ],
        packets: [ci],
      },
      {
        title: 'Server Initial + Handshake',
        desc: 'Two packets coalesced into one datagram',
        detail:
          'The server answers with an Initial packet (its Server Hello) and, in the same UDP datagram, a Handshake packet holding its certificate and Finished. It also picks its own connection ID. Both sides can now derive the 1-RTT keys.',
        packets: [si],
      },
      {
        title: 'Finished — and the request',
        desc: 'Data after just one round trip',
        detail:
          'The client’s next datagram finishes the handshake and already carries the HTTP/3 GET in a short-header 1-RTT packet on stream 0. Short headers expose almost nothing: one byte of flags and the connection ID.',
        facts: [
          ['Header', 'Short (1-RTT)'],
          ['Stream', '0 (request/response)'],
        ],
        packets: [cf],
      },
      {
        title: 'Response — one packet lost',
        desc: 'Other streams keep flowing',
        detail:
          'The server confirms the handshake (HANDSHAKE_DONE) and sends the response in several packets. Packet 1 is lost, yet packet 2, carrying a different stream, is delivered and used straight away. In TCP it would wait behind the gap. The client’s ACK lists exactly which packet numbers arrived.',
        facts: [
          ['Lost', 'packet 1 (stream 0)'],
          ['Not blocked', 'stream 4'],
        ],
        packets: [s0, s1, s2, a1],
      },
      {
        title: 'Loss recovery',
        desc: 'Same data, new packet number',
        detail:
          'The server notices packet 1 was skipped and resends the missing stream bytes — in a new packet, number 3. QUIC never reuses packet numbers, so an ACK can never be ambiguous about which copy arrived. The connection ID, not the IP address, identifies the connection, so it would even survive the phone switching networks.',
        facts: [
          ['Resent as', 'packet 3'],
          ['Connection identified by', 'connection ID'],
        ],
        packets: [s3, a2],
      },
      {
        title: 'Close',
        desc: 'CONNECTION_CLOSE, no FIN dance',
        detail: 'When the page is done the client sends a single encrypted CONNECTION_CLOSE frame with the HTTP/3 code H3_NO_ERROR. There is no four-way shutdown like TCP’s FIN exchange.',
        packets: [close],
      },
    ],
    outro: {
      title: 'Faster and more private',
      text: 'One round trip set up an encrypted connection and carried the request. A lost packet only delayed its own stream, and it was resent under a fresh packet number. Almost nothing about the connection was readable on the wire.',
      facts: [
        ['Round trips to request', '1'],
        ['Datagrams', '10'],
      ],
    },
  });
}

export const PACK: Lesson[] = [buildProxy(), buildSocks(), buildReverse(), buildDoh(), buildDnssec(), buildQuic()];
