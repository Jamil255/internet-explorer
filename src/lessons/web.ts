import { clientFinished, clientHello, encrypted, http, serverHello, wsFrame } from '@/engine/protocols';
import { dnsPair, lesson, tcp, webNodes } from './kit';

const HTML =
  '<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is reserved for documentation examples.</p></body></html>\n';

/* ------------------------------------------------------------------ HTTP */

function buildHttp() {
  const lookup = dnsPair();
  const c = tcp('client', 'web', 52344, 80);
  const hs = c.handshake();
  const get = c.send(
    'a',
    http([
      'GET / HTTP/1.1',
      'Host: www.example.com',
      'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/132.0',
      'Accept: text/html,application/xhtml+xml',
      'Accept-Language: en-US,en;q=0.9',
      'Connection: keep-alive',
    ]),
    { label: 'GET /', proto: 'HTTP', info: 'GET / HTTP/1.1', color: 'amber' },
  );
  const resp = c.send(
    'b',
    http(
      [
        'HTTP/1.1 200 OK',
        'Date: Wed, 11 Nov 2026 12:00:00 GMT',
        'Content-Type: text/html; charset=utf-8',
        `Content-Length: ${HTML.length}`,
        'Cache-Control: max-age=3600',
        'Connection: keep-alive',
      ],
      HTML,
    ),
    { label: '200 OK', proto: 'HTTP', info: 'HTTP/1.1 200 OK (text/html)', color: 'violet' },
  );
  const ack = c.ack('a');
  const close = c.close();

  return lesson({
    id: 'http',
    name: 'HTTP',
    title: 'Loading a web page',
    layer: 7,
    tagline: 'One request, one response — in plain text.',
    ...webNodes(),
    legend: [
      ['blue', 'DNS'],
      ['green', 'TCP control'],
      ['amber', 'Request'],
      ['violet', 'Response'],
    ],
    overview: {
      full: 'Hypertext Transfer Protocol',
      description:
        'HTTP is how browsers talk to web servers. The browser sends a request (a method like GET plus a path and some headers) and the server replies with a status code, headers and usually a body such as an HTML page. HTTP/1.1 is plain readable text, which makes it the perfect first protocol to watch.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', '80'],
        ['Runs over', 'TCP'],
        ['Format', 'Text headers + body'],
        ['Methods', 'GET, POST, PUT, DELETE…'],
        ['Spec', 'RFC 9110 / 9112'],
      ],
    },
    steps: [
      {
        title: 'You type a URL',
        desc: 'The browser plans a GET request',
        detail:
          'You enter http://www.example.com. The browser knows it must send “GET /” to that host — but packets are addressed to IP numbers, not names. Before anything else, it needs the server’s IP address.',
        facts: [
          ['URL', 'http://www.example.com/'],
          ['Method', 'GET'],
          ['First hop', 'Router 192.168.1.1'],
        ],
        focus: ['client'],
        typeUrl: 'http://www.example.com',
      },
      {
        title: 'Find the address',
        desc: 'A quick DNS lookup over UDP',
        detail:
          'The laptop asks its DNS resolver (8.8.8.8) “what is the A record for www.example.com?”. One small UDP datagram goes out on port 53 and one comes back carrying the answer: 203.0.113.10.',
        facts: [
          ['Resolver', '8.8.8.8'],
          ['Answer', '203.0.113.10'],
          ['Cached for', '3600 s'],
        ],
        packets: lookup,
      },
      {
        title: 'Open a TCP connection',
        desc: 'The three-way handshake',
        detail:
          'HTTP needs a reliable byte stream, so the laptop opens a TCP connection to port 80. SYN asks to connect, SYN-ACK agrees, ACK confirms. Both sides now know each other’s starting sequence numbers.',
        facts: [
          ['Client port', '52344 (random)'],
          ['Server port', '80'],
          ['Round trips', '1'],
        ],
        packets: hs,
      },
      {
        title: 'Send the request',
        desc: 'GET / HTTP/1.1',
        detail:
          'The request is just lines of text: a request line, then headers such as Host (which site we want — one server can host many) and Accept (which formats we understand). An empty line marks the end. Open the packet to read every byte.',
        facts: [
          ['Request line', 'GET / HTTP/1.1'],
          ['Host header', 'www.example.com'],
          ['Body', 'none'],
        ],
        packets: [get],
      },
      {
        title: 'Server responds',
        desc: '200 OK with the HTML page',
        detail:
          'The server answers with status 200 (OK), headers describing the content, and the HTML itself as the body. The TCP segment also acknowledges the request, so no separate ACK is needed.',
        facts: [
          ['Status', '200 OK'],
          ['Content-Type', 'text/html'],
          ['Body', `${HTML.length} bytes`],
        ],
        packets: [resp],
      },
      {
        title: 'Acknowledge and close',
        desc: 'ACK, then FIN in both directions',
        detail:
          'The laptop acknowledges the response. When the connection is no longer needed, each side sends FIN to say “I’m done sending”, and the last ACK closes it cleanly. (Real browsers often keep it open for the next request.)',
        packets: [ack, ...close],
      },
    ],
    outro: {
      title: 'Page delivered',
      text: 'DNS found the address, TCP built a reliable pipe and HTTP carried one request and one response. Everything was plain text — anyone on the path could read or change it. That is exactly what HTTPS fixes.',
      facts: [
        ['Round trips', '3 (DNS, TCP, HTTP)'],
        ['Encrypted', 'No'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ HTTPS */

function buildHttps() {
  const sni = 'www.example.com';
  const lookup = dnsPair('www.example.com', '203.0.113.10', 0x7c21, 61002);
  const c = tcp('client', 'web', 52811, 443);
  const hs = c.handshake();
  const ch = c.send('a', clientHello(sni), { label: 'CLIENT HELLO', proto: 'TLSv1.3', info: 'Client Hello (SNI=www.example.com)', color: 'teal' });
  const sh = c.send('b', serverHello(sni), {
    label: 'SERVER HELLO',
    proto: 'TLSv1.3',
    info: 'Server Hello, Change Cipher Spec, Application Data',
    color: 'teal',
  });
  const fin = c.send('a', clientFinished(sni), { label: 'FINISHED', proto: 'TLSv1.3', info: 'Change Cipher Spec, Application Data', color: 'teal' });
  const get = c.send('a', encrypted(96, 'GET / HTTP/1.1 … (encrypted HTTP request)', 'hget'), {
    label: 'GET 🔒',
    proto: 'TLSv1.3',
    info: 'Application Data (encrypted request)',
    color: 'amber',
  });
  const resp = c.send('b', encrypted(412, '200 OK + HTML page (encrypted HTTP response)', 'hresp'), {
    label: '200 OK 🔒',
    proto: 'TLSv1.3',
    info: 'Application Data (encrypted response)',
    color: 'violet',
  });
  const ack = c.ack('a');
  const close = c.close();

  return lesson({
    id: 'https',
    name: 'HTTPS',
    title: 'The secure web',
    layer: 7,
    tagline: 'HTTP wrapped inside a TLS 1.3 tunnel.',
    ...webNodes(),
    legend: [
      ['blue', 'DNS'],
      ['green', 'TCP control'],
      ['teal', 'TLS handshake'],
      ['amber', 'Encrypted request'],
      ['violet', 'Encrypted response'],
    ],
    overview: {
      full: 'HTTP over TLS',
      description:
        'HTTPS is ordinary HTTP sent through an encrypted TLS connection. TLS proves the server really is www.example.com (with a certificate) and agrees on fresh keys, so nobody on the path can read or tamper with the request or the page. TLS 1.3 needs just one round trip to set up.',
      facts: [
        ['Layer', 'Application (7) over TLS'],
        ['Port', '443'],
        ['Runs over', 'TCP'],
        ['Key exchange', 'X25519 (ECDHE)'],
        ['Cipher', 'AES-128-GCM'],
        ['Spec', 'RFC 8446 (TLS 1.3)'],
      ],
    },
    steps: [
      {
        title: 'DNS and TCP first',
        desc: 'Same start as plain HTTP',
        detail:
          'The laptop still looks up the address and opens a TCP connection — only now to port 443. DNS here is unencrypted, so the network can still see which name you looked up.',
        packets: [...lookup, ...hs],
      },
      {
        title: 'Client Hello',
        desc: '“Here’s what I support, and my key share”',
        detail:
          'The browser lists the TLS versions and cipher suites it supports, sends a random number and an X25519 public key, and names the site it wants in the SNI extension. SNI is sent in the clear — it’s the one thing the network can still read.',
        facts: [
          ['SNI (visible)', sni],
          ['Offers', 'TLS 1.3, TLS 1.2'],
          ['Key share', 'X25519'],
        ],
        packets: [ch],
      },
      {
        title: 'Server Hello + certificate',
        desc: 'Keys agreed, identity proven',
        detail:
          'The server picks TLS 1.3 and AES-128-GCM and sends its own key share. Both sides can now compute the same secret. Everything after Server Hello — including the certificate chain and its signature — is already encrypted.',
        facts: [
          ['Version', 'TLS 1.3'],
          ['Cipher', 'TLS_AES_128_GCM_SHA256'],
          ['Certificate', 'encrypted on the wire'],
        ],
        packets: [sh],
      },
      {
        title: 'Client Finished',
        desc: 'The handshake is sealed',
        detail:
          'The browser checks the certificate against its trusted authorities, verifies the signature, then sends Finished — a check value over the entire handshake. If anyone had altered a single byte, the values would not match.',
        packets: [fin],
      },
      {
        title: 'Encrypted request and response',
        desc: 'HTTP inside TLS records',
        detail:
          'The same GET request and 200 OK response are sent, but now inside TLS Application Data records. On the wire they look like random bytes; only the record length leaks. Open the packet — there is nothing readable left.',
        facts: [
          ['Visible', 'IPs, ports, sizes, timing'],
          ['Hidden', 'URL path, headers, page'],
        ],
        packets: [get, resp],
      },
      {
        title: 'Close',
        desc: 'ACK and FIN',
        detail: 'The page arrived safely. TCP closes the connection just as before.',
        packets: [ack, ...close],
      },
    ],
    outro: {
      title: 'Secure page delivered',
      text: 'One extra round trip bought privacy and integrity: the path can see that you talked to www.example.com, but not what you asked for or what came back.',
      facts: [
        ['Extra round trips', '1 (TLS 1.3)'],
        ['Still visible', 'SNI, DNS, IP addresses'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ WebSocket */

function buildWebSocket() {
  const c = tcp('client', 'chat', 50120, 80);
  const hs = c.handshake();
  const up = c.send(
    'a',
    http([
      'GET /live HTTP/1.1',
      'Host: chat.example.com',
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
      'Sec-WebSocket-Version: 13',
    ]),
    { label: 'UPGRADE', proto: 'HTTP', info: 'GET /live HTTP/1.1 (Upgrade: websocket)', color: 'amber' },
  );
  const sw = c.send(
    'b',
    http([
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
    ]),
    { label: '101', proto: 'HTTP', info: 'HTTP/1.1 101 Switching Protocols', color: 'violet' },
  );
  const m1 = c.send('a', wsFrame({ text: 'hi everyone!', masked: true, seed: 'm1' }), {
    label: 'TEXT ↑',
    proto: 'WebSocket',
    info: 'WebSocket Text [FIN] [MASKED] "hi everyone!"',
    color: 'pink',
  });
  const p1 = c.send('b', wsFrame({ text: 'Sara: hey! 👋', masked: false, seed: 'p1' }), {
    label: 'PUSH ↓',
    proto: 'WebSocket',
    info: 'WebSocket Text [FIN] "Sara: hey! 👋"',
    color: 'violet',
  });
  const p2 = c.send('b', wsFrame({ text: 'Omar joined the room', masked: false, seed: 'p2' }), {
    label: 'PUSH ↓',
    proto: 'WebSocket',
    info: 'WebSocket Text [FIN] "Omar joined the room"',
    color: 'violet',
  });
  const ack = c.ack('a');
  const ping = c.send('b', wsFrame({ opcode: 9, masked: false, seed: 'ping' }), { label: 'PING', proto: 'WebSocket', info: 'WebSocket Ping [FIN]', color: 'slate' });
  const pong = c.send('a', wsFrame({ opcode: 10, masked: true, seed: 'pong' }), { label: 'PONG', proto: 'WebSocket', info: 'WebSocket Pong [FIN] [MASKED]', color: 'slate' });
  const cl1 = c.send('a', wsFrame({ opcode: 8, close: 1000, masked: true, seed: 'c1' }), { label: 'CLOSE', proto: 'WebSocket', info: 'WebSocket Connection Close [FIN] [MASKED]', color: 'pink' });
  const cl2 = c.send('b', wsFrame({ opcode: 8, close: 1000, masked: false, seed: 'c2' }), { label: 'CLOSE', proto: 'WebSocket', info: 'WebSocket Connection Close [FIN]', color: 'violet' });
  const close = c.close();

  return lesson({
    id: 'websocket',
    name: 'WebSocket',
    title: 'Live updates',
    layer: 7,
    tagline: 'Turn one HTTP request into a two-way live channel.',
    ...webNodes('chat', false),
    legend: [
      ['green', 'TCP control'],
      ['amber', 'HTTP upgrade'],
      ['pink', 'Client → server'],
      ['violet', 'Server → client'],
      ['slate', 'Keep-alive'],
    ],
    overview: {
      full: 'The WebSocket Protocol',
      description:
        'Plain HTTP only answers when asked. WebSocket starts as an HTTP request, then “upgrades” the same TCP connection into a full-duplex channel of small frames. Either side can send at any time — perfect for chat, live scores and multiplayer games.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Ports', '80 (ws) / 443 (wss)'],
        ['Runs over', 'TCP'],
        ['Frame overhead', '2–14 bytes'],
        ['Spec', 'RFC 6455'],
      ],
    },
    steps: [
      {
        title: 'Connect',
        desc: 'A normal TCP handshake',
        detail: 'The chat page opens a TCP connection to chat.example.com, exactly like any HTTP request would. (A real site would use wss:// over TLS; this lesson keeps it readable.)',
        packets: hs,
      },
      {
        title: 'Ask to upgrade',
        desc: 'GET with Upgrade: websocket',
        detail:
          'The browser sends an HTTP GET with “Upgrade: websocket” and a random Sec-WebSocket-Key. This tells the server it wants to switch this connection to a different protocol.',
        packets: [up],
      },
      {
        title: '101 Switching Protocols',
        desc: 'From now on: frames, not HTTP',
        detail:
          'The server agrees with status 101 and proves it understood by hashing the key into Sec-WebSocket-Accept. After this response, no more HTTP is spoken on this connection.',
        packets: [sw],
      },
      {
        title: 'Send a message',
        desc: 'A masked text frame',
        detail:
          'Your message travels as a tiny frame: 2 header bytes, a 4-byte masking key and the text XOR-ed with that key. Browsers must mask what they send so that confused proxies can’t mistake frames for HTTP.',
        facts: [
          ['Opcode', '1 (text)'],
          ['Masked', 'yes (client → server)'],
        ],
        packets: [m1],
      },
      {
        title: 'Server pushes updates',
        desc: 'No request needed',
        detail: 'Here is the magic: the server sends new messages the moment they happen, without the browser asking. Server frames are not masked.',
        packets: [p1, p2, ack],
      },
      {
        title: 'Keep-alive',
        desc: 'Ping and Pong',
        detail: 'To check the connection is still alive (and keep NAT routers from forgetting it), the server sends a Ping control frame; the browser answers with Pong automatically.',
        packets: [ping, pong],
      },
      {
        title: 'Close',
        desc: 'Close frames, then TCP FIN',
        detail: 'Leaving the page sends a Close frame with code 1000 (normal). The server echoes it, and TCP then closes the connection.',
        packets: [cl1, cl2, ...close],
      },
    ],
    outro: {
      title: 'Two-way channel',
      text: 'One HTTP request became a long-lived pipe where both sides talk freely with just a few bytes of overhead per message.',
      facts: [['Messages', '3 text, 1 ping/pong']],
    },
  });
}

export const http1 = buildHttp();
export const https = buildHttps();
export const websocket = buildWebSocket();
