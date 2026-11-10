# Network Explorer

**Learn how the internet works, one packet at a time.**

Network Explorer is an interactive lesson site. Each lesson animates real network traffic on a diagram and explains every step. Each packet is built byte by byte, with valid checksums and lengths, so you can open any packet and see what every field means.

Built by [@Jamil255](https://github.com/Jamil255).

---

## Features

- **39 protocol lessons** in three groups:
  - **Core (11):** QUIC, TCP, UDP, IP, BGP, IPv6, ICMP, IGMP, Ethernet, PPPoE, Wi-Fi
  - **Application (19):** HTTP, WebSocket, WebRTC, SIP, RTSP, RTMP, DNS, DHCP, NTP, Captive Portal, SMTP, POP3, IMAP, FTP, SMB, HTTP Proxy, SOCKS5, Reverse Proxy, Modbus
  - **Security (9):** HTTPS, DNS over HTTPS, DNSSEC, WPA3, RADIUS, SSH, TLS, WireGuard, IPsec
- **Two views of the traffic**
  - **Network view:** packets travel across an animated diagram. Nodes appear as they join in, and the camera zooms to follow them.
  - **Sequence view:** a sequence diagram with one lifeline per device and step dividers.
- **Packet flow table** in the style of Wireshark: time, source, destination, protocol, info and size. Lost packets are marked.
- **Packet inspector**
  - A byte map of the layers (Ethernet, IP, TCP/UDP, application)
  - A decoded field tree, with a plain-language explanation for each field
  - A hex and ASCII dump, linked both ways to the tree: hover a field to see its bytes, or hover a byte to see its field
  - An **E.G.** badge on values that change in every real capture
- **Playback controls**
  - Play/pause, step forward/back and reset
  - Speed from 0.25× to 3×
  - A **one packet at a time** mode
- **Learning progress:** finished lessons are saved in your browser.
- **Search palette** (Ctrl K) that searches protocol names and every step.
- **Sidebar accordion:** the current lesson shows its steps, with done and current state.
- **OSI layer indicator** for the current protocol.
- **View tools:** hide the protocol list, diagram-only mode, fullscreen, and light/dark theme.
- **Interface in 8 languages:** English, اردو, हिन्दी, العربية, Español, Français, Deutsch and 中文. Urdu and Arabic switch to right-to-left. Lesson text itself is in English.
- **Responsive layout:** on phones the protocol list becomes a drawer and the playback controls move to the bottom of the screen.

## Keyboard shortcuts

| Key | Action |
|---|---|
| `Space` | Play or pause |
| `→` / `←` | Next / previous step |
| `S` | One packet at a time |
| `1` – `9` | Jump to step 1–9 |
| `[` / `]` | Slower / faster |
| `Esc` | Back to the overview, or close a dialog |
| `V` | Switch between network and sequence view |
| `D` | Diagram only |
| `L` | Show or hide the protocol list |
| `F` | Fullscreen |
| `T` | Light or dark theme |
| `Ctrl K` or `/` | Search |
| `N` / `P` | Next / previous protocol |
| `?` | Show all shortcuts |

In the packet inspector, `←` and `→` move between packets.

## Tech stack

- [Next.js 14](https://nextjs.org/) (App Router), with every lesson pre-rendered as a static page at `/lesson/<id>`
- React 18 and TypeScript
- [lucide-react](https://lucide.dev/) icons
- Plain CSS with theme tokens. There is no UI framework.

## Getting started

You need Node.js 18 or newer.

```bash
npm install
npm run dev        # http://localhost:3000
```

Production build:

```bash
npm run build
npm start
```

## Project structure

```
src/
├── app/
│   ├── layout.tsx            # fonts, theme bootstrap, metadata
│   ├── page.tsx              # "/" opens the HTTP lesson
│   ├── lesson/[id]/page.tsx  # one static page per lesson
│   └── globals.css           # the whole theme (light + dark)
├── components/
│   ├── Explorer.tsx          # app state: playback, keyboard, layout
│   ├── NetworkView.tsx       # animated diagram + camera
│   ├── SequenceView.tsx      # sequence diagram
│   ├── PacketTable.tsx       # packet flow table
│   ├── Inspector.tsx         # byte map, field tree, hex dump
│   ├── ExplainPanel.tsx      # overview / step details / summary
│   ├── Sidebar.tsx           # protocol list with tabs and step accordion
│   ├── Chrome.tsx            # top bar, controls, search, shortcuts, language menu
│   ├── i18n.tsx              # interface translations
│   ├── hooks.ts              # animation, persisted state, theme, progress
│   └── icons.tsx             # node icons and logo
├── engine/
│   ├── bytes.ts              # frame builder: Ethernet, IPv4/IPv6, TCP, UDP, ICMP, raw frames
│   ├── protocols.ts          # HTTP, DNS, DHCP, NTP, TLS 1.3, WebSocket writers
│   ├── fieldHelp.ts          # field explanations and "example value" rules
│   ├── graph.ts              # shortest path between nodes
│   ├── nodes.ts              # node registry (label, icon, address)
│   └── types.ts              # Lesson, Step, Packet types
└── lessons/
    ├── kit.ts                # helpers: packet(), udp(), tcp() session, dnsPair(), lesson()
    ├── index.ts              # lesson list, groups and order
    ├── web.ts, core.ts       # HTTP, HTTPS, WebSocket, DNS, DHCP, TCP, NTP, ICMP, SMTP
    └── pack-a … pack-e.ts    # the other 30 lessons
```

## Adding a lesson

A lesson is plain data: nodes, links, a legend, an overview, steps and an outro. Packets are built with the kit helpers, which handle addresses, MAC addresses, TCP sequence numbers and checksums for you.

```ts
import { http } from '@/engine/protocols';
import { dnsPair, lesson, tcp, webNodes } from './kit';

const c = tcp('client', 'web', 52344, 80);        // a TCP session; call its methods in time order
const hs = c.handshake();                           // SYN, SYN-ACK, ACK
const get = c.send('a', http(['GET / HTTP/1.1', 'Host: www.example.com']), {
  label: 'GET /', proto: 'HTTP', info: 'GET / HTTP/1.1', color: 'amber',
});

export const myLesson = lesson({
  id: 'my-lesson', name: 'Demo', title: 'A tiny example', layer: 7,
  tagline: 'One request.',
  ...webNodes(),
  legend: [['green', 'TCP'], ['amber', 'Request']],
  overview: { full: 'Demo Protocol', description: '…', facts: [['Port', '80']] },
  steps: [
    { title: 'Look up', desc: 'DNS', detail: '…', packets: dnsPair() },
    { title: 'Connect', desc: 'Handshake', detail: '…', packets: hs },
    { title: 'Ask', desc: 'GET', detail: '…', packets: [get] },
  ],
  outro: { title: 'Done', text: '…' },
});
```

To make the lesson appear in the app, add it to `src/lessons/index.ts`, in the `ALL` list and in one of the groups.

For traffic that is not IP, such as ARP, 802.11 or PPPoE discovery, build the frame with `rawFrame()` from `engine/bytes.ts` and pass it to `packet({ raw })`. A lesson can register its own devices with `registerNodes()` from `engine/nodes.ts`.

## Credits

Inspired by [Protocol Explorer](https://protocol-explorer-alpha.vercel.app/). This project is an independent implementation: its own code, lesson text and styling.
