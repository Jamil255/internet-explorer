// Pack A: mail download (POP3, IMAP), files (FTP, SMB), remote login (SSH) and the TLS handshake.
import { ascii, hex, rand, u16, u24, u32, type AppWriter, type Writer } from '@/engine/bytes';
import { registerNodes } from '@/engine/nodes';
import { clientFinished, clientHello, data, lines } from '@/engine/protocols';
import type { Lesson, NodeId } from '@/engine/types';
import { lesson, tcp, webNodes } from './kit';

registerNodes({
  pop: { label: 'pop.example.org', icon: 'mail', ip: '203.0.113.30' },
  imap: { label: 'imap.example.org', icon: 'mail', ip: '203.0.113.31' },
  ftp: { label: 'ftp.example.org', icon: 'folder', ip: '203.0.113.40' },
  nas: { label: 'NAS (shared folders)', icon: 'hdd', ip: '192.168.1.20' },
  sshsrv: { label: 'server.example.org', icon: 'server', ip: '203.0.113.60' },
  tlssrv: { label: 'shop.example.com', icon: 'lock', ip: '203.0.113.70' },
});

/* ------------------------------------------------------------------ shared helpers */

/** One text session: client commands (amber) and server replies (violet). */
function textSession(server: NodeId, cport: number, sport: number, proto: string, name: string) {
  const c = tcp('client', server, cport, sport);
  const S = (ls: string[], label: string, info = ls[0]) =>
    c.send('b', lines(name, ls, () => 'Reply'), { label, proto, info: `S: ${info}`, color: 'violet' });
  const C = (ls: string[], label: string, info = ls[0]) =>
    c.send('a', lines(name, ls, () => 'Command'), { label, proto, info: `C: ${info}`, color: 'amber' });
  return { c, S, C };
}

/* ------------------------------------------------------------------ POP3 */

const MAIL_1 = [
  'From: Sara <sara@example.net>',
  'To: Amir <amir@example.org>',
  'Subject: Re: Lunch tomorrow?',
  'Date: Wed, 11 Nov 2026 12:20:00 +0000',
  '',
  'Sounds good - 1pm at the usual place!',
];

function buildPop3() {
  const { c, S, C } = textSession('pop', 50311, 110, 'POP3', 'Post Office Protocol v3');
  const hs = c.handshake();
  const greet = S(['+OK POP3 server ready <1896.1794312000@pop.example.org>'], '+OK');
  const user = C(['USER amir'], 'USER');
  const userOk = S(['+OK send your password'], '+OK');
  const pass = C(['PASS correct-horse-battery'], 'PASS');
  const passOk = S(['+OK logged in, 2 messages'], '+OK');
  const stat = C(['STAT'], 'STAT');
  const statOk = S(['+OK 2 1904'], '+OK', '+OK 2 1904 (2 messages, 1904 bytes)');
  const list = C(['LIST'], 'LIST');
  const listOk = S(['+OK 2 messages', '1 412', '2 1492', '.'], 'LIST', '+OK 2 messages (scan listing)');
  const retr = C(['RETR 1'], 'RETR 1');
  const retrOk = S(['+OK 412 octets', ...MAIL_1, '.'], 'MESSAGE', '+OK 412 octets (message follows)');
  const dele = C(['DELE 1'], 'DELE 1');
  const deleOk = S(['+OK message 1 marked for deletion'], '+OK');
  const quit = C(['QUIT'], 'QUIT');
  const bye = S(['+OK bye, 1 message deleted'], '+OK');
  const close = c.close();

  return lesson({
    id: 'pop3',
    name: 'POP3',
    title: 'Downloading email',
    layer: 7,
    tagline: 'Log in, download, delete — mail moves to your device.',
    ...webNodes('pop', false),
    legend: [
      ['green', 'TCP control'],
      ['amber', 'Command'],
      ['violet', 'Reply'],
    ],
    overview: {
      full: 'Post Office Protocol, version 3',
      description:
        'POP3 is the simplest way to collect mail: the app logs in, downloads new messages and usually deletes them from the server. The mailbox then lives on your device. Each command is one line of text and every reply starts with +OK or -ERR.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Ports', '110 (plain / STLS), 995 (TLS)'],
        ['Runs over', 'TCP'],
        ['Model', 'Download, then delete'],
        ['Replies', '+OK or -ERR'],
        ['Spec', 'RFC 1939'],
      ],
    },
    steps: [
      {
        title: 'Connect',
        desc: 'TCP to port 110, then a greeting',
        detail:
          'The mail app opens a TCP connection to pop.example.org and the server greets it with +OK. This lesson uses plain port 110 so you can read every byte — a real app would use port 995 (TLS from the first byte) or upgrade with the STLS command, and these same lines would travel encrypted.',
        facts: [
          ['Server', 'pop.example.org'],
          ['Port', '110 (shown unencrypted)'],
        ],
        packets: [...hs, greet],
      },
      {
        title: 'Log in',
        desc: 'USER, then PASS',
        detail:
          'The username and password are sent as two commands. Over plain port 110 the password would be readable by anyone on the path — which is exactly why POP3 is always run inside TLS today.',
        facts: [
          ['Commands', 'USER, PASS'],
          ['Risk here', 'password in clear text'],
        ],
        packets: [user, userOk, pass, passOk],
      },
      {
        title: 'Check the mailbox',
        desc: 'STAT and LIST',
        detail:
          'STAT returns the number of messages and their total size. LIST gives the size of each one, ending with a line holding a single dot — the end marker for every multi-line POP3 reply.',
        facts: [
          ['Messages', '2'],
          ['Total size', '1904 bytes'],
        ],
        packets: [stat, statOk, list, listOk],
      },
      {
        title: 'Download a message',
        desc: 'RETR 1',
        detail: 'RETR fetches the whole message — headers, blank line, body — exactly as it was delivered, again finished by a lone dot.',
        packets: [retr, retrOk],
      },
      {
        title: 'Delete and quit',
        desc: 'DELE 1, QUIT',
        detail:
          'DELE only marks the message. The server really removes it when the app says QUIT; if the connection dropped first, nothing would be deleted. Apps that offer “leave a copy on the server” simply skip DELE.',
        facts: [
          ['DELE', 'marks for deletion'],
          ['Removed at', 'QUIT'],
        ],
        packets: [dele, deleOk, quit, bye, ...close],
      },
    ],
    outro: {
      title: 'Mail downloaded',
      text: 'The message is now on the laptop and gone from the server. Simple and fast — but read it on your phone later and it won’t be there. IMAP solves that.',
      facts: [
        ['Downloaded', '1 message'],
        ['Left on server', '1 message'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ IMAP */

function buildImap() {
  const { c, S, C } = textSession('imap', 50412, 143, 'IMAP', 'Internet Message Access Protocol');
  const hs = c.handshake();
  const greet = S(['* OK [CAPABILITY IMAP4rev2 STARTTLS IDLE LITERAL+] imap.example.org ready'], '* OK');
  const login = C(['a1 LOGIN amir correct-horse-battery'], 'LOGIN');
  const loginOk = S(['a1 OK LOGIN completed'], 'OK');
  const select = C(['a2 SELECT INBOX'], 'SELECT');
  const selectOk = S(
    [
      '* 3 EXISTS',
      '* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)',
      '* OK [UIDVALIDITY 1794300000] UIDs valid',
      '* OK [UIDNEXT 104] Predicted next UID',
      'a2 OK [READ-WRITE] SELECT completed',
    ],
    'INBOX',
    '* 3 EXISTS … a2 OK SELECT completed',
  );
  const fetch = C(['a3 FETCH 3 (FLAGS BODY[HEADER.FIELDS (FROM SUBJECT)])'], 'FETCH 3');
  const fetchOk = S(
    [
      '* 3 FETCH (FLAGS () BODY[HEADER.FIELDS (FROM SUBJECT)] {64}',
      'From: Sara <sara@example.net>',
      'Subject: Re: Lunch tomorrow?',
      '',
      ')',
      'a3 OK FETCH completed',
    ],
    'HEADERS',
    '* 3 FETCH (FLAGS () BODY[HEADER.FIELDS …])',
  );
  const store = C(['a4 STORE 3 +FLAGS (\\Seen)'], 'STORE');
  const storeOk = S(['* 3 FETCH (FLAGS (\\Seen))', 'a4 OK STORE completed'], 'OK');
  const idle = C(['a5 IDLE'], 'IDLE');
  const idling = S(['+ idling'], '+ idling');
  const push = S(['* 4 EXISTS'], 'NEW MAIL', '* 4 EXISTS (new message arrived)');
  const doneCmd = C(['DONE'], 'DONE');
  const idleOk = S(['a5 OK IDLE terminated'], 'OK');
  const logout = C(['a6 LOGOUT'], 'LOGOUT');
  const bye = S(['* BYE logging out', 'a6 OK LOGOUT completed'], 'BYE');
  const close = c.close();

  return lesson({
    id: 'imap',
    name: 'IMAP',
    title: 'Mail in sync',
    layer: 7,
    tagline: 'The mailbox stays on the server; every device sees the same.',
    ...webNodes('imap', false),
    legend: [
      ['green', 'TCP control'],
      ['amber', 'Tagged command'],
      ['violet', 'Server response'],
    ],
    overview: {
      full: 'Internet Message Access Protocol',
      description:
        'With IMAP your mail stays on the server, organised into folders. Apps fetch only what they need — often just headers — and changes like “read” or “moved to Archive” are stored on the server, so your laptop and phone always agree. Every command carries a tag (a1, a2…) so replies can be matched up.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Ports', '143 (STARTTLS), 993 (TLS)'],
        ['Runs over', 'TCP'],
        ['Model', 'Mail stays on the server'],
        ['Push', 'IDLE'],
        ['Spec', 'RFC 9051 (IMAP4rev2)'],
      ],
    },
    steps: [
      {
        title: 'Connect',
        desc: 'Greeting with capabilities',
        detail:
          'After the TCP handshake the server says * OK and lists what it supports. Lines starting with * are untagged — information, not the answer to a specific command. (Shown on port 143 without TLS so it is readable; real apps use 993 or STARTTLS.)',
        packets: [...hs, greet],
      },
      {
        title: 'Log in',
        desc: 'a1 LOGIN',
        detail: 'The app picks a tag, a1, and logs in. The server finishes with a line starting with the same tag and a status: OK, NO or BAD.',
        facts: [['Tag', 'a1']],
        packets: [login, loginOk],
      },
      {
        title: 'Open the inbox',
        desc: 'a2 SELECT INBOX',
        detail:
          'Selecting a folder returns how many messages exist, which flags are allowed and the UID values that let an app resume a sync later without downloading everything again.',
        facts: [
          ['Messages', '3'],
          ['Folder', 'INBOX (read-write)'],
        ],
        packets: [select, selectOk],
      },
      {
        title: 'Read just what is needed',
        desc: 'FETCH headers, then mark as seen',
        detail:
          'Instead of downloading the whole message, the app asks for only the From and Subject lines. When you open it, STORE sets the \\Seen flag on the server — so it shows as read on every device.',
        facts: [
          ['Fetched', 'two header fields (64 bytes)'],
          ['Flag set', '\\Seen'],
        ],
        packets: [fetch, fetchOk, store, storeOk],
      },
      {
        title: 'Wait for new mail',
        desc: 'IDLE: the server pushes',
        detail:
          'IDLE keeps the connection open and lets the server speak first. When Sara’s next message arrives the server immediately sends * 4 EXISTS. DONE ends the idle so the app can fetch it.',
        facts: [['Push message', '* 4 EXISTS']],
        packets: [idle, idling, push, doneCmd, idleOk],
      },
      {
        title: 'Log out',
        desc: 'a6 LOGOUT',
        detail: 'The server says BYE, confirms the tagged command and TCP closes. Every message is still on the server.',
        packets: [logout, bye, ...close],
      },
    ],
    outro: {
      title: 'Mailbox in sync',
      text: 'Nothing was downloaded and deleted — the app read headers, set a flag and got a live push for new mail. Open your phone and it shows exactly the same inbox.',
      facts: [
        ['On server', '4 messages'],
        ['Commands', '6 tagged'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ FTP */

const REPORT = '%PDF-1.7\n% quarterly report, page 1 of 12 ...\n'.repeat(18);

function buildFtp() {
  const { c, S, C } = textSession('ftp', 50520, 21, 'FTP', 'File Transfer Protocol');
  const hs = c.handshake();
  const greet = S(['220 ftp.example.org FTP server ready'], '220');
  const user = C(['USER amir'], 'USER');
  const u331 = S(['331 Password required for amir'], '331');
  const pass = C(['PASS correct-horse-battery'], 'PASS');
  const p230 = S(['230 User amir logged in'], '230');
  const type = C(['TYPE I'], 'TYPE I');
  const t200 = S(['200 Type set to I (binary)'], '200');
  const pasv = C(['PASV'], 'PASV');
  const p227 = S(['227 Entering Passive Mode (203,0,113,40,195,80)'], '227', '227 Entering Passive Mode (203,0,113,40,195,80) → port 50000');

  const d = tcp('client', 'ftp', 51022, 50000);
  const dhs = d.handshake().map((p) => ({ ...p, color: 'teal' as const }));
  const retr = C(['RETR report.pdf'], 'RETR');
  const r150 = S(['150 Opening BINARY mode data connection for report.pdf (972 bytes)'], '150');
  const file = d.send('b', data('FTP-DATA', REPORT, 'File contents'), {
    label: 'FILE DATA',
    proto: 'FTP-DATA',
    info: `FTP Data: ${REPORT.length} bytes (report.pdf)`,
    color: 'teal',
  });
  const dfin1 = d.seg('b', 'FA', { label: 'FIN', color: 'teal' });
  const dfin2 = d.seg('a', 'FA', { label: 'FIN-ACK', color: 'teal' });
  const dfin3 = d.seg('b', 'A', { label: 'ACK', color: 'teal' });
  const r226 = S(['226 Transfer complete'], '226');
  const quit = C(['QUIT'], 'QUIT');
  const bye = S(['221 Goodbye'], '221');
  const close = c.close();

  return lesson({
    id: 'ftp',
    name: 'FTP',
    title: 'Transferring files',
    layer: 7,
    tagline: 'Commands on one connection, the file on another.',
    ...webNodes('ftp', false),
    legend: [
      ['green', 'Control TCP'],
      ['amber', 'Command'],
      ['violet', 'Reply'],
      ['teal', 'Data connection'],
    ],
    overview: {
      full: 'File Transfer Protocol',
      description:
        'FTP is one of the oldest internet protocols, and it is unusual: it uses two TCP connections. A control connection on port 21 carries text commands and numeric replies, and a separate data connection is opened for every file or directory listing. In passive mode the server tells the client which port to connect to.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Ports', '21 (control) + a data port'],
        ['Runs over', 'TCP (two connections)'],
        ['Modes', 'Passive (PASV) or active (PORT)'],
        ['Secure versions', 'FTPS, or SFTP over SSH'],
        ['Spec', 'RFC 959'],
      ],
    },
    steps: [
      {
        title: 'Control connection',
        desc: 'TCP to port 21, then 220',
        detail:
          'The FTP client connects to port 21. This connection will only ever carry commands and replies. The server introduces itself with code 220 — like SMTP, replies are three-digit numbers.',
        packets: [...hs, greet],
      },
      {
        title: 'Log in',
        desc: 'USER, 331, PASS, 230',
        detail:
          '331 means “user name okay, need a password”; 230 means logged in. Classic FTP sends the password in clear text, which is why FTPS (FTP over TLS) or SFTP are used in practice.',
        facts: [
          ['331', 'password required'],
          ['230', 'logged in'],
        ],
        packets: [user, u331, pass, p230],
      },
      {
        title: 'Passive mode',
        desc: 'PASV: “which port should I use?”',
        detail:
          'TYPE I switches to binary so the file is copied byte for byte. PASV asks the server to open a port for the data. The reply encodes the address and port as six numbers: 203,0,113,40 and 195×256 + 80 = port 50000.',
        facts: [
          ['Address', '203.0.113.40'],
          ['Port', '195 × 256 + 80 = 50000'],
        ],
        packets: [type, t200, pasv, p227],
      },
      {
        title: 'Data connection',
        desc: 'A second TCP handshake',
        detail:
          'The client opens a brand-new TCP connection to port 50000. Passive mode exists because the client connecting outward works through home routers and NAT; the older active mode (server connects back to the client) usually does not.',
        facts: [['Data port', '50000']],
        packets: dhs,
      },
      {
        title: 'The file arrives',
        desc: 'RETR, 150, data, 226',
        detail:
          'RETR is sent on the control connection; the file itself flows over the data connection. When the server has sent every byte it closes the data connection — that is how the client knows the file is complete — and confirms with 226 on the control connection.',
        facts: [
          ['File', 'report.pdf'],
          ['Size', `${REPORT.length} bytes`],
          ['End of file', 'data connection closed'],
        ],
        packets: [retr, r150, file, dfin1, dfin2, dfin3, r226],
      },
      {
        title: 'Quit',
        desc: 'QUIT, 221',
        detail: 'The client says QUIT, the server says goodbye and the control connection closes too.',
        packets: [quit, bye, ...close],
      },
    ],
    outro: {
      title: 'File downloaded',
      text: 'Two connections, one for talking and one for the file. That split is FTP’s signature — and the reason firewalls and NAT routers need special help with it.',
      facts: [
        ['TCP connections', '2'],
        ['Encrypted', 'No (use FTPS / SFTP)'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ SMB2 */

const le16 = (v: number) => [v & 255, (v >>> 8) & 255];
const le32 = (v: number) => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255];
const le64 = (v: number) => [...le32(v >>> 0), ...le32(Math.floor(v / 2 ** 32))];
const utf16 = (s: string) => Array.from(s).flatMap((ch) => le16(ch.charCodeAt(0)));

const SMB_CMDS: Record<number, string> = {
  0: 'NEGOTIATE',
  1: 'SESSION_SETUP',
  3: 'TREE_CONNECT',
  5: 'CREATE',
  6: 'CLOSE',
  8: 'READ',
};
const SMB_STATUS: Record<number, string> = {
  0: 'STATUS_SUCCESS',
  0xc0000016: 'STATUS_MORE_PROCESSING_REQUIRED',
};

type F = [string, string, number[]];

function smb(o: {
  cmd: number;
  resp?: boolean;
  status?: number;
  mid: number;
  sid?: number;
  tid?: number;
  signed?: boolean;
  body: F[];
  summary: string;
}): AppWriter {
  return (w) => {
    const bodyLen = o.body.reduce((n, f) => n + f[2].length, 0);
    const smbLen = 64 + bodyLen;
    w.begin('nbss', 'NetBIOS Session Service');
    w.f('Message type', 'Session message (0x00)', [0]);
    w.f('Length', `${smbLen} bytes`, u24(smbLen));
    w.end(`Session message, ${smbLen} bytes`);

    w.begin('app', 'SMB2 (Server Message Block v2/3)');
    const flags = (o.resp ? 1 : 0) | (o.signed ? 8 : 0);
    const status = o.status ?? 0;
    w.f('Protocol ID', '0xFE "SMB"', [0xfe, ...ascii('SMB')]);
    w.f('Header length', '64 bytes', le16(64));
    w.f('Credit charge', 1, le16(1));
    w.f('Status', `${SMB_STATUS[status] ?? hex(status, 8)} (${hex(status, 8)})`, le32(status));
    w.f('Command', `${SMB_CMDS[o.cmd]} (${o.cmd})`, le16(o.cmd));
    w.f(o.resp ? 'Credits granted' : 'Credits requested', o.resp ? 32 : 1, le16(o.resp ? 32 : 1));
    w.f('Flags', `${hex(flags, 8)} (${[o.resp ? 'response' : 'request', o.signed && 'signed'].filter(Boolean).join(', ')})`, le32(flags));
    w.f('Next command', '0 (not chained)', le32(0));
    w.f('Message ID', o.mid, le64(o.mid));
    w.f('Process ID', hex(0xfeff, 8), le32(0xfeff));
    w.f('Tree ID', o.tid ? hex(o.tid, 8) : '0 (none yet)', le32(o.tid ?? 0));
    w.f('Session ID', o.sid ? hex(o.sid, 16) : '0 (none yet)', le64(o.sid ?? 0));
    w.f('Signature', o.signed ? 'AES-128-GMAC (16 bytes)' : '0 (not signed)', o.signed ? rand(`sig${o.mid}${o.resp}`, 16) : new Array(16).fill(0));
    for (const [n, v, b] of o.body) w.f(n, v, b);
    w.end(o.summary);
  };
}

const SID = 0x0000440000000051 % 2 ** 53;
const TID = 0x00000005;

function buildSmb() {
  const c = tcp('client', 'nas', 49712, 445);
  const hs = c.handshake();
  const dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
  const negReq = c.send(
    'a',
    smb({
      cmd: 0, mid: 0, summary: 'Negotiate Protocol Request',
      body: [
        ['Structure size', '36', le16(36)],
        ['Dialect count', String(dialects.length), le16(dialects.length)],
        ['Security mode', 'Signing required (0x0002)', le16(2)],
        ['Reserved', '0', le16(0)],
        ['Capabilities', 'DFS, Leasing, Large MTU, Encryption (0x0000006f)', le32(0x6f)],
        ['Client GUID', '16 random bytes', rand('cguid', 16)],
        ['Negotiate contexts', 'offset · count (8 bytes)', [0x70, 0, 0, 0, 2, 0, 0, 0]],
        ['Dialects', 'SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1', dialects.flatMap(le16)],
      ],
    }),
    { label: 'NEGOTIATE', proto: 'SMB2', info: 'Negotiate Protocol Request', color: 'amber' },
  );
  const negResp = c.send(
    'b',
    smb({
      cmd: 0, resp: true, mid: 0, summary: 'Negotiate Protocol Response · SMB 3.1.1',
      body: [
        ['Structure size', '65', le16(65)],
        ['Security mode', 'Signing required (0x0002)', le16(2)],
        ['Chosen dialect', 'SMB 3.1.1 (0x0311)', le16(0x0311)],
        ['Negotiate context count', '2', le16(2)],
        ['Server GUID', '16 bytes', rand('sguid', 16)],
        ['Capabilities', 'Leasing, Large MTU, Encryption', le32(0x6e)],
        ['Max read / write size', '8 MiB each', [...le32(8388608), ...le32(8388608), ...le32(8388608)]],
        ['System time', '2026-11-11 12:00:00 UTC', rand('stime', 8)],
        ['Security blob', 'SPNEGO: offers NTLMSSP (74 bytes)', rand('spnego0', 74)],
      ],
    }),
    { label: 'NEGOTIATE', proto: 'SMB2', info: 'Negotiate Protocol Response (dialect 3.1.1)', color: 'violet' },
  );
  const ss1 = c.send(
    'a',
    smb({
      cmd: 1, mid: 1, summary: 'Session Setup Request, NTLMSSP_NEGOTIATE',
      body: [
        ['Structure size', '25', le16(25)],
        ['Flags · Security mode', 'signing required', [0, 2]],
        ['Capabilities', 'DFS', le32(1)],
        ['Security blob', 'NTLMSSP NEGOTIATE (supported options)', [...ascii('NTLMSSP\0'), ...le32(1), ...rand('ntlm1', 32)]],
      ],
    }),
    { label: 'SESSION SETUP', proto: 'SMB2', info: 'Session Setup Request, NTLMSSP_NEGOTIATE', color: 'amber' },
  );
  const ss1r = c.send(
    'b',
    smb({
      cmd: 1, resp: true, status: 0xc0000016, mid: 1, sid: SID, summary: 'Session Setup Response, NTLMSSP_CHALLENGE',
      body: [
        ['Structure size', '9', le16(9)],
        ['Session flags', '0', le16(0)],
        ['Security blob', 'NTLMSSP CHALLENGE (8-byte server challenge)', [...ascii('NTLMSSP\0'), ...le32(2), ...rand('ntlm2', 48)]],
      ],
    }),
    { label: 'CHALLENGE', proto: 'SMB2', info: 'Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED', color: 'violet' },
  );
  const ss2 = c.send(
    'a',
    smb({
      cmd: 1, mid: 2, sid: SID, summary: 'Session Setup Request, NTLMSSP_AUTH, User: NAS\\amir',
      body: [
        ['Structure size', '25', le16(25)],
        ['Flags · Security mode', 'signing required', [0, 2]],
        ['Capabilities', 'DFS', le32(1)],
        ['Security blob', 'NTLMSSP AUTH: user NAS\\amir + NTLMv2 response', [...ascii('NTLMSSP\0'), ...le32(3), ...utf16('amir'), ...rand('ntlm3', 96)]],
      ],
    }),
    { label: 'AUTH', proto: 'SMB2', info: 'Session Setup Request, NTLMSSP_AUTH, User: NAS\\amir', color: 'amber' },
  );
  const ss2r = c.send(
    'b',
    smb({ cmd: 1, resp: true, mid: 2, sid: SID, signed: true, summary: 'Session Setup Response (success)', body: [['Structure size', '9', le16(9)], ['Session flags', '0', le16(0)]] }),
    { label: 'LOGGED IN', proto: 'SMB2', info: 'Session Setup Response', color: 'violet' },
  );
  const share = '\\\\192.168.1.20\\photos';
  const tc = c.send(
    'a',
    smb({
      cmd: 3, mid: 3, sid: SID, signed: true, summary: `Tree Connect Request Tree: ${share}`,
      body: [
        ['Structure size', '9', le16(9)],
        ['Flags', '0', le16(0)],
        ['Path offset · length', `${utf16(share).length} bytes`, [...le16(72), ...le16(utf16(share).length)]],
        ['Share path', share, utf16(share)],
      ],
    }),
    { label: 'TREE CONNECT', proto: 'SMB2', info: `Tree Connect Request Tree: ${share}`, color: 'amber' },
  );
  const tcr = c.send(
    'b',
    smb({
      cmd: 3, resp: true, mid: 3, sid: SID, tid: TID, signed: true, summary: 'Tree Connect Response (disk share)',
      body: [
        ['Structure size', '16', le16(16)],
        ['Share type', 'Disk (0x01)', [1, 0]],
        ['Share flags', '0', le32(0)],
        ['Capabilities', '0', le32(0)],
        ['Maximal access', 'Read, write, delete (0x001f01ff)', le32(0x1f01ff)],
      ],
    }),
    { label: 'SHARE OK', proto: 'SMB2', info: 'Tree Connect Response', color: 'violet' },
  );
  const fname = 'beach.jpg';
  const cr = c.send(
    'a',
    smb({
      cmd: 5, mid: 4, sid: SID, tid: TID, signed: true, summary: `Create Request File: ${fname}`,
      body: [
        ['Structure size', '57', le16(57)],
        ['Oplock · Impersonation', 'Lease · Impersonation', [0xff, 0, ...le32(2)]],
        ['Desired access', 'Read data, read attributes (0x00120089)', le32(0x120089)],
        ['Share access', 'Read, write, delete', le32(7)],
        ['Disposition', 'Open existing (1)', le32(1)],
        ['File name', fname, utf16(fname)],
      ],
    }),
    { label: 'OPEN FILE', proto: 'SMB2', info: `Create Request File: ${fname}`, color: 'amber' },
  );
  const crr = c.send(
    'b',
    smb({
      cmd: 5, resp: true, mid: 4, sid: SID, tid: TID, signed: true, summary: `Create Response File: ${fname}`,
      body: [
        ['Structure size', '89', le16(89)],
        ['Create action', 'File opened (1)', le32(1)],
        ['File size', '1,286 bytes', le64(1286)],
        ['File ID', '16-byte handle', rand('fid', 16)],
      ],
    }),
    { label: 'HANDLE', proto: 'SMB2', info: `Create Response File: ${fname}`, color: 'violet' },
  );
  const rd = c.send(
    'a',
    smb({
      cmd: 8, mid: 5, sid: SID, tid: TID, signed: true, summary: `Read Request Len: 1286 Off: 0 File: ${fname}`,
      body: [
        ['Structure size', '49', le16(49)],
        ['Length', '1286 bytes', le32(1286)],
        ['Offset', '0', le64(0)],
        ['File ID', '16-byte handle', rand('fid', 16)],
      ],
    }),
    { label: 'READ', proto: 'SMB2', info: `Read Request Len:1286 Off:0 File: ${fname}`, color: 'amber' },
  );
  const jpeg = [0xff, 0xd8, 0xff, 0xe0, 0, 16, ...ascii('JFIF\0'), ...rand('jpeg', 1275)];
  const rdr = c.send(
    'b',
    smb({
      cmd: 8, resp: true, mid: 5, sid: SID, tid: TID, signed: true, summary: 'Read Response · 1286 bytes',
      body: [
        ['Structure size', '17', le16(17)],
        ['Data offset · length', '1286 bytes', [80, 0, ...le32(jpeg.length), ...le32(0), ...le32(0)]],
        ['File data', 'JPEG image (starts FF D8 FF E0 … JFIF)', jpeg],
      ],
    }),
    { label: 'FILE DATA', proto: 'SMB2', info: 'Read Response', color: 'teal' },
  );
  const ack = c.ack('a');

  return lesson({
    id: 'smb',
    name: 'SMB',
    title: 'Shared folders',
    layer: 7,
    tagline: 'How a laptop opens a file on the NAS down the hall.',
    nodes: [
      { id: 'client', x: 12, y: 58 },
      { id: 'router', x: 48, y: 30, label: 'Router / switch' },
      { id: 'nas', x: 84, y: 58 },
    ],
    links: [
      ['client', 'router'],
      ['router', 'nas'],
    ],
    legend: [
      ['green', 'TCP control'],
      ['amber', 'SMB request'],
      ['violet', 'SMB response'],
      ['teal', 'File data'],
    ],
    overview: {
      full: 'Server Message Block (SMB 2/3)',
      description:
        'SMB is how Windows, macOS and Linux share folders and printers on a local network. Every request — negotiate, log in, connect to a share, open, read — is a binary message with a fixed 64-byte header. SMB 3 adds signing and encryption so files can’t be read or changed on the way.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', 'TCP 445'],
        ['Header', '64 bytes, little-endian'],
        ['Login', 'NTLMv2 or Kerberos'],
        ['Security', 'Signing, AES encryption (SMB 3)'],
        ['Spec', 'Microsoft MS-SMB2'],
      ],
    },
    steps: [
      {
        title: 'Connect to port 445',
        desc: 'TCP on the local network',
        detail:
          'You open \\\\192.168.1.20\\photos in the file manager. The laptop opens a TCP connection to port 445 on the NAS. Both are on the same home network, so nothing goes out to the internet.',
        packets: hs,
      },
      {
        title: 'Negotiate',
        desc: 'Pick the newest common dialect',
        detail:
          'The laptop lists every SMB version it speaks and says it requires signing. The NAS chooses 3.1.1. In 3.1.1 both sides hash this exchange into the session keys, so a meddler who tried to force an older, weaker version would make the login fail.',
        facts: [
          ['Offered', '2.0.2 … 3.1.1'],
          ['Chosen', 'SMB 3.1.1'],
        ],
        packets: [negReq, negResp],
      },
      {
        title: 'Log in',
        desc: 'NTLM challenge and response',
        detail:
          'Without a Windows domain the login uses NTLMv2. The NAS answers the first SESSION_SETUP with “more processing required” and an 8-byte random challenge. The laptop proves it knows the password by mixing it with that challenge — the password itself never crosses the network. From now on every message is signed.',
        facts: [
          ['Method', 'NTLMv2 (domain: Kerberos)'],
          ['Status 1', 'MORE_PROCESSING_REQUIRED'],
          ['Signing', 'AES-128-GMAC'],
        ],
        packets: [ss1, ss1r, ss2, ss2r],
      },
      {
        title: 'Connect to the share',
        desc: 'TREE_CONNECT \\\\nas\\photos',
        detail: 'A “tree” is a shared folder. The NAS confirms it is a disk share and returns a Tree ID that later requests quote.',
        facts: [['Tree ID', hex(TID, 8)]],
        packets: [tc, tcr],
      },
      {
        title: 'Open and read a file',
        desc: 'CREATE, then READ',
        detail:
          'Despite its name, CREATE also opens existing files; it returns a 16-byte file handle. READ asks for 1286 bytes from offset 0 and the NAS sends back the JPEG — you can spot its FF D8 FF E0 “JFIF” signature in the hex dump.',
        facts: [
          ['File', fname],
          ['Size', '1,286 bytes'],
        ],
        packets: [cr, crr, rd, rdr, ack],
      },
    ],
    outro: {
      title: 'File opened',
      text: 'Five request/response pairs turned a folder path into bytes on your screen — every one signed, so nothing could be altered on the way.',
      facts: [
        ['Dialect', 'SMB 3.1.1'],
        ['Round trips', '7'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ SSH */

const nameList = (s: string) => [...u32(ascii(s).length), ...ascii(s)];
const sshString = (b: number[]) => [...u32(b.length), ...b];

/** Writes one unencrypted SSH binary packet (RFC 4253 §6) into the current layer. */
function sshPacket(w: Writer, payload: F[], seed: string) {
  const payloadLen = payload.reduce((n, f) => n + f[2].length, 0);
  let pad = 8 - ((5 + payloadLen) % 8);
  if (pad < 4) pad += 8;
  const packetLen = 1 + payloadLen + pad;
  w.f('Packet length', `${packetLen} bytes`, u32(packetLen));
  w.f('Padding length', pad, [pad]);
  for (const [n, v, b] of payload) w.f(n, v, b);
  w.f('Random padding', `${pad} bytes`, rand(seed, pad));
}

function sshVersion(text: string): AppWriter {
  return (w) => {
    w.begin('app', 'SSH Protocol');
    w.f('Protocol version exchange', text, ascii(text + '\r\n'));
    w.end(text);
  };
}

function kexinit(side: 'client' | 'server'): AppWriter {
  const lists: [string, string][] = [
    ['kex_algorithms', side === 'client' ? 'sntrup761x25519-sha512,curve25519-sha256,ext-info-c' : 'sntrup761x25519-sha512,curve25519-sha256'],
    ['server_host_key_algorithms', 'ssh-ed25519,rsa-sha2-512'],
    ['encryption_algorithms (c→s)', 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com'],
    ['encryption_algorithms (s→c)', 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com'],
    ['mac_algorithms (c→s)', 'hmac-sha2-256-etm@openssh.com'],
    ['mac_algorithms (s→c)', 'hmac-sha2-256-etm@openssh.com'],
    ['compression (c→s)', 'none,zlib@openssh.com'],
    ['compression (s→c)', 'none,zlib@openssh.com'],
  ];
  return (w) => {
    w.begin('app', 'SSH Protocol');
    sshPacket(
      w,
      [
        ['Message code', 'Key Exchange Init (20)', [20]],
        ['Cookie', '16 random bytes', rand('cookie' + side, 16)],
        ...lists.map(([n, v]) => [n, v, nameList(v)] as F),
        ['languages (both directions)', '(empty)', [...u32(0), ...u32(0)]],
        ['first_kex_packet_follows', 'false', [0]],
        ['Reserved', '0', u32(0)],
      ],
      'pad-kex-' + side,
    );
    w.end(`Key Exchange Init (${side})`);
  };
}

function encSsh(len: number, what: string, seed: string): AppWriter {
  return (w) => {
    w.begin('app', 'SSH Protocol');
    w.f('Packet length (encrypted)', '4 bytes, encrypted with a separate key', rand(seed + 'L', 4));
    w.f('Encrypted packet', what, rand(seed, len));
    w.f('MAC', 'Poly1305 tag (16 bytes)', rand(seed + 'M', 16));
    w.end(`Encrypted packet (${len + 20} bytes)`);
  };
}

function buildSsh() {
  const c = tcp('client', 'sshsrv', 52901, 22);
  const hs = c.handshake();
  const sv = c.send('b', sshVersion('SSH-2.0-OpenSSH_9.9'), { label: 'VERSION', proto: 'SSHv2', info: 'Server: Protocol (SSH-2.0-OpenSSH_9.9)', color: 'violet' });
  const cv = c.send('a', sshVersion('SSH-2.0-OpenSSH_9.9p1'), { label: 'VERSION', proto: 'SSHv2', info: 'Client: Protocol (SSH-2.0-OpenSSH_9.9p1)', color: 'amber' });
  const ck = c.send('a', kexinit('client'), { label: 'KEXINIT', proto: 'SSHv2', info: 'Client: Key Exchange Init', color: 'amber' });
  const sk = c.send('b', kexinit('server'), { label: 'KEXINIT', proto: 'SSHv2', info: 'Server: Key Exchange Init', color: 'violet' });
  const ecdhInit = c.send(
    'a',
    (w) => {
      w.begin('app', 'SSH Protocol');
      sshPacket(
        w,
        [
          ['Message code', 'KEX ECDH Init (30)', [30]],
          ['Client public key (Q_C)', 'sntrup761 (1158 bytes) + X25519 (32 bytes)', sshString(rand('qc', 1190))],
        ],
        'pad-ecdh-i',
      );
      w.end('Elliptic Curve Diffie-Hellman Key Exchange Init');
    },
    { label: 'KEX INIT', proto: 'SSHv2', info: 'Client: Elliptic Curve Diffie-Hellman Key Exchange Init', color: 'amber' },
  );
  const hostKey = [...sshString(ascii('ssh-ed25519')), ...sshString(rand('hostkey', 32))];
  const sig = [...sshString(ascii('ssh-ed25519')), ...sshString(rand('sig', 64))];
  const ecdhReply = c.send(
    'b',
    (w) => {
      w.begin('app', 'SSH Protocol');
      sshPacket(
        w,
        [
          ['Message code', 'KEX ECDH Reply (31)', [31]],
          ['Server host key', 'ssh-ed25519 (32-byte public key)', sshString(hostKey)],
          ['Server public key (Q_S)', 'sntrup761 ciphertext + X25519 (1071 bytes)', sshString(rand('qs', 1071))],
          ['Signature over exchange hash', 'ssh-ed25519 (64 bytes)', sshString(sig)],
        ],
        'pad-ecdh-r',
      );
      sshPacket(w, [['Message code', 'New Keys (21)', [21]]], 'pad-nk-s');
      w.end('ECDH Key Exchange Reply, New Keys');
    },
    { label: 'KEX REPLY', proto: 'SSHv2', info: 'Server: Elliptic Curve Diffie-Hellman Key Exchange Reply, New Keys', color: 'violet' },
  );
  const nk = c.send(
    'a',
    (w) => {
      w.begin('app', 'SSH Protocol');
      sshPacket(w, [['Message code', 'New Keys (21)', [21]]], 'pad-nk-c');
      w.end('New Keys');
    },
    { label: 'NEWKEYS', proto: 'SSHv2', info: 'Client: New Keys', color: 'amber' },
  );
  const svcReq = c.send('a', encSsh(28, 'SERVICE_REQUEST "ssh-userauth"', 'e1'), { label: 'AUTH? 🔒', proto: 'SSHv2', info: 'Client: Encrypted packet (len=48)', color: 'teal' });
  const svcOk = c.send('b', encSsh(28, 'SERVICE_ACCEPT "ssh-userauth"', 'e2'), { label: 'OK 🔒', proto: 'SSHv2', info: 'Server: Encrypted packet (len=48)', color: 'teal' });
  const authReq = c.send('a', encSsh(380, 'USERAUTH_REQUEST: user "amir", publickey ssh-ed25519, with signature', 'e3'), {
    label: 'KEY LOGIN 🔒',
    proto: 'SSHv2',
    info: 'Client: Encrypted packet (len=400)',
    color: 'teal',
  });
  const authOk = c.send('b', encSsh(12, 'USERAUTH_SUCCESS', 'e4'), { label: 'SUCCESS 🔒', proto: 'SSHv2', info: 'Server: Encrypted packet (len=32)', color: 'teal' });
  const chOpen = c.send('a', encSsh(124, 'CHANNEL_OPEN "session" + CHANNEL_REQUEST "pty-req" + "shell"', 'e5'), {
    label: 'SHELL 🔒',
    proto: 'SSHv2',
    info: 'Client: Encrypted packet (len=144)',
    color: 'teal',
  });
  const chOk = c.send('b', encSsh(76, 'CHANNEL_OPEN_CONFIRMATION, CHANNEL_SUCCESS, banner and prompt', 'e6'), {
    label: 'PROMPT 🔒',
    proto: 'SSHv2',
    info: 'Server: Encrypted packet (len=96)',
    color: 'teal',
  });
  const keys = c.send('a', encSsh(44, 'CHANNEL_DATA: "ls\\r" (your keystrokes)', 'e7'), { label: 'ls ⏎ 🔒', proto: 'SSHv2', info: 'Client: Encrypted packet (len=64)', color: 'amber' });
  const out = c.send('b', encSsh(156, 'CHANNEL_DATA: "notes.txt  photos  projects\\r\\n$ " (command output)', 'e8'), {
    label: 'OUTPUT 🔒',
    proto: 'SSHv2',
    info: 'Server: Encrypted packet (len=176)',
    color: 'violet',
  });
  const ack = c.ack('a');

  return lesson({
    id: 'ssh',
    name: 'SSH',
    title: 'Secure remote login',
    layer: 7,
    tagline: 'A terminal on a far-away server, encrypted end to end.',
    ...webNodes('sshsrv', false),
    legend: [
      ['green', 'TCP control'],
      ['amber', 'Client (plain setup)'],
      ['violet', 'Server'],
      ['teal', 'Encrypted'],
    ],
    overview: {
      full: 'Secure Shell',
      description:
        'SSH gives you a command line on another computer — and also file copies (scp, sftp) and tunnels. It starts by agreeing on algorithms and fresh keys, proves the server’s identity with its host key, then logs you in, usually with a key pair instead of a password. After the key exchange everything is encrypted.',
      facts: [
        ['Layer', 'Application (7)'],
        ['Port', 'TCP 22'],
        ['Key exchange', 'sntrup761 + X25519 (post-quantum hybrid)'],
        ['Cipher', 'ChaCha20-Poly1305'],
        ['Login', 'Public key (Ed25519)'],
        ['Spec', 'RFC 4251–4254'],
      ],
    },
    steps: [
      {
        title: 'Say hello',
        desc: 'TCP, then version strings',
        detail:
          'After the TCP handshake on port 22 each side sends one line of plain text naming its protocol version and software: “SSH-2.0-OpenSSH_9.9”. These two lines are later hashed into the keys, so they can’t be tampered with unnoticed.',
        packets: [...hs, sv, cv],
      },
      {
        title: 'Agree on algorithms',
        desc: 'KEXINIT from both sides',
        detail:
          'Each side sends a list of the key exchange methods, host key types, ciphers, MACs and compression it supports, in order of preference. For each category the first client choice the server also supports wins.',
        facts: [
          ['Key exchange', 'sntrup761x25519-sha512'],
          ['Cipher', 'chacha20-poly1305'],
          ['Host key', 'ssh-ed25519'],
        ],
        packets: [ck, sk],
      },
      {
        title: 'Key exchange',
        desc: 'Shared secret + host key check',
        detail:
          'The client sends its half of a hybrid exchange — a Streamlined NTRU Prime key (built to survive future quantum computers) plus an X25519 key. The server replies with its half, its host key and a signature over the whole exchange. The client checks that host key against ~/.ssh/known_hosts; this is what the “authenticity of host can’t be established” prompt is about on the first connection.',
        facts: [
          ['Proves', 'server identity (host key)'],
          ['First time', 'fingerprint prompt'],
        ],
        packets: [ecdhInit, ecdhReply],
      },
      {
        title: 'Switch on encryption',
        desc: 'NEWKEYS',
        detail: 'NEWKEYS means “from my next packet on, I use the new keys”. Look at the next packets: even their length field is encrypted, and each ends with a 16-byte Poly1305 tag.',
        packets: [nk],
      },
      {
        title: 'Log in with a key',
        desc: 'Public-key authentication',
        detail:
          'The client asks for the user-auth service, then proves it owns the private key matching a public key in the server’s ~/.ssh/authorized_keys by signing the session ID. No password ever crosses the network.',
        facts: [
          ['User', 'amir'],
          ['Method', 'publickey (Ed25519)'],
        ],
        packets: [svcReq, svcOk, authReq, authOk],
      },
      {
        title: 'Open a shell and type',
        desc: 'Channels carry the session',
        detail:
          'A “session” channel with a terminal (pty) and a shell is opened. Your keystrokes go up as CHANNEL_DATA and the command output comes back the same way — all encrypted, so the network only sees sizes and timing.',
        packets: [chOpen, chOk, keys, out, ack],
      },
    ],
    outro: {
      title: 'Logged in securely',
      text: 'Two plain-text lines and two lists of algorithms were the only readable bytes. Everything from your login to every keystroke travelled encrypted and authenticated.',
      facts: [
        ['Readable packets', '6 (setup only)'],
        ['Login', 'key, no password'],
      ],
    },
  });
}

/* ------------------------------------------------------------------ TLS 1.3 handshake */

const ext = (type: number, body: number[]) => [...u16(type), ...u16(body.length), ...body];

function serverHelloOnly(sni: string): AppWriter {
  return (w) => {
    w.begin('app', 'Transport Layer Security');
    const exts: F[] = [
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
    w.end('Server Hello, Change Cipher Spec');
  };
}

/** Several encrypted records in one segment; each shows what is inside. */
function records(list: [number, string][], seed: string, summary: string): AppWriter {
  return (w) => {
    w.begin('app', 'Transport Layer Security');
    list.forEach(([len, what], i) => {
      w.f(`Record ${i + 1} · content type`, 'Application Data (23) — real type hidden inside', [23]);
      w.f(`Record ${i + 1} · version`, 'TLS 1.2 (0x0303)', u16(0x0303));
      w.f(`Record ${i + 1} · length`, `${len} bytes`, u16(len));
      w.f(`Record ${i + 1} · encrypted`, what, rand(`${seed}${i}`, len));
    });
    w.end(summary);
  };
}

function buildTls() {
  const sni = 'shop.example.com';
  const c = tcp('client', 'tlssrv', 53114, 443);
  const hs = c.handshake();
  const ch = c.send('a', clientHello(sni), { label: 'CLIENT HELLO', proto: 'TLSv1.3', info: `Client Hello (SNI=${sni})`, color: 'amber' });
  const sh = c.send('b', serverHelloOnly(sni), { label: 'SERVER HELLO', proto: 'TLSv1.3', info: 'Server Hello, Change Cipher Spec', color: 'violet' });
  const cert = c.send(
    'b',
    records(
      [
        [38, 'Encrypted Extensions (ALPN: h2)'],
        [1032, 'Certificate: shop.example.com ← intermediate CA (chain of 2)'],
        [97, 'Certificate Verify: ECDSA signature over the handshake so far'],
        [53, 'Finished: HMAC over the whole handshake'],
      ],
      'cert' + sni,
      'Encrypted Extensions, Certificate, Certificate Verify, Finished',
    ),
    { label: 'CERTIFICATE 🔒', proto: 'TLSv1.3', info: 'Application Data ×4 (EncryptedExtensions, Certificate, CertificateVerify, Finished)', color: 'teal' },
  );
  const fin = c.send('a', clientFinished(sni), { label: 'FINISHED', proto: 'TLSv1.3', info: 'Change Cipher Spec, Application Data (Finished)', color: 'amber' });
  const req = c.send('a', records([[143, 'HTTP/2 request: GET /cart']], 'req' + sni, 'Application Data'), {
    label: 'DATA 🔒',
    proto: 'TLSv1.3',
    info: 'Application Data (encrypted request)',
    color: 'teal',
  });
  const resp = c.send(
    'b',
    records(
      [
        [226, 'New Session Ticket (for faster resumption next time)'],
        [870, 'HTTP/2 response: 200 OK + page'],
      ],
      'resp' + sni,
      'Application Data ×2',
    ),
    { label: 'DATA 🔒', proto: 'TLSv1.3', info: 'Application Data (session ticket, encrypted response)', color: 'violet' },
  );
  const alertC = c.send('a', records([[19, 'Alert: close_notify (level warning)']], 'al1' + sni, 'Encrypted Alert'), {
    label: 'CLOSE_NOTIFY',
    proto: 'TLSv1.3',
    info: 'Application Data (encrypted alert: close_notify)',
    color: 'red',
  });
  const alertS = c.send('b', records([[19, 'Alert: close_notify (level warning)']], 'al2' + sni, 'Encrypted Alert'), {
    label: 'CLOSE_NOTIFY',
    proto: 'TLSv1.3',
    info: 'Application Data (encrypted alert: close_notify)',
    color: 'red',
  });
  const close = c.close();

  return lesson({
    id: 'tls',
    name: 'TLS/SSL',
    title: 'Encryption',
    layer: 6,
    tagline: 'The TLS 1.3 handshake, record by record.',
    ...webNodes('tlssrv', false),
    legend: [
      ['green', 'TCP control'],
      ['amber', 'Client handshake'],
      ['violet', 'Server handshake'],
      ['teal', 'Encrypted records'],
      ['red', 'Alert'],
    ],
    overview: {
      full: 'Transport Layer Security',
      description:
        'TLS (once called SSL) wraps any TCP connection in encryption. In one round trip the TLS 1.3 handshake agrees on a cipher, derives fresh keys with Diffie-Hellman, and proves the server’s identity with a certificate signed by a trusted authority. After that, data travels in authenticated, encrypted records.',
      facts: [
        ['Layer', 'Presentation (6) / between TCP and apps'],
        ['Version', 'TLS 1.3'],
        ['Key exchange', 'ECDHE (X25519)'],
        ['Identity', 'X.509 certificate'],
        ['Round trips', '1 (0 when resuming)'],
        ['Spec', 'RFC 8446'],
      ],
    },
    steps: [
      {
        title: 'Client Hello',
        desc: 'Offers, random and a key share',
        detail:
          'Right after the TCP handshake the client sends its supported versions and cipher suites, a 32-byte random value, and — the TLS 1.3 trick — an X25519 public key straight away, guessing the server will accept it. The server name (SNI) is readable so the server knows which certificate to present.',
        facts: [
          ['Ciphers offered', '3 (AES-GCM, ChaCha20)'],
          ['Key share', 'X25519'],
          ['Visible', `SNI = ${sni}`],
        ],
        packets: [...hs, ch],
      },
      {
        title: 'Server Hello',
        desc: 'Choices plus the server’s key share',
        detail:
          'The server picks TLS 1.3 and TLS_AES_128_GCM_SHA256 and sends its own X25519 public key. Now each side combines its private key with the other’s public key and gets the same shared secret, which no eavesdropper can compute. The Change Cipher Spec record is a harmless leftover that keeps old middleboxes happy.',
        facts: [
          ['Cipher', 'AES-128-GCM + SHA-256'],
          ['Shared secret', 'ECDHE, never sent'],
        ],
        packets: [sh],
      },
      {
        title: 'Certificate',
        desc: 'Identity — already encrypted',
        detail:
          'Everything after Server Hello is encrypted with handshake keys. Inside: the certificate chain (shop.example.com, signed by an intermediate CA that chains to a root the browser trusts), a CertificateVerify signature proving the server holds the certificate’s private key, and the server’s Finished. On the wire each looks like Application Data.',
        facts: [
          ['Chain', 'leaf → intermediate → root'],
          ['Proof', 'Certificate Verify (ECDSA)'],
          ['Hidden', 'real record types'],
        ],
        packets: [cert],
      },
      {
        title: 'Finished',
        desc: 'Both sides confirm the transcript',
        detail:
          'The client validates the chain, the dates and the name, checks the signature, then sends its own Finished: an HMAC over every handshake byte. If anything had been changed in transit, the values would not match and the connection would be dropped.',
        packets: [fin],
      },
      {
        title: 'Encrypted data',
        desc: 'Application keys take over',
        detail:
          'Data now flows with fresh application keys. Each record is encrypted and carries a 16-byte authentication tag. The server also sends a session ticket so the next visit can resume with no extra round trip.',
        facts: [
          ['Record overhead', '5-byte header + 16-byte tag'],
          ['Ticket', 'enables 1-RTT/0-RTT resumption'],
        ],
        packets: [req, resp],
      },
      {
        title: 'Closing',
        desc: 'close_notify, then FIN',
        detail:
          'Before TCP closes, each side sends a close_notify alert (itself encrypted). That tells the other side the data really ended, rather than being cut off by an attacker injecting a TCP FIN.',
        packets: [alertC, alertS, ...close],
      },
    ],
    outro: {
      title: 'Secure from start to finish',
      text: 'One round trip produced shared keys and a verified identity. From the certificate onward, nothing in the connection was readable — only its size and timing.',
      facts: [
        ['Handshake', '1 RTT'],
        ['Readable', 'Client Hello, Server Hello'],
      ],
    },
  });
}

export const PACK: Lesson[] = [buildPop3(), buildImap(), buildFtp(), buildSmb(), buildSsh(), buildTls()];
