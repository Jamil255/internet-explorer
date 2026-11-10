import type { Lesson } from '@/engine/types';
import { dhcpLesson, dnsLesson, icmpLesson, ntpLesson, smtpLesson, tcpLesson } from './core';
import { PACK as A } from './pack-a';
import { PACK as B } from './pack-b';
import { PACK as C } from './pack-c';
import { PACK as D } from './pack-d';
import { PACK as E } from './pack-e';
import { http1, https, websocket } from './web';

const ALL: Lesson[] = [http1, https, websocket, dnsLesson, dhcpLesson, tcpLesson, ntpLesson, icmpLesson, smtpLesson, ...A, ...B, ...C, ...D, ...E];
const byId = new Map(ALL.map((l) => [l.id, l]));

/** Same grouping and order as the original site. */
const GROUP_IDS: Record<'core' | 'application' | 'security', string[]> = {
  core: ['quic', 'tcp', 'udp', 'ip', 'bgp', 'ipv6', 'icmp', 'igmp', 'ethernet', 'pppoe', 'wifi'],
  application: [
    'http', 'websocket', 'webrtc', 'sip', 'rtsp', 'rtmp', 'dns', 'dhcp', 'ntp', 'portal',
    'smtp', 'pop3', 'imap', 'ftp', 'smb', 'proxy', 'socks', 'reverse', 'modbus',
  ],
  security: ['https', 'doh', 'dnssec', 'wpa3', 'radius', 'ssh', 'tls', 'wireguard', 'ipsec'],
};

const pick = (ids: string[]) => ids.map((id) => byId.get(id)).filter((l): l is Lesson => !!l);

/** Lessons in the order they appear in the "All" tab. */
export const LESSONS: Lesson[] = [
  ...pick(GROUP_IDS.core),
  ...pick(GROUP_IDS.application),
  ...pick(GROUP_IDS.security),
];

export const GROUPS: { id: string; label: string; ids: string[] }[] = [
  { id: 'all', label: 'All', ids: LESSONS.map((l) => l.id) },
  { id: 'core', label: 'Core', ids: pick(GROUP_IDS.core).map((l) => l.id) },
  { id: 'application', label: 'Application', ids: pick(GROUP_IDS.application).map((l) => l.id) },
  { id: 'security', label: 'Security', ids: pick(GROUP_IDS.security).map((l) => l.id) },
];

export const groupOf = (id: string) =>
  (Object.keys(GROUP_IDS) as (keyof typeof GROUP_IDS)[]).find((g) => GROUP_IDS[g].includes(id)) ?? 'application';

export const LAYER_NAMES: Record<number, string> = {
  2: 'Data link',
  3: 'Network',
  4: 'Transport',
  5: 'Session',
  6: 'Presentation',
  7: 'Application',
};

export const getLesson = (id: string) => LESSONS.find((l) => l.id === id);
