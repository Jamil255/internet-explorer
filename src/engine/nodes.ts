export type IconName =
  | 'laptop'
  | 'router'
  | 'cloud'
  | 'server'
  | 'globe'
  | 'mail'
  | 'crown'
  | 'network'
  | 'database'
  | 'tower'
  | 'clock'
  | 'chat'
  | 'switch'
  | 'wifi'
  | 'shield'
  | 'camera'
  | 'phone'
  | 'video'
  | 'factory'
  | 'hdd'
  | 'lock'
  | 'users'
  | 'tv'
  | 'key'
  | 'folder'
  | 'building'
  | 'monitor'
  | 'smartphone'
  | 'shieldcheck'
  | 'radio';

export interface NodeInfo {
  label: string;
  icon: IconName;
  ip?: string;
}

export const NODE_INFO: Record<string, NodeInfo> = {
  client: { label: 'Your laptop', icon: 'laptop', ip: '192.168.1.10' },
  router: { label: 'Home router', icon: 'router', ip: '192.168.1.1' },
  internet: { label: 'Internet', icon: 'cloud' },
  dns: { label: 'DNS resolver', icon: 'server', ip: '8.8.8.8' },
  web: { label: 'www.example.com', icon: 'globe', ip: '203.0.113.10' },
  mail: { label: 'mail.example.net', icon: 'mail', ip: '203.0.113.25' },
  root: { label: 'Root server', icon: 'crown', ip: '198.41.0.4' },
  tld: { label: '.com server', icon: 'network', ip: '192.5.6.30' },
  auth: { label: 'example.com NS', icon: 'database', ip: '199.43.135.53' },
  isp: { label: 'ISP router', icon: 'tower', ip: '100.64.0.1' },
  ntp: { label: 'Time server', icon: 'clock', ip: '203.0.113.123' },
  chat: { label: 'chat.example.com', icon: 'chat', ip: '203.0.113.50' },
};

/**
 * Lessons call this at module load to add their own nodes (a switch, a NAS,
 * a VPN server…). Existing ids are not overwritten.
 */
export function registerNodes(nodes: Record<string, NodeInfo>) {
  for (const [id, info] of Object.entries(nodes)) if (!NODE_INFO[id]) NODE_INFO[id] = info;
}
