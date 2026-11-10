import {
  Building2,
  Cctv,
  Clock,
  Cloud,
  Crown,
  Database,
  EthernetPort,
  Factory,
  FolderOpen,
  Globe,
  HardDrive,
  KeyRound,
  Laptop,
  Lock,
  Mail,
  MessagesSquare,
  Monitor,
  Network,
  Phone,
  Radio,
  RadioTower,
  Router,
  Server,
  Shield,
  ShieldCheck,
  Smartphone,
  Tv,
  Users,
  Video,
  Wifi,
  type LucideIcon,
} from 'lucide-react';
import type { IconName } from '@/engine/nodes';

export const NODE_ICONS: Record<IconName, LucideIcon> = {
  laptop: Laptop,
  router: Router,
  cloud: Cloud,
  server: Server,
  globe: Globe,
  mail: Mail,
  crown: Crown,
  network: Network,
  database: Database,
  tower: RadioTower,
  clock: Clock,
  chat: MessagesSquare,
  switch: EthernetPort,
  wifi: Wifi,
  shield: Shield,
  camera: Cctv,
  phone: Phone,
  video: Video,
  factory: Factory,
  hdd: HardDrive,
  lock: Lock,
  users: Users,
  tv: Tv,
  key: KeyRound,
  folder: FolderOpen,
  building: Building2,
  monitor: Monitor,
  smartphone: Smartphone,
  shieldcheck: ShieldCheck,
  radio: Radio,
};

export function Logo({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden fill="none" stroke="var(--ink)" strokeWidth="3" strokeLinejoin="round">
      <path d="M32 6 56 19v26L32 58 8 45V19Z" fill="var(--accent-soft)" />
      <path d="M8 19l24 13 24-13M32 32v26" />
      <path d="M20 12.5 44 25.5" strokeWidth="2" />
    </svg>
  );
}
