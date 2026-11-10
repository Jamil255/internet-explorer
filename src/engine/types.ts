import type { Frame } from './bytes';

export type NodeId = string;
export type PacketColor = 'blue' | 'green' | 'amber' | 'violet' | 'teal' | 'red' | 'pink' | 'slate';

export interface Packet {
  from: NodeId;
  to: NodeId;
  color: PacketColor;
  label: string;
  proto: string;
  info: string;
  src: string;
  dst: string;
  lost?: boolean;
  frame: Frame;
  len: number;
  time: number;
}

export interface Step {
  title: string;
  desc: string;
  detail: string;
  facts?: [string, string][];
  packets?: Packet[];
  focus?: NodeId[];
  /** Animate typing this into a browser address bar beside the laptop. */
  typeUrl?: string;
}

export interface NodeSpec {
  id: NodeId;
  x: number;
  y: number;
  label?: string;
  sub?: string;
  /** Override the registered address shown under the node. */
  ip?: string;
}

export interface Lesson {
  id: string;
  name: string;
  title: string;
  layer: number;
  tagline: string;
  overview: { full: string; description: string; facts: [string, string][] };
  nodes: NodeSpec[];
  links: [NodeId, NodeId][];
  legend: [PacketColor, string][];
  steps: Step[];
  outro: { title: string; text: string; facts?: [string, string][] };
  packetCount: number;
}
