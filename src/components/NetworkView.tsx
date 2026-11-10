'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import { X } from 'lucide-react';
import { findPath } from '@/engine/graph';
import { NODE_INFO } from '@/engine/nodes';
import type { Lesson, Step } from '@/engine/types';
import { bubbleLine, useFlight, type Inflight } from './hooks';
import { NODE_ICONS } from './icons';

interface Props {
  lesson: Lesson;
  step: Step | null;
  /** -1 = overview, steps.length = summary. Drives which nodes are shown and where the camera points. */
  stepIndex: number;
  inflight: Inflight | null;
  speed: number;
  onArrive: () => void;
}

const edgeKey = (a: string, b: string) => [a, b].sort().join('|');

export function NetworkView({ lesson, step, stepIndex, inflight, speed, onArrive }: Props) {
  const box = useRef<HTMLDivElement>(null);
  const pkt = useRef<HTMLDivElement>(null);
  const [lit, setLit] = useState<{ id: string; n: number } | null>(null);
  const [lost, setLost] = useState(false);
  const pos = useMemo(() => Object.fromEntries(lesson.nodes.map((n) => [n.id, n])), [lesson]);

  const path = useMemo(
    () => (inflight ? findPath(lesson.links, inflight.packet.from, inflight.packet.to) : []),
    [inflight, lesson.links],
  );
  const active = useMemo(() => {
    const s = new Set<string>();
    for (let i = 1; i < path.length; i++) s.add(edgeKey(path[i - 1], path[i]));
    return s;
  }, [path]);

  useFlight(
    inflight,
    speed,
    (t, lostNow) => {
      const el = pkt.current;
      const b = box.current;
      if (!el || !b || path.length < 2) return;
      if (t === 0) setLost(false);
      if (lostNow) setLost(true);
      const W = b.clientWidth;
      const H = b.clientHeight;
      const pts = path.map((id) => [(pos[id].x / 100) * W, (pos[id].y / 100) * H]);
      const lens = pts.slice(1).map((p, i) => Math.hypot(p[0] - pts[i][0], p[1] - pts[i][1]));
      const total = lens.reduce((a, c) => a + c, 0);
      // ease in/out a little for a softer motion
      const e = t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2;
      let d = (inflight?.packet.lost ? t : e) * total;
      let i = 0;
      while (i < lens.length - 1 && d > lens[i]) d -= lens[i++];
      const f = lens[i] ? d / lens[i] : 0;
      const x = pts[i][0] + (pts[i + 1][0] - pts[i][0]) * f;
      const y = pts[i][1] + (pts[i + 1][1] - pts[i][1]) * f;
      el.style.transform = `translate(${x}px, ${y}px) translate(-50%, -50%)`;
    },
    () => {
      if (inflight && !inflight.packet.lost) setLit((l) => ({ id: inflight.packet.to, n: (l?.n ?? 0) + 1 }));
      onArrive();
    },
  );

  useEffect(() => {
    if (!lit) return;
    const t = setTimeout(() => setLit(null), 650);
    return () => clearTimeout(t);
  }, [lit]);

  // Progressive reveal: only nodes that have taken part so far are shown, and the camera frames them.
  const visible = useMemo(() => {
    if (stepIndex < 0 || stepIndex >= lesson.steps.length) return new Set(lesson.nodes.map((n) => n.id));
    const v = new Set<string>();
    lesson.steps.slice(0, stepIndex + 1).forEach((s) => {
      s.focus?.forEach((id) => v.add(id));
      s.packets?.forEach((p) => findPath(lesson.links, p.from, p.to).forEach((id) => v.add(id)));
    });
    if (!v.size) lesson.nodes.forEach((n) => v.add(n.id));
    return v;
  }, [lesson, stepIndex]);
  const camera = useMemo(() => {
    const ns = lesson.nodes.filter((n) => visible.has(n.id));
    const xs = ns.map((n) => n.x);
    const ys = ns.map((n) => n.y);
    const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
    const s = Math.max(1, Math.min(2.1, 100 / (x1 - x0 + 34), 100 / (y1 - y0 + 40)));
    if (s === 1) return "none";
    const cx = (x0 + x1) / 2;
    const cy = (y0 + y1) / 2;
    const tx = Math.min(0, Math.max(100 - 100 * s, 50 - cx * s));
    const ty = Math.min(0, Math.max(100 - 100 * s, 50 - cy * s));
    return `translate(${tx}%, ${ty}%) scale(${s})`;
  }, [lesson.nodes, visible]);

  const focus = new Set(step?.focus ?? []);
  const endpoints = new Set(inflight ? [inflight.packet.from, inflight.packet.to] : []);
  const color = inflight?.packet.color ?? 'slate';

  return (
    <div className="network" ref={box}>
      <div className="camera" style={{ transform: camera }}>
      <svg className="links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden>
        {lesson.links.map(([a, b]) => {
          const on = active.has(edgeKey(a, b));
          return (
            <g key={a + b} className={visible.has(a) && visible.has(b) ? "" : "is-hidden"}>
              <line
                x1={pos[a].x} y1={pos[a].y} x2={pos[b].x} y2={pos[b].y}
                className="link" vectorEffect="non-scaling-stroke"
              />
              {on && (
                <line
                  x1={pos[a].x} y1={pos[a].y} x2={pos[b].x} y2={pos[b].y}
                  className={`link-active c-${color}`} vectorEffect="non-scaling-stroke"
                />
              )}
            </g>
          );
        })}
      </svg>

      {lesson.nodes.map((n) => {
        const info = NODE_INFO[n.id] ?? { label: n.id, icon: 'server' as const };
        const Icon = NODE_ICONS[info.icon];
        const cls = [
          'node',
          `node-${info.icon}`,
          lit?.id === n.id && 'is-lit',
          focus.has(n.id) && 'is-focus',
          endpoints.has(n.id) && 'is-active',
          !visible.has(n.id) && 'is-hidden',
        ]
          .filter(Boolean)
          .join(' ');
        return (
          <div key={n.id} className={cls} style={{ left: `${n.x}%`, top: `${n.y}%` }}>
            <div className="node-icon">
              <Icon size={26} strokeWidth={1.6} />
            </div>
            <div className="node-text">
              <div className="node-label">{n.label ?? info.label}</div>
              {(n.ip ?? info.ip) && <div className="node-ip">{n.ip ?? info.ip}</div>}
            </div>
          </div>
        );
      })}

      {step?.typeUrl && pos.client && (
        <div
          className="urlbar"
          key={step.typeUrl}
          style={{ left: `${pos.client.x}%`, top: `${pos.client.y - 24}%` }}
        >
          <span className="urlbar-dots"><i /><i /><i /></span>
          <span className="urlbar-text" style={{ ['--chars' as string]: step.typeUrl.length }}>
            {step.typeUrl}
          </span>
        </div>
      )}

      <div
        ref={pkt}
        className={`packet c-${color} ${lost ? 'is-lost' : ''}`}
        style={{ visibility: inflight ? 'visible' : 'hidden' }}
      >
        {inflight && (
          <>
            <span className="packet-label">
              {lost && <X size={12} strokeWidth={3} />}
              {lost ? 'LOST' : inflight.packet.label}
            </span>
            {!lost && <span className="packet-sub">{bubbleLine(inflight.packet)}</span>}
          </>
        )}
      </div>
      </div>
    </div>
  );
}
