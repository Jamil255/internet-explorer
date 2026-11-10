'use client';
import { Fragment, useEffect, useMemo, useRef, useState } from 'react';

function StepDivider({ n, title }: { n: number; title: string }) {
  return (
    <div className="seq-divider">
      <span>
        Step {n + 1} · {title}
      </span>
    </div>
  );
}
import { NODE_INFO } from '@/engine/nodes';
import type { Lesson, Packet } from '@/engine/types';
import { bubbleLine, useFlight, type Inflight } from './hooks';
import { NODE_ICONS } from './icons';

interface Props {
  lesson: Lesson;
  captured: Packet[];
  inflight: Inflight | null;
  speed: number;
  onArrive: () => void;
  onInspect: (index: number) => void;
}

/** Sequence diagram: one lifeline per node, one arrow per packet, newest at the bottom. */
export function SequenceView({ lesson, captured, inflight, speed, onArrive, onInspect }: Props) {
  const scroller = useRef<HTMLDivElement>(null);
  const live = useRef<HTMLDivElement>(null);
  const [lost, setLost] = useState(false);

  // Only nodes that actually send or receive get a lifeline, ordered left to right.
  const cols = useMemo(() => {
    const used = new Set<string>();
    for (const s of lesson.steps) for (const p of s.packets ?? []) used.add(p.from).add(p.to);
    return lesson.nodes.filter((n) => used.has(n.id)).sort((a, b) => a.x - b.x || a.y - b.y);
  }, [lesson]);
  // Which captured index starts each step, for the "STEP n · TITLE" dividers.
  const { stepStarts, liveStep } = useMemo(() => {
    const starts = new Map<number, number>();
    let i = 0;
    let firstUnstarted: number | null = null;
    lesson.steps.forEach((s, si) => {
      const n = s.packets?.length ?? 0;
      if (!n) return;
      if (i < captured.length) starts.set(i, si);
      else if (firstUnstarted === null && i === captured.length) firstUnstarted = si;
      i += n;
    });
    return { stepStarts: starts, liveStep: firstUnstarted };
  }, [lesson, captured.length]);

  const colX = (id: string) => {
    const i = cols.findIndex((c) => c.id === id);
    return cols.length < 2 ? 50 : 15 + (i * 73) / (cols.length - 1);
  };

  useFlight(
    inflight,
    speed,
    (t, lostNow) => {
      if (t === 0) setLost(false);
      if (lostNow) setLost(true);
      live.current?.style.setProperty('--t', String(t));
    },
    onArrive,
  );

  useEffect(() => {
    const el = scroller.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
  }, [captured.length, inflight?.key]);

  const arrow = (p: Packet, i: number | null, liveRow = false) => {
    const a = colX(p.from);
    const b = colX(p.to);
    const left = Math.min(a, b);
    const width = Math.abs(b - a);
    const rtl = b < a;
    return (
      <div
        key={i ?? 'live'}
        ref={liveRow ? live : undefined}
        className={`seq-row c-${p.color} ${rtl ? 'is-rtl' : ''} ${p.lost ? 'is-lost' : ''} ${liveRow ? 'is-live' : ''} ${
          liveRow && lost ? 'is-dead' : ''
        }`}
        onClick={i !== null ? () => onInspect(i) : undefined}
        role={i !== null ? 'button' : undefined}
        tabIndex={i !== null ? 0 : undefined}
        title={i !== null ? 'Inspect this packet' : undefined}
      >
        <span className="seq-time">{i !== null ? `${p.time.toFixed(3)}s` : ''}</span>
        <div className="seq-arrow" style={{ left: `${left}%`, width: `${width}%` }}>
          <span className="seq-line" />
          <span className="seq-head" />
          <span className="seq-text">
            <b>{p.label}</b>
            <small>{bubbleLine(p)}</small>
          </span>
          {p.lost && <span className="seq-x">✕</span>}
        </div>
      </div>
    );
  };

  return (
    <div className="sequence">
      <div className="seq-heads">
        {cols.map((c) => {
          const info = NODE_INFO[c.id];
          const Icon = NODE_ICONS[info?.icon ?? 'server'];
          return (
            <div key={c.id} className="seq-head-node" style={{ left: `${colX(c.id)}%` }}>
              <Icon size={18} strokeWidth={1.8} />
              <span>{c.label ?? info?.label ?? c.id}</span>
            </div>
          );
        })}
      </div>
      <div className="seq-body" ref={scroller}>
        {cols.map((c) => (
          <span key={c.id} className="seq-lifeline" style={{ left: `${colX(c.id)}%` }} />
        ))}
        {captured.length === 0 && !inflight && <div className="seq-empty">Packets will appear here as they are sent.</div>}
        {captured.map((p, i) => (
          <Fragment key={i}>
            {stepStarts.get(i) !== undefined && <StepDivider n={stepStarts.get(i)!} title={lesson.steps[stepStarts.get(i)!].title} />}
            {arrow(p, i)}
          </Fragment>
        ))}
        {inflight && liveStep !== null && <StepDivider n={liveStep} title={lesson.steps[liveStep].title} />}
        {inflight && arrow(inflight.packet, null, true)}
      </div>
    </div>
  );
}
