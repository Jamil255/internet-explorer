'use client';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { Packet } from '@/engine/types';

function read<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : (JSON.parse(v) as T);
  } catch {
    return fallback;
  }
}

/** useState that survives reloads. Starts from the fallback to keep SSR and hydration in sync. */
export function usePersisted<T>(key: string, fallback: T) {
  const [value, setValue] = useState<T>(fallback);
  useEffect(() => setValue(read(key, fallback)), [key]); // eslint-disable-line react-hooks/exhaustive-deps
  const set = useCallback(
    (v: T | ((prev: T) => T)) =>
      setValue((prev) => {
        const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v;
        try {
          localStorage.setItem(key, JSON.stringify(next));
        } catch {}
        return next;
      }),
    [key],
  );
  return [value, set] as const;
}

export function useTheme() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  useEffect(() => {
    setTheme(document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');
  }, []);
  const toggle = useCallback(() => {
    setTheme((t) => {
      const next = t === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      try {
        localStorage.setItem('nx:theme', next);
      } catch {}
      return next;
    });
  }, []);
  return { theme, toggle };
}

export function useProgress() {
  const [done, setDone] = usePersisted<string[]>('nx:done', []);
  const markDone = useCallback(
    (id: string) => setDone((d) => (d.includes(id) ? d : [...d, id])),
    [setDone],
  );
  const reset = useCallback(() => setDone([]), [setDone]);
  return { done, markDone, reset };
}

export interface Inflight {
  packet: Packet;
  key: string;
  hops: number;
}

export const flightMs = (hops: number, speed: number) => Math.max(700, hops * 640) / speed;

/**
 * Drives one packet's animation: calls onFrame(t) with progress 0..1 every
 * frame, then onArrive once it lands (or once a lost packet has died).
 */
export function useFlight(
  inflight: Inflight | null,
  speed: number,
  onFrame: (t: number, lostNow: boolean) => void,
  onArrive: () => void,
) {
  const frameRef = useRef(onFrame);
  const arriveRef = useRef(onArrive);
  const speedRef = useRef(speed);
  frameRef.current = onFrame;
  arriveRef.current = onArrive;
  speedRef.current = speed;

  useLayoutEffect(() => {
    if (!inflight) return;
    const stopAt = inflight.packet.lost ? 0.55 : 1;
    let t = 0;
    let last = performance.now();
    let raf = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    frameRef.current(0, false);
    const tick = (now: number) => {
      const dt = now - last;
      last = now;
      t = Math.min(stopAt, t + dt / flightMs(inflight.hops, 1) * speedRef.current);
      frameRef.current(t, false);
      if (t < stopAt) raf = requestAnimationFrame(tick);
      else if (inflight.packet.lost) {
        frameRef.current(t, true);
        timer = setTimeout(() => arriveRef.current(), 1000 / speedRef.current);
      } else {
        timer = setTimeout(() => arriveRef.current(), 220 / speedRef.current);
      }
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      if (timer) clearTimeout(timer);
    };
  }, [inflight?.key]); // eslint-disable-line react-hooks/exhaustive-deps
}

/** Short text shown under a packet's label while it travels. */
export function bubbleLine(p: Packet): string {
  const app = p.frame.layers.find((l) => l.key === 'app');
  if (app?.summary) return app.summary.length > 38 ? app.summary.slice(0, 36) + '…' : app.summary;
  const tcp = p.frame.layers.find((l) => l.key === 'tcp');
  if (tcp) {
    const seq = tcp.fields.find((f) => f.name === 'Sequence number')?.value.split(' ')[0];
    const ack = tcp.fields.find((f) => f.name === 'Acknowledgment number')?.value.split(' ')[0];
    return `seq=${seq}${ack && ack !== '0' ? ` ack=${ack}` : ''}`;
  }
  const icmp = p.frame.layers.find((l) => l.key === 'icmp');
  return icmp?.summary ?? '';
}
