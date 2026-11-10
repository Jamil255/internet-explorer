'use client';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ListOrdered, Share2 } from 'lucide-react';
import { findPath } from '@/engine/graph';
import type { Packet } from '@/engine/types';
import { LESSONS, getLesson } from '@/lessons';
import { Controls, SearchPalette, ShortcutsDialog, SPEEDS, Topbar } from './Chrome';
import { ExplainPanel, type PacketCard } from './ExplainPanel';
import { NODE_INFO } from '@/engine/nodes';
import { Inspector } from './Inspector';
import { NetworkView } from './NetworkView';
import { PacketTable } from './PacketTable';
import { SequenceView } from './SequenceView';
import { Sidebar } from './Sidebar';
import { usePersisted, useProgress, useTheme, type Inflight } from './hooks';
import { I18nProvider, useT } from './i18n';

export default function Explorer(props: { initialId: string }) {
  return (
    <I18nProvider>
      <ExplorerInner {...props} />
    </I18nProvider>
  );
}

function ExplorerInner({ initialId }: { initialId: string }) {
  const { t } = useT();
  const [lessonId, setLessonId] = useState(initialId);
  const lesson = getLesson(lessonId) ?? LESSONS[0];
  const steps = lesson.steps;
  const total = steps.length;

  // playback
  const [step, setStep] = useState(-1);
  const [shown, setShown] = useState(0);
  const [gate, setGate] = useState(Infinity);
  const [run, setRun] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = usePersisted('nx:speed', 1);
  const [oneByOne, setOneByOne] = usePersisted('nx:onebyone', false);

  // view
  const [view, setView] = usePersisted<'network' | 'sequence'>('nx:view', 'network');
  const [listOpen, setListOpen] = usePersisted('nx:list', true);
  const [focusMode, setFocusMode] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [inspect, setInspect] = useState<number | null>(null);
  const [dialog, setDialog] = useState<'search' | 'keys' | null>(null);
  const { theme, toggle: toggleTheme } = useTheme();
  const { done, markDone } = useProgress();
  const root = useRef<HTMLDivElement>(null);

  const cur = step >= 0 && step < total ? steps[step] : null;
  const pk = cur?.packets ?? [];
  const limit = Math.min(pk.length, gate);

  const inflight: Inflight | null = useMemo(() => {
    if (!cur || shown >= limit) return null;
    const packet = pk[shown];
    return { packet, key: `${run}:${step}:${shown}`, hops: findPath(lesson.links, packet.from, packet.to).length - 1 };
  }, [cur, shown, limit, pk, run, step, lesson.links]);

  const captured = useMemo(() => {
    const out: Packet[] = [];
    steps.forEach((s, si) => {
      const list = s.packets ?? [];
      if (si < step) out.push(...list);
      else if (si === step) out.push(...list.slice(0, shown));
    });
    return out;
  }, [steps, step, shown]);

  /* ---------- navigation ---------- */

  const goTo = useCallback(
    (n: number) => {
      const s = Math.max(-1, Math.min(total, n));
      setStep(s);
      setShown(0);
      setGate(oneByOne ? 1 : Infinity);
      setRun((r) => r + 1);
      if (s < 0) setPlaying(false);
    },
    [total, oneByOne],
  );

  const next = useCallback(() => {
    if (cur && oneByOne && shown < pk.length) {
      if (shown < gate) setShown(shown + 1); // finish the packet in flight
      else setGate(shown + 1); // release the next one
      return;
    }
    if (step < total) goTo(step + 1);
  }, [cur, oneByOne, shown, gate, pk.length, step, total, goTo]);

  const prev = useCallback(() => {
    if (step >= 0) goTo(step - 1);
  }, [step, goTo]);

  const toggle = useCallback(() => {
    if (step < 0 || step >= total) {
      goTo(0);
      setPlaying(true);
    } else setPlaying((p) => !p);
  }, [step, total, goTo]);

  const replay = useCallback(() => {
    goTo(0);
    setPlaying(true);
  }, [goTo]);

  const pickLesson = useCallback(
    (id: string, atStep = -1) => {
      setLessonId(id);
      setStep(atStep);
      setShown(0);
      setGate(oneByOne ? 1 : Infinity);
      setRun((r) => r + 1);
      setPlaying(false);
      setInspect(null);
      setDrawer(false);
      if (window.location.pathname !== `/lesson/${id}`) window.history.pushState(null, '', `/lesson/${id}`);
    },
    [oneByOne],
  );

  const lessonIndex = LESSONS.findIndex((l) => l.id === lesson.id);
  const nextLesson = lessonIndex < LESSONS.length - 1 ? LESSONS[lessonIndex + 1] : null;
  const prevLesson = lessonIndex > 0 ? LESSONS[lessonIndex - 1] : null;

  // browser back/forward
  useEffect(() => {
    const on = () => {
      const id = window.location.pathname.split('/lesson/')[1];
      if (id && getLesson(id)) pickLesson(id);
      else if (window.location.pathname === '/') pickLesson(LESSONS[0].id);
    };
    window.addEventListener('popstate', on);
    return () => window.removeEventListener('popstate', on);
  }, [pickLesson]);

  // toggling one-by-one mid-step applies immediately
  useEffect(() => {
    setGate(oneByOne ? shown + 1 : Infinity);
  }, [oneByOne]); // eslint-disable-line react-hooks/exhaustive-deps

  const onArrive = useCallback(() => setShown((s) => s + 1), []);

  // autoplay: release gated packets, then advance to the next step
  useEffect(() => {
    if (!playing || inflight || step < 0) return;
    if (step >= total) {
      setPlaying(false);
      return;
    }
    if (shown < pk.length) {
      const t = setTimeout(() => setGate(shown + 1), 650 / speed);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => goTo(step + 1), (pk.length ? 1500 : 2800) / speed);
    return () => clearTimeout(t);
  }, [playing, inflight, step, shown, pk.length, total, speed, goTo]);

  useEffect(() => {
    if (step >= total) markDone(lesson.id);
  }, [step, total, lesson.id, markDone]);

  /* ---------- fullscreen ---------- */

  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenEnabled) return;
    if (document.fullscreenElement) document.exitFullscreen();
    else root.current?.requestFullscreen().catch(() => {});
  }, []);
  useEffect(() => {
    const on = () => setFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', on);
    return () => document.removeEventListener('fullscreenchange', on);
  }, []);

  /* ---------- keyboard ---------- */

  const changeSpeed = useCallback(
    (dir: number) => {
      const i = SPEEDS.indexOf(speed);
      setSpeed(SPEEDS[Math.max(0, Math.min(SPEEDS.length - 1, (i < 0 ? 2 : i) + dir))]);
    },
    [speed, setSpeed],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setDialog('search');
        return;
      }
      if (e.ctrlKey || e.metaKey || e.altKey) return;

      if (dialog) {
        if (e.key === 'Escape') setDialog(null);
        return;
      }
      if (inspect !== null) {
        if (e.key === 'Escape') setInspect(null);
        else if (e.key === 'ArrowLeft') setInspect((i) => Math.max(0, (i ?? 0) - 1));
        else if (e.key === 'ArrowRight') setInspect((i) => Math.min(captured.length - 1, (i ?? 0) + 1));
        return;
      }

      const k = e.key;
      if (k === ' ') {
        e.preventDefault();
        toggle();
      } else if (k === 'ArrowRight') next();
      else if (k === 'ArrowLeft') prev();
      else if (k === 'Escape') {
        if (drawer) setDrawer(false);
        else if (focusMode) setFocusMode(false);
        else goTo(-1);
      } else if (/^[1-9]$/.test(k)) goTo(Number(k) - 1);
      else if (k === '[') changeSpeed(-1);
      else if (k === ']') changeSpeed(1);
      else if (k === 's' || k === 'S') setOneByOne((v) => !v);
      else if (k === 'v' || k === 'V') setView((v) => (v === 'network' ? 'sequence' : 'network'));
      else if (k === 'd' || k === 'D') setFocusMode((v) => !v);
      else if (k === 'l' || k === 'L') setListOpen((v) => !v);
      else if (k === 'f' || k === 'F') toggleFullscreen();
      else if (k === 't' || k === 'T') toggleTheme();
      else if (k === '/') {
        e.preventDefault();
        setDialog('search');
      } else if (k === '?') setDialog('keys');
      else if ((k === 'n' || k === 'N') && nextLesson) pickLesson(nextLesson.id);
      else if ((k === 'p' || k === 'P') && prevLesson) pickLesson(prevLesson.id);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [
    dialog, inspect, captured.length, toggle, next, prev, goTo, drawer, focusMode, changeSpeed,
    setOneByOne, setView, setListOpen, toggleFullscreen, toggleTheme, nextLesson, prevLesson, pickLesson,
  ]);

  /* ---------- render ---------- */

  const nodeLabel = (id: string) => lesson.nodes.find((n) => n.id === id)?.label ?? NODE_INFO[id]?.label ?? id;
  const whereOf = (p: Packet) =>
    p.from === 'client' || p.to === 'client'
      ? 'Captured on your laptop’s network card'
      : `Captured on the link leaving ${nodeLabel(p.from)}`;
  // The packet the explain panel describes: the one in flight, else the last one delivered in this step.
  const card: PacketCard | null = (() => {
    if (!cur || !pk.length) return null;
    const flying = !!inflight;
    const idx = flying ? shown : Math.min(shown, pk.length) - 1;
    if (idx < 0) return null;
    const before = steps.slice(0, step).reduce((n, s) => n + (s.packets?.length ?? 0), 0);
    const p = pk[idx];
    return { packet: p, no: before + idx + 1, total: lesson.packetCount, fromLabel: nodeLabel(p.from), toLabel: nodeLabel(p.to), flying };
  })();

  const openStepPacket = (si: number, pi: number) => {
    const before = steps.slice(0, si).reduce((n, s) => n + (s.packets?.length ?? 0), 0);
    setInspect(before + pi);
  };

  const cls = [
    'app',
    !listOpen && 'is-list-hidden',
    focusMode && 'is-focus',
    drawer && 'is-drawer-open',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div className={cls} ref={root}>
      <Topbar
        done={done}
        listOpen={listOpen}
        focusMode={focusMode}
        fullscreen={fullscreen}
        theme={theme}
        onDrawer={() => setDrawer(true)}
        onSearch={() => setDialog('search')}
        onList={() => setListOpen((v) => !v)}
        onFocus={() => setFocusMode((v) => !v)}
        onFullscreen={toggleFullscreen}
        onKeys={() => setDialog('keys')}
        onTheme={toggleTheme}
        layer={lesson.layer}
      />

      <div className="layout">
        <Sidebar
          current={lesson.id}
          done={done}
          onPick={(id) => pickLesson(id)}
          onClose={() => setDrawer(false)}
          step={step}
          onGo={goTo}
          playing={playing}
        />
        {drawer && <div className="drawer-scrim" onClick={() => setDrawer(false)} />}

        <main className="center">
          <section className="panel stage">
            <div className="stage-head">
              <div className="view-switch" role="tablist" title="Switch view (V)">
                <button className={view === 'network' ? 'is-active' : ''} onClick={() => setView('network')}>
                  <Share2 size={14} /> {t('Network')}
                </button>
                <button className={view === 'sequence' ? 'is-active' : ''} onClick={() => setView('sequence')}>
                  <ListOrdered size={14} /> {t('Sequence')}
                </button>
              </div>
              <h1 className="stage-title">
                {lesson.name} <span>· {lesson.title}</span>
              </h1>
            </div>

            <div className="stage-body">
              {view === 'network' ? (
                <NetworkView lesson={lesson} step={cur} stepIndex={step} inflight={inflight} speed={speed} onArrive={onArrive} />
              ) : (
                <SequenceView
                  lesson={lesson}
                  captured={captured}
                  inflight={inflight}
                  speed={speed}
                  onArrive={onArrive}
                  onInspect={setInspect}
                />
              )}
              {step < 0 && (
                <div className="stage-overlay">
                  <button className="btn primary lg" onClick={toggle}>
                    ▶ {t('Start lesson')} · {lesson.name}
                  </button>
                </div>
              )}
              {cur && focusMode && (
                <div className="caption fade-in" key={step}>
                  <b>
                    {step + 1}. {cur.title}
                  </b>{' '}
                  — {cur.desc}
                </div>
              )}
            </div>
          </section>

          <PacketTable
            lesson={lesson}
            captured={captured}
            selected={inspect}
            onSelect={setInspect}
            actions={
              <Controls
                playing={playing}
                oneByOne={oneByOne}
                speed={speed}
                step={step}
                total={total}
                onPrev={prev}
                onToggle={toggle}
                onNext={next}
                onReplay={replay}
                onOneByOne={() => setOneByOne((v) => !v)}
                onSpeed={setSpeed}
                onGo={goTo}
              />
            }
          />
        </main>

        <ExplainPanel
          lesson={lesson}
          step={step}
          shown={shown}
          onGo={goTo}
          onStart={toggle}
          onNextLesson={nextLesson ? () => pickLesson(nextLesson.id) : null}
          onInspectStepPacket={openStepPacket}
          card={card}
          onInspectCard={() => card && !card.flying && setInspect(card.no - 1)}
          playing={playing}
        />
      </div>

      {inspect !== null && captured[inspect] && (
        <Inspector packets={captured} index={inspect} onIndex={setInspect} onClose={() => setInspect(null)} whereOf={whereOf} />
      )}
      {dialog === 'search' && (
        <SearchPalette
          onClose={() => setDialog(null)}
          onPick={(id, s) => {
            setDialog(null);
            pickLesson(id, s);
          }}
        />
      )}
      {dialog === 'keys' && <ShortcutsDialog onClose={() => setDialog(null)} />}
    </div>
  );
}
