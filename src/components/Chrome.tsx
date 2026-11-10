'use client';
// Top bar, playback controls and the two dialogs (search palette, shortcuts).
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Footprints,
  Github,
  Languages,
  Keyboard,
  Maximize2,
  Menu,
  Minimize2,
  Moon,
  PanelLeft,
  Pause,
  Play,
  RotateCcw,
  ScanEye,
  Search,
  SkipBack,
  SkipForward,
  Sun,
  X,
} from 'lucide-react';
import { LAYER_NAMES, LESSONS } from '@/lessons';
import { Logo } from './icons';
import { LANGS, useT } from './i18n';

/* ---------------------------------------------------------------- Topbar */

interface TopbarProps {
  layer: number;
  done: string[];
  listOpen: boolean;
  focusMode: boolean;
  fullscreen: boolean;
  theme: 'dark' | 'light';
  onDrawer: () => void;
  onSearch: () => void;
  onList: () => void;
  onFocus: () => void;
  onFullscreen: () => void;
  onKeys: () => void;
  onTheme: () => void;
}

export function Topbar(p: TopbarProps) {
  const { t } = useT();
  const pct = Math.round((p.done.length / LESSONS.length) * 100);
  return (
    <header className="topbar">
      <button className="tool-btn drawer-btn" onClick={p.onDrawer} title={t('Protocols')}>
        <Menu size={18} />
      </button>
      <a className="brand" href="/">
        <span className="logo-frame">
          <i className="corner tl" />
          <i className="corner tr" />
          <i className="corner bl" />
          <i className="corner br" />
          <Logo size={30} />
        </span>
        <span className="brand-text">
          <b>
            NETWORK <em>EXPLORER</em>
          </b>
          <small>{t('Learn how the internet works')}</small>
        </span>
      </a>
      <span className="topbar-sep" />

      <div className="osi" title="OSI layer of this protocol">
        <div className="osi-head">
          <span>{t('OSI layer')}</span>
          <b>{t(LAYER_NAMES[p.layer])}</b>
        </div>
        <div className="osi-cells">
          {[1, 2, 3, 4, 5, 6, 7].map((n) => (
            <span key={n} className={n === p.layer ? 'is-on' : ''}>{n}</span>
          ))}
        </div>
      </div>

      <button className="search-btn" onClick={p.onSearch}>
        <Search size={15} />
        <span>{t('Search protocols & steps')}</span>
        <kbd>Ctrl K</kbd>
      </button>

      <div className="learning" title={`${p.done.length} of ${LESSONS.length} lessons completed`}>
        <div className="learning-head">
          <span>{t('Learning progress')}</span>
          <b>{pct}%</b>
        </div>
        <div className="learning-bars">
          {LESSONS.map((l) => (
            <i key={l.id} className={p.done.includes(l.id) ? 'is-done' : ''} title={l.name} />
          ))}
        </div>
      </div>

      <div className="view-tools">
        <button className={`tool-btn ${p.listOpen ? 'is-on' : ''}`} onClick={p.onList} title="Protocol list (L)">
          <PanelLeft size={17} />
        </button>
        <button className={`tool-btn ${p.focusMode ? 'is-on' : ''}`} onClick={p.onFocus} title="Diagram only (D)">
          <ScanEye size={17} />
        </button>
        <button className="tool-btn" onClick={p.onFullscreen} title="Fullscreen (F)">
          {p.fullscreen ? <Minimize2 size={17} /> : <Maximize2 size={17} />}
        </button>
        <button className="tool-btn" onClick={p.onKeys} title="Keyboard shortcuts (?)">
          <Keyboard size={17} />
        </button>
      </div>
      <span className="topbar-sep" />

      <a className="credit" href="https://github.com/Jamil255" target="_blank" rel="noreferrer">
        <span className="credit-label">{t('Built by')}</span>
        <span className="credit-name">
          <Github size={13} /> Jamil255
        </span>
      </a>
      <span className="topbar-sep" />

      <LangMenu />
      <div className="theme-switch" role="group" title="Light or dark theme (T)">
        <button className={p.theme === 'light' ? 'is-on' : ''} onClick={() => p.theme !== 'light' && p.onTheme()} aria-label="Light theme">
          <Sun size={16} />
        </button>
        <button className={p.theme === 'dark' ? 'is-on' : ''} onClick={() => p.theme !== 'dark' && p.onTheme()} aria-label="Dark theme">
          <Moon size={16} />
        </button>
      </div>
    </header>
  );
}

/* ---------------------------------------------------------------- Language menu */

function LangMenu() {
  const { lang, setLang, t } = useT();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', esc);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', esc);
    };
  }, [open]);
  return (
    <div className="lang" ref={ref}>
      <button className="icon-btn lang-btn" onClick={() => setOpen((o) => !o)} title={t('Language')} aria-expanded={open}>
        <Languages size={17} />
        <span>{lang.toUpperCase()}</span>
      </button>
      {open && (
        <div className="lang-menu" role="menu">
          {LANGS.map((l) => (
            <button
              key={l.code}
              role="menuitemradio"
              aria-checked={l.code === lang}
              className={l.code === lang ? 'is-on' : ''}
              onClick={() => {
                setLang(l.code);
                setOpen(false);
              }}
            >
              <b>{l.native}</b>
              <small>{l.name}</small>
            </button>
          ))}
          <p className="lang-note">Interface language. Lesson text is in English.</p>
        </div>
      )}
    </div>
  );
}

/* ---------------------------------------------------------------- Controls */

export const SPEEDS = [0.25, 0.5, 1, 1.5, 2, 3];

interface ControlsProps {
  playing: boolean;
  oneByOne: boolean;
  speed: number;
  step: number;
  total: number;
  onPrev: () => void;
  onToggle: () => void;
  onNext: () => void;
  onReplay: () => void;
  onOneByOne: () => void;
  onSpeed: (s: number) => void;
  onGo: (s: number) => void;
}

export function Controls(c: ControlsProps) {
  const { t } = useT();
  return (
    <div className="controls" role="group" aria-label="Playback">
      <span className="steps-count" aria-live="polite">
        {c.step < 0 ? t('Overview') : c.step >= c.total ? t('Done') : `${c.step + 1} / ${c.total}`}
      </span>
      <select className="ctl speed" value={c.speed} onChange={(e) => c.onSpeed(Number(e.target.value))} title="Speed ([ and ])">
        {SPEEDS.map((s) => (
          <option key={s} value={s}>
            {s}×
          </option>
        ))}
      </select>
      <button
        className={`ctl sq ${c.oneByOne ? 'is-on' : ''}`}
        onClick={c.onOneByOne}
        title="One packet at a time (S)"
        aria-pressed={c.oneByOne}
      >
        <Footprints size={15} />
      </button>
      <button className="ctl sq" onClick={c.onPrev} disabled={c.step < 0} title="Previous step (←)">
        <SkipBack size={15} />
      </button>
      <button className="ctl primary play-btn" onClick={c.onToggle} title="Play or pause (Space)">
        {c.playing ? <Pause size={15} fill="currentColor" /> : <Play size={15} fill="currentColor" />}
        {c.playing ? t('Pause') : t('Play')}
      </button>
      <button className="ctl" onClick={c.onNext} disabled={c.step >= c.total} title="Next step (→)">
        <SkipForward size={15} className="hide-lg" />
        {t('Step')}
      </button>
      <button className="ctl" onClick={c.onReplay} title="Replay from the start">
        <RotateCcw size={15} />
        <span className="hide-sm">{t('Reset')}</span>
      </button>
    </div>
  );
}

/* ---------------------------------------------------------------- Dialog shell */

function Dialog({ onClose, className, children }: { onClose: () => void; className?: string; children: React.ReactNode }) {
  return (
    <div className="dialog-backdrop" onMouseDown={onClose}>
      <div className={`dialog ${className ?? ''}`} onMouseDown={(e) => e.stopPropagation()} role="dialog">
        {children}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- Search palette */

interface Hit {
  lesson: string;
  step: number;
  title: string;
  sub: string;
}

export function SearchPalette({ onClose, onPick }: { onClose: () => void; onPick: (lesson: string, step: number) => void }) {
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => input.current?.focus(), []);

  const hits = useMemo<Hit[]>(() => {
    const t = q.trim().toLowerCase();
    const all: Hit[] = [];
    for (const l of LESSONS) {
      const hay = `${l.name} ${l.title} ${l.overview.full} ${l.tagline}`.toLowerCase();
      if (!t || hay.includes(t)) all.push({ lesson: l.id, step: -1, title: `${l.name} — ${l.title}`, sub: l.overview.full });
      if (t)
        l.steps.forEach((s, i) => {
          if (`${s.title} ${s.desc} ${s.detail}`.toLowerCase().includes(t))
            all.push({ lesson: l.id, step: i, title: s.title, sub: `${l.name} · step ${i + 1} · ${s.desc}` });
        });
    }
    return all.slice(0, 40);
  }, [q]);

  useEffect(() => setSel(0), [q]);

  return (
    <Dialog onClose={onClose} className="palette">
      <div className="palette-field">
        <Search size={18} />
        <input
          ref={input}
          value={q}
          placeholder="Search protocols and steps…"
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') {
              e.preventDefault();
              setSel((s) => Math.min(hits.length - 1, s + 1));
            } else if (e.key === 'ArrowUp') {
              e.preventDefault();
              setSel((s) => Math.max(0, s - 1));
            } else if (e.key === 'Enter' && hits[sel]) onPick(hits[sel].lesson, hits[sel].step);
            else if (e.key === 'Escape') onClose();
          }}
        />
        <kbd>Esc</kbd>
      </div>
      <ul className="palette-list">
        {hits.length === 0 && <li className="palette-empty">Nothing matches “{q}”.</li>}
        {hits.map((h, i) => (
          <li key={`${h.lesson}-${h.step}`}>
            <button
              className={i === sel ? 'is-sel' : ''}
              onMouseEnter={() => setSel(i)}
              onClick={() => onPick(h.lesson, h.step)}
            >
              <span className="palette-kind">{h.step < 0 ? 'Protocol' : 'Step'}</span>
              <span className="palette-text">
                <b>{h.title}</b>
                <small>{h.sub}</small>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </Dialog>
  );
}

/* ---------------------------------------------------------------- Shortcuts */

const SHORTCUTS: [string, [string[], string][]][] = [
  [
    'Playback',
    [
      [['Space'], 'Play or pause'],
      [['→'], 'Next step'],
      [['←'], 'Previous step'],
      [['S'], 'One packet at a time'],
      [['1', '9'], 'Go to step 1 – 9'],
      [['[', ']'], 'Slower / faster'],
      [['Esc'], 'Back to the overview'],
    ],
  ],
  [
    'View',
    [
      [['V'], 'Network or sequence view'],
      [['D'], 'Diagram only'],
      [['L'], 'Show or hide the protocol list'],
      [['F'], 'Fullscreen'],
      [['T'], 'Light or dark theme'],
    ],
  ],
  [
    'Find',
    [
      [['Ctrl K', '/'], 'Search protocols and steps'],
      [['N', 'P'], 'Next / previous protocol'],
      [['?'], 'These shortcuts'],
    ],
  ],
  [
    'Packet inspector',
    [
      [['←', '→'], 'Previous / next packet'],
      [['Esc'], 'Close it'],
    ],
  ],
];

export function ShortcutsDialog({ onClose }: { onClose: () => void }) {
  const { t } = useT();
  return (
    <Dialog onClose={onClose} className="shortcuts">
      <div className="dialog-head">
        <h2>{t('Keyboard shortcuts')}</h2>
        <button className="icon-btn" onClick={onClose}>
          <X size={18} />
        </button>
      </div>
      <div className="shortcuts-body">
        {SHORTCUTS.map(([group, items]) => (
          <section key={group}>
            <h3>{group}</h3>
            <dl>
              {items.map(([keys, label]) => (
                <div key={label}>
                  <dt>
                    {keys.map((k, i) => (
                      <span key={k}>
                        {i > 0 && <span className="kbd-or">/</span>}
                        <kbd>{k}</kbd>
                      </span>
                    ))}
                  </dt>
                  <dd>{label}</dd>
                </div>
              ))}
            </dl>
          </section>
        ))}
      </div>
      <p className="dialog-foot muted small">
        Press <kbd>?</kbd> any time to see these again.
      </p>
    </Dialog>
  );
}
