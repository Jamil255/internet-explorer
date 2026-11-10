'use client';
import { useState } from 'react';
import { Check, ChevronDown, ChevronRight, X } from 'lucide-react';
import { GROUPS, LESSONS } from '@/lessons';
import { useT } from './i18n';

interface Props {
  current: string;
  done: string[];
  onPick: (id: string) => void;
  onClose: () => void;
  step: number;
  onGo: (step: number) => void;
  playing: boolean;
}

export function Sidebar({ current, done, onPick, onClose, step, onGo, playing }: Props) {
  const { t } = useT();
  const [tab, setTab] = useState('all');
  const ids = GROUPS.find((g) => g.id === tab)?.ids ?? [];
  const list = LESSONS.filter((l) => ids.includes(l.id));

  return (
    <aside className="panel sidebar" id="protocols">
      <div className="panel-head">
        <h2 className="panel-title">{t('Internet protocols')}</h2>
        <button className="icon-btn drawer-close" onClick={onClose} title="Close (Esc)">
          <X size={18} />
        </button>
      </div>
      <div className="tabs" role="tablist">
        {GROUPS.map((g) => (
          <button
            key={g.id}
            role="tab"
            aria-selected={tab === g.id}
            className={`tab ${tab === g.id ? 'is-active' : ''}`}
            onClick={() => setTab(g.id)}
          >
            {t(g.label)}
            <span className="tab-count">{g.ids.length}</span>
          </button>
        ))}
      </div>
      <ul className="proto-list">
        {list.map((l) => (
          <li key={l.id}>
            <button
              className={`proto-item ${l.id === current ? 'is-current' : ''}`}
              onClick={() => onPick(l.id)}
              aria-current={l.id === current}
            >
              <span
                className={`proto-status ${l.id === current && playing ? 'is-playing' : ''} ${done.includes(l.id) ? 'is-done' : ''}`}
              >
                {done.includes(l.id) && <Check size={10} strokeWidth={4} />}
              </span>
              <span className="proto-text">
                <span className="proto-name">{l.name}</span>
                <span className="proto-title">{l.overview.full}</span>
              </span>
              <span className={`layer-chip L${l.layer}`}>L{l.layer}</span>
              {l.id === current ? <ChevronDown size={16} className="proto-chev" /> : <ChevronRight size={16} className="proto-chev" />}
            </button>
            {l.id === current && (
              <ol className="proto-steps">
                {l.steps.map((s, i) => (
                  <li key={i} className={i === step ? 'is-current' : i < step ? 'is-done' : ''}>
                    <button onClick={() => onGo(i)}>
                      <span className="ps-dot">{i < step ? <Check size={10} strokeWidth={4} /> : i + 1}</span>
                      <span className="ps-text">
                        <b>{s.title}</b>
                        <small>{s.desc}</small>
                      </span>
                    </button>
                  </li>
                ))}
              </ol>
            )}
          </li>
        ))}
      </ul>
    </aside>
  );
}
