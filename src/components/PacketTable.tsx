'use client';
import { useEffect, useRef } from 'react';
import type { Lesson, Packet } from '@/engine/types';
import { useT } from './i18n';

interface Props {
  lesson: Lesson;
  captured: Packet[];
  selected: number | null;
  onSelect: (i: number) => void;
  /** Playback controls, shown on the right of the panel header. */
  actions?: React.ReactNode;
}

export function PacketTable({ lesson, captured, selected, onSelect, actions }: Props) {
  const { t } = useT();
  const scroller = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = scroller.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
  }, [captured.length]);

  return (
    <section className="panel packets">
      <div className="panel-head">
        <h2 className="panel-title">{t('Packet flow')}</h2>
        <div className="legend">
          {lesson.legend.map(([c, label]) => (
            <span key={label} className="legend-item">
              <i className={`dot c-${c}`} />
              {label}
            </span>
          ))}
        </div>
        <div className="packet-actions">{actions}</div>
      </div>
      <div className="packet-scroll" ref={scroller}>
        <table className="packet-table">
          <thead>
            <tr>
              <th style={{ width: 52 }}>{t('No.')}</th>
              <th style={{ width: 84 }}>{t('Time')}</th>
              <th style={{ width: 132 }}>{t('Source')}</th>
              <th style={{ width: 132 }}>{t('Destination')}</th>
              <th style={{ width: 92 }}>{t('Protocol')}</th>
              <th>{t('Info')}</th>
              <th style={{ width: 70 }}>{t('Size')}</th>
            </tr>
          </thead>
          <tbody>
            {captured.length === 0 && (
              <tr className="empty">
                <td colSpan={7}>{t('No packets yet — press Play or → to start.')}</td>
              </tr>
            )}
            {captured.map((p, i) => (
              <tr
                key={i}
                className={`${selected === i ? 'is-selected' : ''} ${p.lost ? 'is-lost' : ''}`}
                onClick={() => onSelect(i)}
                tabIndex={0}
                onKeyDown={(e) => e.key === 'Enter' && onSelect(i)}
              >
                <td>
                  <span className={`num c-${p.color}`}>{i + 1}</span>
                </td>
                <td className="mono">{p.time.toFixed(3)}</td>
                <td className="mono">{p.src}</td>
                <td className="mono">{p.dst}</td>
                <td>
                  <span className={`proto c-${p.color}`}>{p.proto}</span>
                </td>
                <td className="info">
                  {p.info}
                  {p.lost && <span className="lost-chip">LOST</span>}
                </td>
                <td className="mono">{p.len} B</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
