'use client';
import { ArrowRight, Check, ChevronLeft, Play, RotateCcw } from 'lucide-react';
import { bubbleLine } from './hooks';
import { LAYER_NAMES } from '@/lessons';
import type { Lesson, Packet } from '@/engine/types';
import { useT } from './i18n';

export interface PacketCard {
  packet: Packet;
  no: number;
  total: number;
  fromLabel: string;
  toLabel: string;
  flying: boolean;
}

interface Props {
  lesson: Lesson;
  step: number;
  shown: number;
  onGo: (step: number) => void;
  onStart: () => void;
  onNextLesson: (() => void) | null;
  onInspectStepPacket: (stepIndex: number, packetIndex: number) => void;
  card: PacketCard | null;
  onInspectCard: () => void;
  playing: boolean;
}

function Facts({ facts }: { facts?: [string, string][] }) {
  if (!facts?.length) return null;
  return (
    <dl className="facts">
      {facts.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ExplainPanel({ lesson, step, shown, onGo, onStart, onNextLesson, onInspectStepPacket, card, onInspectCard, playing }: Props) {
  const { t } = useT();
  const total = lesson.steps.length;
  const cur = step >= 0 && step < total ? lesson.steps[step] : null;

  return (
    <aside className="panel explain">
      <div className="panel-head">
        <h2 className="panel-title">{t(step < 0 ? 'Protocol overview' : step >= total ? 'Summary' : 'Step details')}</h2>
        {step >= 0 && (
          <button className="btn xs" onClick={() => onGo(-1)} title="Back to the overview (Esc)">
            <ChevronLeft size={13} /> {t('Overview')}
          </button>
        )}
        {step < 0 && <span className={`status ${playing ? 'is-on' : ''}`}>● {t('Active')}</span>}
      </div>
      <div className="explain-scroll">
        {step < 0 && (
          <div className="explain-card fade-in" key="overview">
            <div className="eyebrow">
              {t('Layer')} {lesson.layer} · {t(LAYER_NAMES[lesson.layer])}
            </div>
            <h2 className="explain-title">{lesson.name}</h2>
            <p className="explain-full">{lesson.overview.full}</p>
            <p className="explain-text">{lesson.overview.description}</p>
            <Facts facts={lesson.overview.facts} />
            <button className="btn primary wide" onClick={onStart}>
              <Play size={16} fill="currentColor" /> {t('Start lesson')}
            </button>
            <p className="hint">
              <kbd>Space</kbd> play · <kbd>→</kbd> next step · <kbd>?</kbd> all shortcuts
            </p>
          </div>
        )}

        {cur && (
          <div className="explain-card fade-in" key={`step-${step}`}>
            <div className="eyebrow">
              {t('Step')} {step + 1} {t('of')} {total}
            </div>
            <h2 className="explain-title">{cur.title}</h2>
            <p className="explain-sub">{cur.desc}</p>
            <p className="explain-text">{cur.detail}</p>
            {card && (
              <button className={`pcard c-${card.packet.color} ${card.flying ? 'is-flying' : ''}`} onClick={onInspectCard} disabled={card.flying} title="Inspect this packet">
                <span className="pcard-head">
                  <span className="pcard-label">{card.packet.label}</span>
                  <span className="pcard-route">{card.fromLabel} → {card.toLabel}</span>
                </span>
                <span className="pcard-line mono">{bubbleLine(card.packet) || card.packet.info}</span>
                <span className="pcard-meta">
                  Packet {card.no} of {card.total} · {card.packet.proto} · {card.packet.len} B
                  {card.packet.lost && <span className="lost-chip">LOST</span>}
                </span>
              </button>
            )}
            <Facts facts={cur.facts} />
            {!!cur.packets?.length && (
              <div className="chips">
                <div className="chips-label">{t('Packets in this step')}</div>
                {cur.packets.map((p, i) => (
                  <button
                    key={i}
                    className={`chip c-${p.color} ${i < shown ? 'is-sent' : i === shown ? 'is-flying' : ''}`}
                    disabled={i >= shown}
                    onClick={() => onInspectStepPacket(step, i)}
                    title={i < shown ? 'Inspect' : 'Not sent yet'}
                  >
                    <i className="dot" />
                    {p.label}
                    {p.lost && <span className="lost-chip">LOST</span>}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        {step >= total && (
          <div className="explain-card fade-in done-card" key="outro">
            <div className="done-badge">
              <Check size={26} strokeWidth={3} />
            </div>
            <div className="eyebrow">{t('Lesson complete')}</div>
            <h2 className="explain-title">{lesson.outro.title}</h2>
            <p className="explain-text">{lesson.outro.text}</p>
            <Facts facts={[...(lesson.outro.facts ?? []), ['Packets', String(lesson.packetCount)]]} />
            <div className="row-btns">
              <button className="btn" onClick={() => onGo(0)}>
                <RotateCcw size={15} /> {t('Replay')}
              </button>
              {onNextLesson && (
                <button className="btn primary" onClick={onNextLesson}>
                  {t('Next lesson')} <ArrowRight size={15} />
                </button>
              )}
            </div>
          </div>
        )}

        <ol className="timeline">
          <li className={step < 0 ? 'is-current' : 'is-done'}>
            <button onClick={() => onGo(-1)}>
              <span className="tl-dot" />
              <span className="tl-title">{t('Overview')}</span>
            </button>
          </li>
          {lesson.steps.map((s, i) => (
            <li key={i} className={i === step ? 'is-current' : i < step ? 'is-done' : ''}>
              <button onClick={() => onGo(i)}>
                <span className="tl-dot">{i < step ? <Check size={10} strokeWidth={4} /> : i + 1}</span>
                <span className="tl-title">{s.title}</span>
                <span className="tl-desc">{s.desc}</span>
              </button>
            </li>
          ))}
          <li className={step >= total ? 'is-current' : ''}>
            <button onClick={() => onGo(total)}>
              <span className="tl-dot">★</span>
              <span className="tl-title">{t('Summary')}</span>
            </button>
          </li>
        </ol>
      </div>
    </aside>
  );
}
