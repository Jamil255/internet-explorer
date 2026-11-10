'use client';
import { useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronLeft, ChevronRight, X } from 'lucide-react';
import type { Field, Layer } from '@/engine/bytes';
import { fieldHelp, isExample } from '@/engine/fieldHelp';
import type { Packet } from '@/engine/types';

interface Props {
  packets: Packet[];
  index: number;
  onIndex: (i: number) => void;
  onClose: () => void;
  /** Describes where this capture was taken, e.g. “Seen on the laptop’s network card”. */
  whereOf?: (p: Packet) => string;
}

const SHORT: Record<string, string> = {
  'Ethernet II': 'Ethernet',
  'Internet Protocol Version 4': 'IPv4',
  'Internet Protocol Version 6': 'IPv6',
  'Transmission Control Protocol': 'TCP',
  'User Datagram Protocol': 'UDP',
  'Internet Control Message Protocol': 'ICMP',
  'Internet Control Message Protocol v6': 'ICMPv6',
  'Hypertext Transfer Protocol': 'HTTP',
  'Domain Name System': 'DNS',
  'Transport Layer Security': 'TLS',
  'Dynamic Host Configuration Protocol': 'DHCP',
  'Network Time Protocol': 'NTP',
  'Simple Mail Transfer Protocol': 'SMTP',
};
const shortName = (l: Layer) => SHORT[l.name] ?? (l.name.length > 14 ? l.key.toUpperCase() : l.name);

type Range = { start: number; len: number };
const same = (a: Range | null, b: Range) => !!a && a.start === b.start && a.len === b.len;

export function Inspector({ packets, index, onIndex, onClose, whereOf }: Props) {
  const p = packets[index];
  const where = p && whereOf ? whereOf(p) : '';
  const [hl, setHl] = useState<Range | null>(null);
  const [closed, setClosed] = useState<Record<number, boolean>>({ 0: true });

  useEffect(() => {
    setHl(null);
  }, [index]);

  const fields = useMemo(() => p?.frame.layers.flatMap((l) => l.fields) ?? [], [p]);
  if (!p) return null;

  const bytes = p.frame.bytes;
  const layerOf = (i: number) => p.frame.layers.findIndex((l) => i >= l.start && i < l.start + l.len);
  const fieldAt = (i: number): Field | undefined => fields.find((f) => i >= f.start && i < f.start + f.len);
  const rows = Math.ceil(bytes.length / 16);

  return (
    <div className="inspector-backdrop" onClick={onClose}>
      <aside className="inspector" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Packet inspector">
        <header className="ins-head">
          <span className={`num lg c-${p.color}`}>{index + 1}</span>
          <div className="ins-title">
            <div className="ins-name">
              {p.label} <span className={`proto c-${p.color}`}>{p.proto}</span>
              {p.lost && <span className="lost-chip">LOST</span>}
            </div>
            <div className="ins-where mono">
              {p.src} → {p.dst} · {p.len} bytes · {p.time.toFixed(3)} s
            </div>
          </div>
          <div className="ins-nav">
            <button className="icon-btn" disabled={index === 0} onClick={() => onIndex(index - 1)} title="Previous packet (←)">
              <ChevronLeft size={18} />
            </button>
            <span className="muted small">
              {index + 1}/{packets.length}
            </span>
            <button
              className="icon-btn"
              disabled={index === packets.length - 1}
              onClick={() => onIndex(index + 1)}
              title="Next packet (→)"
            >
              <ChevronRight size={18} />
            </button>
            <button className="icon-btn" onClick={onClose} title="Close (Esc)">
              <X size={18} />
            </button>
          </div>
        </header>

        <p className="ins-info">{p.info}</p>

        <div className="bytemap">
          {where && <div className="bytemap-where">{where}</div>}
          <div className="bytemap-bar">
            {p.frame.layers.map((l, li) => (
              <button
                key={li}
                className={`bytemap-seg L${li}`}
                style={{ flexGrow: Math.max(l.len, 6) }}
                onMouseEnter={() => setHl({ start: l.start, len: l.len })}
                onMouseLeave={() => setHl(null)}
                onClick={() => setClosed((c) => ({ ...c, [li]: false }))}
              >
                <i />
                <span>{shortName(l)}</span>
                <small>{l.len}</small>
              </button>
            ))}
          </div>
        </div>

        <div className="ins-body">
          <div className="ins-tree">
            {p.frame.layers.map((l, li) => (
              <div key={li} className={`ins-layer L${li}`}>
                <button
                  className="ins-layer-head"
                  onClick={() => setClosed((c) => ({ ...c, [li]: !c[li] }))}
                  onMouseEnter={() => setHl({ start: l.start, len: l.len })}
                  onMouseLeave={() => setHl(null)}
                >
                  <ChevronDown size={14} className={closed[li] ? 'rot' : ''} />
                  <span className="ins-layer-name">{l.name}</span>
                  <span className="ins-layer-sum">{l.summary}</span>
                  <span className="ins-layer-len">{l.len} B</span>
                </button>
                {!closed[li] && (
                  <div className="ins-fields">
                    {l.fields.map((f, fi) => (
                      <div
                        key={fi}
                        className={`ins-field ${same(hl, f) ? 'is-hl' : ''}`}
                        onMouseEnter={() => setHl({ start: f.start, len: f.len })}
                        onMouseLeave={() => setHl(null)}
                      >
                        <span className="ins-fname">{f.name}</span>
                        <span className="ins-fval">
                          {f.value}
                          {isExample(l.key, f.name, f.value) && (
                            <span className="eg" title="An example value: it differs in every real capture">
                              E.G.
                            </span>
                          )}
                        </span>
                        <span className="ins-flen">{f.len}</span>
                        {fieldHelp(l.key, f.name) && <span className="ins-help">{fieldHelp(l.key, f.name)}</span>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="hex">
            <div className="hex-head">
              <span>Offset</span>
              <span>Bytes</span>
              <span>ASCII</span>
            </div>
            <div className="hex-rows">
              {Array.from({ length: rows }, (_, r) => {
                const row = bytes.slice(r * 16, r * 16 + 16);
                return (
                  <div key={r} className="hex-row">
                    <span className="hex-off">{(r * 16).toString(16).padStart(4, '0')}</span>
                    <span className="hex-bytes">
                      {row.map((b, i) => {
                        const at = r * 16 + i;
                        const on = hl && at >= hl.start && at < hl.start + hl.len;
                        return (
                          <span
                            key={i}
                            className={`hb L${layerOf(at)} ${on ? 'is-hl' : ''}`}
                            onMouseEnter={() => {
                              const f = fieldAt(at);
                              if (f) setHl({ start: f.start, len: f.len });
                            }}
                            onMouseLeave={() => setHl(null)}
                          >
                            {b.toString(16).padStart(2, '0')}
                          </span>
                        );
                      })}
                    </span>
                    <span className="hex-ascii">
                      {row.map((b, i) => {
                        const at = r * 16 + i;
                        const on = hl && at >= hl.start && at < hl.start + hl.len;
                        return (
                          <span key={i} className={on ? 'is-hl' : ''}>
                            {b >= 32 && b < 127 ? String.fromCharCode(b) : '·'}
                          </span>
                        );
                      })}
                    </span>
                  </div>
                );
              })}
            </div>
            <div className="hex-legend">
              {p.frame.layers.map((l, li) => (
                <span key={li} className={`hex-key L${li}`}>
                  <i />
                  {shortName(l)}
                </span>
              ))}
            </div>
          </div>
        </div>
        <footer className="ins-foot muted small">
          <span className="eg">E.G.</span> an example value — it differs in every real capture. Hover a field to find its
          bytes, or a byte to find its field.
        </footer>
      </aside>
    </div>
  );
}
