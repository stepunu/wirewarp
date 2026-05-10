import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Ic } from './icons'
import { K } from './ui'
import type { Agent } from '../lib/types'

type IconFn = (p?: { s?: number }) => ReactNode

type Item = {
  section: string
  icon: IconFn
  label: string
  hint: string
  action: () => void
}

export function CommandPalette({
  onClose,
  navigate,
  agents,
}: {
  onClose: () => void
  navigate: (path: string) => void
  agents: Agent[]
}) {
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  const items = useMemo<Item[]>(() => {
    const all: Item[] = [
      { section: 'Navigate', icon: Ic.dashboard, label: 'Dashboard', hint: 'g d', action: () => navigate('/') },
      { section: 'Navigate', icon: Ic.agent, label: 'Agents', hint: 'g a', action: () => navigate('/agents') },
      { section: 'Navigate', icon: Ic.server, label: 'Tunnel servers', hint: 'g s', action: () => navigate('/tunnel-servers') },
      { section: 'Navigate', icon: Ic.client, label: 'Tunnel clients', hint: 'g c', action: () => navigate('/tunnel-clients') },
      { section: 'Navigate', icon: Ic.host, label: 'LAN clients', hint: 'g l', action: () => navigate('/lan-clients') },
      { section: 'Navigate', icon: Ic.forward, label: 'Port forwards', hint: 'g p', action: () => navigate('/port-forwards') },
      { section: 'Navigate', icon: Ic.settings, label: 'Settings', hint: '', action: () => navigate('/settings') },
      { section: 'Actions', icon: Ic.plus, label: 'New port forward', hint: 'N', action: () => navigate('/port-forwards?new=1') },
      { section: 'Actions', icon: Ic.plus, label: 'Issue agent token', hint: '', action: () => navigate('/agents?new=1') },
      ...agents.slice(0, 8).map<Item>((a) => ({
        section: 'Agents',
        icon: a.type === 'server' ? Ic.server : Ic.client,
        label: a.name,
        hint: a.id,
        action: () => navigate(`/agents/${a.id}`),
      })),
    ]
    if (!q) return all
    const f = q.toLowerCase()
    return all.filter(
      (x) => x.label.toLowerCase().includes(f) || x.hint.toLowerCase().includes(f),
    )
  }, [q, agents, navigate])

  const sections = useMemo(() => {
    const map = new Map<string, (Item & { _i: number })[]>()
    items.forEach((it, i) => {
      if (!map.has(it.section)) map.set(it.section, [])
      map.get(it.section)!.push({ ...it, _i: i })
    })
    return [...map.entries()]
  }, [items])

  function run(it: Item) {
    it.action()
    onClose()
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setIdx((i) => Math.min(items.length - 1, i + 1))
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      setIdx((i) => Math.max(0, i - 1))
    }
    if (e.key === 'Enter') {
      e.preventDefault()
      if (items[idx]) run(items[idx])
    }
    if (e.key === 'Escape') onClose()
  }

  return (
    <div
      className="cmdk-scrim"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="cmdk">
        <div className="cmdk-input-wrap">
          <span className="scheme">wire://</span>
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => {
              setQ(e.target.value)
              setIdx(0)
            }}
            onKeyDown={onKeyDown}
            placeholder="search agents, pages, actions…"
          />
          <K>esc</K>
        </div>
        <div className="cmdk-list">
          {sections.map(([section, rows]) => (
            <div key={section}>
              <div className="cmdk-section">{section}</div>
              {rows.map((r) => (
                <div
                  key={r._i}
                  className={`cmdk-row ${r._i === idx ? 'active' : ''}`}
                  onMouseEnter={() => setIdx(r._i)}
                  onClick={() => run(r)}
                >
                  <r.icon s={14} />
                  <span>{r.label}</span>
                  {r.hint && <span className="hint">{r.hint}</span>}
                </div>
              ))}
            </div>
          ))}
          {items.length === 0 && (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--fg-3)' }}>No matches.</div>
          )}
        </div>
        <div className="cmdk-foot">
          <span>
            <K>↑</K>
            <K>↓</K> navigate
          </span>
          <span>
            <K>↵</K> select
          </span>
          <span>
            <K>esc</K> close
          </span>
          <span style={{ marginLeft: 'auto' }}>{items.length} results</span>
        </div>
      </div>
    </div>
  )
}
