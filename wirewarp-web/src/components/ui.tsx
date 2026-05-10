import {
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type SelectHTMLAttributes,
  type ReactNode,
  type CSSProperties,
  useEffect,
} from 'react'

/* ---------- KBD ---------- */
export function K({ children }: { children: ReactNode }) {
  return <kbd>{children}</kbd>
}

/* ---------- Button ---------- */
type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'primary' | 'ghost' | 'danger'
  size?: 'sm' | 'lg'
  kbd?: ReactNode
  leading?: ReactNode
  trailing?: ReactNode
}

export function Button({
  variant = 'default',
  size,
  children,
  kbd,
  leading,
  trailing,
  className,
  ...rest
}: ButtonProps) {
  const cls = ['btn']
  if (variant === 'primary') cls.push('btn-primary')
  if (variant === 'ghost') cls.push('btn-ghost')
  if (variant === 'danger') cls.push('btn-danger')
  if (size === 'sm') cls.push('btn-sm')
  if (size === 'lg') cls.push('btn-lg')
  if (className) cls.push(className)
  return (
    <button className={cls.join(' ')} {...rest}>
      {leading}
      {children}
      {trailing}
      {kbd && <span className="kbd-inline">{kbd}</span>}
    </button>
  )
}

/* ---------- Input / Select / Field ---------- */
type InputProps = InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }
export function Input({ mono, className, ...rest }: InputProps) {
  return <input className={`input ${mono ? 'input-mono' : ''} ${className || ''}`} {...rest} />
}

type SelectProps = SelectHTMLAttributes<HTMLSelectElement> & { children: ReactNode }
export function Select({ children, className, ...rest }: SelectProps) {
  return (
    <select className={`select ${className || ''}`} {...rest}>
      {children}
    </select>
  )
}

export function Field({
  label,
  hint,
  children,
  style,
}: {
  label: ReactNode
  hint?: ReactNode
  children: ReactNode
  style?: CSSProperties
}) {
  return (
    <label className="field" style={style}>
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  )
}

/* ---------- Badge ---------- */
type Tone = 'neutral' | 'ok' | 'warn' | 'err' | 'info' | 'peer' | 'accent'
export function Badge({
  tone = 'neutral',
  children,
  leading,
}: {
  tone?: Tone
  children: ReactNode
  leading?: ReactNode
}) {
  return (
    <span className={`badge ${tone}`}>
      {leading}
      {children}
    </span>
  )
}

/* ---------- Toggle ---------- */
export function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={on}
      className={`tg ${on ? 'on' : ''}`}
      onClick={() => onChange(!on)}
    />
  )
}

/* ---------- StatusDot ---------- */
const STATUS_MAP: Record<string, string> = {
  connected: 'ok',
  online: 'ok',
  active: 'ok',
  pending: 'warn',
  degraded: 'warn',
  disconnected: 'err',
  offline: 'err',
  error: 'err',
  down: 'err',
  peering: 'info',
  info: 'info',
}
export function StatusDot({ status, label }: { status?: string | null; label?: ReactNode | false }) {
  const cls = STATUS_MAP[status || ''] || ''
  return (
    <span className="row" style={{ gap: 6 }}>
      <span className={`dot ${cls}`} aria-hidden></span>
      {label !== false && (
        <span style={{ textTransform: 'lowercase', color: 'var(--fg-1)' }}>
          {label || status}
        </span>
      )}
    </span>
  )
}

/* ---------- IpChip ---------- */
export function IpChip({
  ip,
  port,
  primary,
  scheme,
}: {
  ip: ReactNode
  port?: number | null
  primary?: boolean
  scheme?: ReactNode
}) {
  return (
    <span className={`ipchip ${primary ? 'primary' : ''}`}>
      {scheme && <span className="scheme">{scheme}</span>}
      <span>
        {ip}
        {port != null && (
          <>
            <span style={{ color: 'var(--fg-3)' }}>:</span>
            {port}
          </>
        )}
      </span>
    </span>
  )
}

/* ---------- Tabs ---------- */
export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { value: T; label: ReactNode; count?: number }[]
  value: T
  onChange: (v: T) => void
}) {
  return (
    <div className="tabs">
      {tabs.map((t) => (
        <button
          key={t.value}
          className={`tab ${value === t.value ? 'active' : ''}`}
          onClick={() => onChange(t.value)}
        >
          {t.label}
          {t.count != null && (
            <span
              style={{
                color: 'var(--fg-3)',
                fontFamily: 'var(--font-mono)',
                marginLeft: 6,
                fontSize: 11,
              }}
            >
              {t.count}
            </span>
          )}
        </button>
      ))}
    </div>
  )
}

/* ---------- Tooltip ---------- */
export function Tooltip({ text, children }: { text: ReactNode; children: ReactNode }) {
  return (
    <span className="has-tooltip" tabIndex={0}>
      {children}
      <span className="tip">{text}</span>
    </span>
  )
}

/* ---------- Stat ---------- */
export function Stat({ label, value }: { label: ReactNode; value: ReactNode }) {
  return (
    <div>
      <div
        style={{
          fontSize: 11,
          color: 'var(--fg-2)',
          fontFamily: 'var(--font-mono)',
          textTransform: 'uppercase',
          letterSpacing: 0.5,
          marginBottom: 4,
        }}
      >
        {label}
      </div>
      <div
        className="mono"
        style={{ fontSize: 14, color: 'var(--fg-0)', fontVariantNumeric: 'tabular-nums' }}
      >
        {value}
      </div>
    </div>
  )
}

/* ---------- Dialog ---------- */
export function Dialog({
  title,
  scheme,
  onClose,
  children,
  footer,
  width,
}: {
  title: ReactNode
  scheme?: ReactNode
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  width?: number
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div
      className="scrim"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="dialog" style={width ? { width } : undefined}>
        <div className="dialog-head">
          <div>
            <h2 style={{ display: 'inline' }}>{title}</h2>
            {scheme && <span className="scheme">{scheme}</span>}
          </div>
          <button className="tb-icon-btn" onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>
        <div className="dialog-body">{children}</div>
        {footer && <div className="dialog-foot">{footer}</div>}
      </div>
    </div>
  )
}

function CloseIcon() {
  return (
    <svg width={12} height={12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M2.5 2.5l7 7M9.5 2.5l-7 7" />
    </svg>
  )
}

/* ---------- Sheet ---------- */
export function Sheet({
  onClose,
  children,
  width,
}: {
  onClose: () => void
  children: ReactNode
  width?: number
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <>
      <div className="sheet-scrim" onClick={onClose} />
      <aside className="sheet" style={width ? { width } : undefined}>
        {children}
      </aside>
    </>
  )
}

/* ---------- KV (key/value table for detail panes) ---------- */
type KVRow = [label: ReactNode, value: ReactNode, mono?: boolean]
export function KV({ pairs }: { pairs: KVRow[] }) {
  return (
    <div className="kv">
      {pairs.map(([k, v, mono], i) => (
        <div
          key={i}
          className="kv-row"
          style={{
            display: 'grid',
            gridTemplateColumns: '120px 1fr 28px',
            gap: 12,
            padding: '8px 14px',
            borderBottom: '1px solid var(--border-soft)',
            fontSize: 13,
            alignItems: 'center',
          }}
        >
          <span
            style={{
              color: 'var(--fg-2)',
              fontFamily: 'var(--font-mono)',
              fontSize: 11,
              textTransform: 'uppercase',
              letterSpacing: 0.5,
            }}
          >
            {k}
          </span>
          <span className={mono ? 'mono' : ''} style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {v}
          </span>
          {mono && (
            <button
              className="tb-icon-btn"
              style={{ width: 22, height: 22 }}
              onClick={() => {
                if (typeof v === 'string') navigator.clipboard?.writeText(v)
              }}
              aria-label="copy"
            >
              <svg width={10} height={10} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4">
                <rect x="3.5" y="3.5" width="7" height="7" rx="0.5" />
                <path d="M2 8.5V2.5C2 1.95 2.45 1.5 3 1.5H8.5" />
              </svg>
            </button>
          )}
        </div>
      ))}
    </div>
  )
}

/* ---------- FilterBar ---------- */
import { Ic } from './icons'
import type { RefObject } from 'react'
export function FilterBar({
  filterRef,
  filter,
  setFilter,
  chips,
  right,
}: {
  filterRef?: RefObject<HTMLInputElement | null>
  filter: string
  setFilter: (s: string) => void
  chips?: { label: ReactNode; value: string; onChange: (v: string) => void; options: [string, string][] }[]
  right?: ReactNode
}) {
  return (
    <div className="filter-bar">
      <div className="filter-input-wrap">
        <Ic.search />
        <input
          ref={filterRef}
          className="filter-input"
          placeholder="filter…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <K>/</K>
      </div>
      {chips?.map((c, i) => (
        <span key={i} className="filter-chip">
          <span className="label">{c.label}</span>
          <select value={c.value} onChange={(e) => c.onChange(e.target.value)}>
            {c.options.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </span>
      ))}
      <div className="grow"></div>
      {right}
    </div>
  )
}

/* ---------- relTime ---------- */
// eslint-disable-next-line react-refresh/only-export-components
export function relTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const ms = Date.now() - new Date(iso).getTime()
  if (ms < 5000) return 'just now'
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.floor(h / 24)
  return `${d}d ago`
}
