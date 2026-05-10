type IP = { s?: number }

export const Ic = {
  dashboard: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <rect x="1.5" y="1.5" width="4.5" height="5" />
      <rect x="8" y="1.5" width="4.5" height="3" />
      <rect x="1.5" y="8.5" width="4.5" height="3" />
      <rect x="8" y="6.5" width="4.5" height="5.5" />
    </svg>
  ),
  agent: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <rect x="1.5" y="2" width="11" height="7" rx="1" />
      <path d="M5 12h4M7 9v3" />
    </svg>
  ),
  server: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <rect x="1.5" y="1.5" width="11" height="4" />
      <rect x="1.5" y="7.5" width="11" height="4" />
      <circle cx="3.5" cy="3.5" r="0.4" fill="currentColor" />
      <circle cx="3.5" cy="9.5" r="0.4" fill="currentColor" />
    </svg>
  ),
  client: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <rect x="1.5" y="2" width="11" height="8" rx="1" />
      <path d="M4 12h6" />
    </svg>
  ),
  forward: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M2 4h6l3 3-3 3H2" />
      <path d="M2 7h9" />
    </svg>
  ),
  settings: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <circle cx="7" cy="7" r="2" />
      <path d="M7 1v2M7 11v2M1 7h2M11 7h2M2.7 2.7l1.4 1.4M9.9 9.9l1.4 1.4M2.7 11.3l1.4-1.4M9.9 4.1l1.4-1.4" />
    </svg>
  ),
  search: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <circle cx="6" cy="6" r="4" />
      <path d="M9 9l3 3" />
    </svg>
  ),
  plus: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M6 1.5v9M1.5 6h9" />
    </svg>
  ),
  chevR: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M4.5 2.5L8 6l-3.5 3.5" />
    </svg>
  ),
  chevD: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M2.5 4.5L6 8l3.5-3.5" />
    </svg>
  ),
  copy: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4">
      <rect x="3.5" y="3.5" width="7" height="7" rx="0.5" />
      <path d="M2 8.5V2.5C2 1.95 2.45 1.5 3 1.5H8.5" />
    </svg>
  ),
  close: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M2.5 2.5l7 7M9.5 2.5l-7 7" />
    </svg>
  ),
  sun: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <circle cx="7" cy="7" r="2.5" />
      <path d="M7 1v2M7 11v2M1 7h2M11 7h2M2.5 2.5l1.5 1.5M10 10l1.5 1.5M2.5 11.5l1.5-1.5M10 4l1.5-1.5" />
    </svg>
  ),
  moon: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M11.5 8.5A5 5 0 1 1 5.5 2.5a4 4 0 0 0 6 6z" />
    </svg>
  ),
  panelL: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <rect x="1.5" y="2" width="11" height="10" rx="1" />
      <path d="M5 2v10" />
    </svg>
  ),
  help: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <circle cx="7" cy="7" r="5.5" />
      <path d="M5.5 5.5C5.5 4.5 6.2 4 7 4s1.5.5 1.5 1.4c0 1.1-1.5 1.4-1.5 2.4M7 10v.1" />
    </svg>
  ),
  refresh: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M10 4A4.5 4.5 0 1 0 10.5 7" />
      <path d="M10 1.5V4H7.5" />
    </svg>
  ),
  edit: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M2 10h2l5.5-5.5L7.5 2.5 2 8z" />
    </svg>
  ),
  trash: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M2 3.5h8M5 6v3M7 6v3" />
      <path d="M3 3.5l.5 7h5l.5-7M4.5 3.5V2h3v1.5" />
    </svg>
  ),
  play: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="currentColor">
      <path d="M3 2l7 4-7 4z" />
    </svg>
  ),
  download: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M6 1.5v7M3 6l3 3 3-3M2 10.5h8" />
    </svg>
  ),
  arrow: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M2 6h8M7 3l3 3-3 3" />
    </svg>
  ),
  host: (p?: IP) => (
    <svg width={p?.s || 14} height={p?.s || 14} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
      <rect x="1.5" y="3" width="11" height="6" rx="0.5" />
      <path d="M4.5 11h5" />
      <path d="M7 9v2" />
      <circle cx="3.5" cy="6" r="0.4" fill="currentColor" />
    </svg>
  ),
  enter: (p?: IP) => (
    <svg width={p?.s || 12} height={p?.s || 12} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M10 2v4H3.5l2-2M3.5 6l2 2" />
    </svg>
  ),
}
