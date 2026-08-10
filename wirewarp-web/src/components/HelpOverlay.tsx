import { useEffect } from 'react'
import { Ic } from './icons'
import { K } from './ui'

export function HelpOverlay({ onClose }: { onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === '?') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div
      className="help-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="help-card">
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 16 }}>
          <div>
            <h2>Keyboard shortcuts</h2>
            <p>Operators want to fly. Don't make us click.</p>
          </div>
          <button className="tb-icon-btn" onClick={onClose}>
            <Ic.close />
          </button>
        </div>
        <div className="help-grid">
          <section>
            <h3>Global</h3>
            <dl>
              <dt>
                <K>⌘</K>
                <K>K</K>
              </dt>
              <dd>Open command palette</dd>
              <dt>
                <K>?</K>
              </dt>
              <dd>This help</dd>
              <dt>
                <K>/</K>
              </dt>
              <dd>Focus filter on current page</dd>
              <dt>
                <K>N</K>
              </dt>
              <dd>New (context-sensitive)</dd>
            </dl>
            <h3 style={{ marginTop: 16 }}>Tables</h3>
            <dl>
              <dt>
                <K>j</K>
                <K>k</K>
              </dt>
              <dd>Move row focus</dd>
              <dt>
                <K>↵</K>
              </dt>
              <dd>Open focused row</dd>
              <dt>
                <K>e</K>
              </dt>
              <dd>Edit focused row</dd>
              <dt>
                <K>x</K>
              </dt>
              <dd>Toggle / disable</dd>
            </dl>
          </section>
          <section>
            <h3>Go to…</h3>
            <dl>
              <dt>
                <K>g</K> <K>d</K>
              </dt>
              <dd>Dashboard</dd>
              <dt>
                <K>g</K> <K>n</K>
              </dt>
              <dd>Nodes</dd>
              <dt>
                <K>g</K> <K>p</K>
              </dt>
              <dd>Port forwards</dd>
            </dl>
            <h3 style={{ marginTop: 16 }}>Forms</h3>
            <dl>
              <dt>
                <K>↵</K>
              </dt>
              <dd>Submit</dd>
              <dt>
                <K>esc</K>
              </dt>
              <dd>Cancel</dd>
              <dt>
                <K>tab</K>
              </dt>
              <dd>Next field</dd>
            </dl>
          </section>
        </div>
        <div
          style={{
            marginTop: 20,
            paddingTop: 14,
            borderTop: '1px solid var(--border-soft)',
            color: 'var(--fg-3)',
            fontSize: 12,
            fontFamily: 'var(--font-mono)',
          }}
        >
          built for sysadmins · keyboard first · dense by default
        </div>
      </div>
    </div>
  )
}
