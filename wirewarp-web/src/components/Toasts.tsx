import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'

type Tone = 'ok' | 'err' | 'info'
type Toast = { id: string; msg: ReactNode; tone: Tone; scheme: string }

type Push = (msg: ReactNode, tone?: Tone, scheme?: string) => void
const ToastCtx = createContext<Push>(() => {})

export function ToastProvider({ children }: { children: ReactNode }) {
  const [list, setList] = useState<Toast[]>([])
  const push: Push = useCallback((msg, tone = 'ok', scheme = 'ok://') => {
    const id = Math.random().toString(36).slice(2)
    setList((l) => [...l, { id, msg, tone, scheme }])
    setTimeout(() => setList((l) => l.filter((x) => x.id !== id)), 3200)
  }, [])
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {list.map((t) => (
          <div key={t.id} className={`toast ${t.tone}`}>
            <span className="scheme">{t.scheme}</span>
            <span>{t.msg}</span>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export function useToast() {
  return useContext(ToastCtx)
}
