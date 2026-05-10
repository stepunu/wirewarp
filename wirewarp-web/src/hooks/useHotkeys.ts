import { useEffect } from 'react'

type Opts = {
  onCmdK: () => void
  onHelp: () => void
  navigate: (path: string) => void
  active: boolean
}

const GO_MAP: Record<string, string> = {
  d: '/',
  a: '/agents',
  s: '/tunnel-servers',
  c: '/tunnel-clients',
  l: '/lan-clients',
  p: '/port-forwards',
  u: '/users',
  e: '/vpn-endpoints',
  v: '/vpn',
}

export function useGlobalHotkeys({ onCmdK, onHelp, navigate, active }: Opts) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName
      const inField = tag === 'INPUT' || tag === 'TEXTAREA'
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        onCmdK()
        return
      }
      if (!active) return
      if (inField) return
      if (e.key === '?') {
        e.preventDefault()
        onHelp()
      }
      if (e.key === 'g') {
        const next = (e2: KeyboardEvent) => {
          window.removeEventListener('keydown', next)
          const dst = GO_MAP[e2.key.toLowerCase()]
          if (dst) navigate(dst)
        }
        window.addEventListener('keydown', next, { once: true })
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onCmdK, onHelp, navigate, active])
}
