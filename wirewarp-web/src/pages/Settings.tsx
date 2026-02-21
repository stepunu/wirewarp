import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { settings } from '../lib/api'

export default function Settings() {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({ queryKey: ['settings'], queryFn: settings.get })

  const [publicUrl, setPublicUrl] = useState('')
  const [internalUrl, setInternalUrl] = useState('')
  const [instanceName, setInstanceName] = useState('')
  const [tokenExpiry, setTokenExpiry] = useState(24)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (data) {
      setPublicUrl(data.public_url ?? '')
      setInternalUrl(data.internal_url ?? '')
      setInstanceName(data.instance_name)
      setTokenExpiry(data.agent_token_expiry_hours)
    }
  }, [data])

  const update = useMutation({
    mutationFn: () =>
      settings.update({
        public_url: publicUrl.trim() || null,
        internal_url: internalUrl.trim() || null,
        instance_name: instanceName.trim() || undefined,
        agent_token_expiry_hours: tokenExpiry,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings'] })
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    },
  })

  if (isLoading) return <div className="text-gray-400">Loading…</div>

  return (
    <div className="max-w-lg">
      <h1 className="text-2xl font-bold text-white mb-6">Settings</h1>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 space-y-5">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Public URL</label>
          <input
            type="text"
            value={publicUrl}
            onChange={(e) => setPublicUrl(e.target.value)}
            placeholder="http://ddns.example.com:8100"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm placeholder-gray-600"
          />
          <p className="text-xs text-gray-500 mt-1">
            URL used in install commands for VPS/external agents. Must be reachable from the internet. Leave empty to use the browser URL.
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Internal URL</label>
          <input
            type="text"
            value={internalUrl}
            onChange={(e) => setInternalUrl(e.target.value)}
            placeholder="http://192.168.20.220:8100"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm placeholder-gray-600"
          />
          <p className="text-xs text-gray-500 mt-1">
            URL used in install commands for LAN gateway agents. Set this to the control server's direct LAN IP so agents don't rely on split DNS. Leave empty to use the Public URL.
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Instance Name</label>
          <input
            type="text"
            value={instanceName}
            onChange={(e) => setInstanceName(e.target.value)}
            placeholder="WireWarp"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm placeholder-gray-600"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Token Expiry (hours)</label>
          <input
            type="number"
            min={1}
            value={tokenExpiry}
            onChange={(e) => setTokenExpiry(Number(e.target.value))}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm"
          />
          <p className="text-xs text-gray-500 mt-1">How long registration tokens remain valid.</p>
        </div>

        <div className="flex items-center gap-3 pt-2">
          <button
            onClick={() => update.mutate()}
            disabled={update.isPending}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm font-medium disabled:opacity-50"
          >
            {update.isPending ? 'Saving…' : 'Save'}
          </button>
          {saved && <span className="text-sm text-green-400">Saved</span>}
          {update.isError && (
            <span className="text-sm text-red-400">Failed to save</span>
          )}
        </div>
      </div>
    </div>
  )
}
