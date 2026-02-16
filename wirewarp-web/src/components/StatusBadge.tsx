const colors: Record<string, string> = {
  connected: 'bg-green-500/20 text-green-400',
  disconnected: 'bg-red-500/20 text-red-400',
  pending: 'bg-yellow-500/20 text-yellow-400',
}

export default function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium ${colors[status] || 'bg-gray-700 text-gray-300'}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${status === 'connected' ? 'bg-green-400' : status === 'disconnected' ? 'bg-red-400' : 'bg-yellow-400'}`} />
      {status}
    </span>
  )
}
