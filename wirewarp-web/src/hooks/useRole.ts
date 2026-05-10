import { useQuery } from '@tanstack/react-query'
import { auth } from '../lib/api'
import type { Role, User } from '../lib/types'

export function useCurrentUser() {
  return useQuery<User>({
    queryKey: ['me'],
    queryFn: auth.me,
    staleTime: 30_000,
  })
}

export function useRole(): {
  user: User | undefined
  role: Role | undefined
  isAdmin: boolean
  isOperator: boolean
  isViewer: boolean
  isVpnUser: boolean
  canMutate: boolean
} {
  const { data } = useCurrentUser()
  const role = data?.role
  return {
    user: data,
    role,
    isAdmin: role === 'admin',
    isOperator: role === 'operator',
    isViewer: role === 'viewer',
    isVpnUser: role === 'vpn_user',
    canMutate: role === 'admin' || role === 'operator',
  }
}
