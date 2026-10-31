/**
 * Local backend API boundary.
 * The desktop app expects the Python service on localhost:8765.
 * Until it is running, the UI remains in clearly-labelled demo mode.
 */
const API_URL = (import.meta.env.VITE_API_URL as string | undefined) || 'http://127.0.0.1:8765/api'

export type BackendHealth = {
  status: 'ok' | 'degraded'
  service: string
  mode: 'development-scaffold'
}

export const api = {
  baseUrl: API_URL,
  async get<T>(path: string): Promise<T> {
    const response = await fetch(`${API_URL}${path}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(2500),
    })
    if (!response.ok) throw new Error(`API request failed: ${response.status}`)
    return response.json() as Promise<T>
  },
  async health(): Promise<BackendHealth> {
    return this.get<BackendHealth>('/health')
  },
}
