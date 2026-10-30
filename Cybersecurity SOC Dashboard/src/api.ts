/**
 * REST client boundary for the future Flask integration.
 * The UI uses clearly labelled local mock data until VITE_API_URL is configured.
 */
const API_URL = import.meta.env.VITE_API_URL

export const api = {
  configured: Boolean(API_URL),
  async get<T>(path: string): Promise<T> {
    if (!API_URL) throw new Error('Flask API is not configured. Set VITE_API_URL to connect.')
    const response = await fetch(`${API_URL}${path}`, { headers: { Accept: 'application/json' } })
    if (!response.ok) throw new Error(`API request failed: ${response.status}`)
    return response.json() as Promise<T>
  },
}
