const DEFAULT_REFRESH_SECONDS = 60
const MIN_REFRESH_SECONDS = 15
const MAX_REFRESH_SECONDS = 300
const STALE_GRACE_MS = 15 * 60 * 1000

let cache = null

export class BotConfigError extends Error {
  constructor(message, status = 503) {
    super(message)
    this.status = status
  }
}

function clampRefreshSeconds(value) {
  const seconds = Number(value)
  if (!Number.isFinite(seconds)) return DEFAULT_REFRESH_SECONDS
  return Math.min(MAX_REFRESH_SECONDS, Math.max(MIN_REFRESH_SECONDS, Math.floor(seconds)))
}

function httpsOrigin(value) {
  let url
  try { url = new URL(String(value || '').trim()) } catch { throw new BotConfigError('botApiOrigin pada konfigurasi Gist tidak valid.') }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new BotConfigError('botApiOrigin pada konfigurasi Gist harus berupa origin HTTPS yang valid.')
  }
  return url.origin
}

function gistConfigUrl() {
  const raw = String(process.env.UMI_CONFIG_GIST_URL || '').trim()
  if (!raw) return ''
  let url
  try { url = new URL(raw) } catch { throw new BotConfigError('UMI_CONFIG_GIST_URL tidak valid.') }
  if (url.protocol !== 'https:' || url.username || url.password) throw new BotConfigError('UMI_CONFIG_GIST_URL harus menggunakan HTTPS.')
  return url.toString()
}

function staticConfig() {
  const origin = String(process.env.UMI_API_ORIGIN || '').trim()
  if (!origin) throw new BotConfigError('Backend Umi belum dikonfigurasi.')
  return { origin: httpsOrigin(origin), version: 'environment', refreshSeconds: DEFAULT_REFRESH_SECONDS, source: 'environment' }
}

function parseGistConfig(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new BotConfigError('Isi konfigurasi Gist harus berupa objek JSON.')
  if (Number(payload.schemaVersion) !== 1) throw new BotConfigError('schemaVersion konfigurasi Gist tidak didukung.')
  return {
    origin: httpsOrigin(payload.botApiOrigin),
    version: String(payload.version || payload.updatedAt || 'gist').slice(0, 120),
    refreshSeconds: clampRefreshSeconds(payload.refreshSeconds),
    source: 'gist',
  }
}

export async function getBotApiConfig() {
  const url = gistConfigUrl()
  if (!url) return staticConfig()

  const now = Date.now()
  if (cache?.freshUntil > now) return cache.value

  try {
    const response = await fetch(url, {
      headers: { Accept: 'application/json', 'User-Agent': 'Usanagi-Umi-Jadibot-Web/1.2' },
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const value = parseGistConfig(await response.json())
    cache = {
      value,
      freshUntil: now + value.refreshSeconds * 1000,
      staleUntil: now + STALE_GRACE_MS,
    }
    return value
  } catch (error) {
    if (cache?.staleUntil > now) return cache.value
    if (error instanceof BotConfigError) throw error
    throw new BotConfigError('Konfigurasi server dari Gist tidak dapat diambil. Coba lagi sebentar.')
  }
}

export function clearBotApiConfigCache() {
  cache = null
}
