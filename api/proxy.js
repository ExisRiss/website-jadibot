import { assertBodySize, enforceSameOrigin, rateLimit, securityHeaders } from './_security.js'
import { getBotApiConfig } from './_bot-config.js'

const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'PATCH', 'DELETE', 'OPTIONS'])
const ALLOWED_PATHS = new Set([
  'health', 'sessions', 'session/pairing', 'session/status', 'session/restart',
  'session/logout', 'settings/get', 'settings/apply', 'settings/reset',
  'backup/list', 'backup/create', 'backup/restore', 'console/logs', 'console/run',
])

function apiPath(req) {
  const value = req.query?.path
  const raw = Array.isArray(value) ? value.join('/') : String(value || '')
  return raw.split('/').filter(Boolean).map(part => encodeURIComponent(decodeURIComponent(part))).join('/')
}

export default async function handler(req, res) {
  securityHeaders(res)
  try {
    rateLimit(req, 'proxy:all', 300, 60 * 1000)
    assertBodySize(req, 1024 * 1024)
    enforceSameOrigin(req)
  } catch (error) {
    if (error.retryAfter) res.setHeader('Retry-After', String(error.retryAfter))
    return res.status(error.status || 400).json({ error: error.message })
  }
  if (!ALLOWED_METHODS.has(req.method)) {
    res.setHeader('Allow', [...ALLOWED_METHODS].join(', '))
    return res.status(405).json({ error: 'Metode tidak diizinkan.' })
  }

  let botConfig
  try {
    botConfig = await getBotApiConfig()
  } catch (error) {
    return res.status(error.status || 503).json({ error: error.message })
  }

  let path
  try {
    path = apiPath(req)
  } catch {
    return res.status(400).json({ error: 'Path API tidak valid.' })
  }
  if (!path || !ALLOWED_PATHS.has(path)) return res.status(404).json({ error: 'Endpoint API tidak ditemukan.' })
  if (path !== 'health' && !/^Bearer\s+[A-Za-z0-9._~+\/-]{20,10000}$/i.test(String(req.headers.authorization || ''))) {
    return res.status(401).json({ error: 'Autentikasi diperlukan.' })
  }

  const query = new URLSearchParams()
  const queryEntries = Object.entries(req.query || {}).filter(([key]) => key !== 'path')
  if (queryEntries.length > 20) return res.status(400).json({ error: 'Terlalu banyak parameter.' })
  for (const [key, value] of queryEntries) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(key)) return res.status(400).json({ error: 'Parameter tidak valid.' })
    const append = item => {
      const normalized = String(item)
      if (normalized.length > 1000) throw Object.assign(new Error('Parameter terlalu panjang.'), { status: 400 })
      query.append(key, normalized)
    }
    try {
      if (Array.isArray(value)) value.slice(0, 20).forEach(append)
      else if (value !== undefined) append(value)
    } catch (error) {
      return res.status(error.status || 400).json({ error: error.message })
    }
  }
  const target = `${botConfig.origin}/api/${path}${query.size ? `?${query.toString()}` : ''}`

  const headers = {
    Accept: req.headers.accept || 'application/json',
    'User-Agent': 'Usanagi-Umi-Jadibot-Web/1.1',
  }
  if (req.headers.authorization) headers.Authorization = req.headers.authorization
  if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type']

  const options = { method: req.method, headers, redirect: 'manual' }
  if (!['GET', 'HEAD'].includes(req.method)) {
    options.body = typeof req.body === 'string' || Buffer.isBuffer(req.body)
      ? req.body
      : JSON.stringify(req.body ?? {})
    headers['Content-Type'] ||= 'application/json'
  }

  try {
    const upstream = await fetch(target, { ...options, signal: AbortSignal.timeout(55000) })
    const data = Buffer.from(await upstream.arrayBuffer())
    res.status(upstream.status)
    res.setHeader('Content-Type', upstream.headers.get('content-type') || 'application/json; charset=utf-8')
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('X-Umi-Config-Version', botConfig.version)
    return req.method === 'HEAD' ? res.end() : res.send(data)
  } catch (error) {
    const timeout = error?.name === 'TimeoutError' || error?.name === 'AbortError'
    return res.status(timeout ? 504 : 502).json({
      error: timeout
        ? 'Backend Umi tidak merespons tepat waktu. Coba lagi.'
        : 'Backend Umi sedang tidak dapat dijangkau. Coba lagi sebentar.',
    })
  }
}
