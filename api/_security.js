import crypto from 'node:crypto'
import dns from 'node:dns/promises'
import net from 'node:net'

const APP_ORIGIN = 'https://website-jadibot-by-alzriss.vercel.app'
const buckets = globalThis.__umiSecurityBuckets || new Map()
globalThis.__umiSecurityBuckets = buckets

export class HttpError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

export function securityHeaders(res, { api = true } = {}) {
  const headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': api ? 'same-origin' : 'same-site',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'X-DNS-Prefetch-Control': 'off',
    'Cache-Control': 'no-store, max-age=0',
  }
  for (const [key, value] of Object.entries(headers)) res.setHeader(key, value)
}

export function clientKey(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()
  const raw = String(req.headers['x-real-ip'] || forwarded || req.socket?.remoteAddress || 'unknown')
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 24)
}

export function rateLimit(req, scope, limit, windowMs) {
  const now = Date.now()
  const key = `${scope}:${clientKey(req)}`
  let bucket = buckets.get(key)
  if (!bucket || bucket.resetAt <= now) bucket = { count: 0, resetAt: now + windowMs }
  bucket.count += 1
  buckets.set(key, bucket)

  // Opportunistic cleanup for warm serverless instances.
  if (buckets.size > 5000) {
    for (const [entryKey, entry] of buckets) if (entry.resetAt <= now) buckets.delete(entryKey)
  }
  if (bucket.count > limit) {
    const error = new HttpError(429, 'Terlalu banyak permintaan. Coba lagi beberapa saat.')
    error.retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))
    throw error
  }
  return bucket
}

export function enforceSameOrigin(req) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return
  if (String(req.headers['sec-fetch-site'] || '').toLowerCase() === 'cross-site') {
    throw new HttpError(403, 'Permintaan lintas situs ditolak.')
  }
  const origin = String(req.headers.origin || '').trim()
  if (!origin) return // CLI/server clients authenticate using bearer/API keys.
  const ownOrigin = req.headers.host ? `https://${req.headers.host}` : ''
  const configured = String(process.env.UMI_ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean)
  const allowed = new Set([APP_ORIGIN, ownOrigin, ...configured].filter(Boolean))
  if (!allowed.has(origin)) throw new HttpError(403, 'Origin tidak diizinkan.')
}

export function assertBodySize(req, maximumBytes) {
  const length = Number(req.headers['content-length'] || 0)
  if (Number.isFinite(length) && length > maximumBytes) throw new HttpError(413, 'Ukuran permintaan terlalu besar.')
}

export function safeId(value, name = 'ID', min = 1, max = 128) {
  const result = String(value ?? '').trim()
  if (result.length < min || result.length > max || !/^[A-Za-z0-9_-]+$/.test(result)) {
    throw new HttpError(400, `${name} tidak valid.`)
  }
  return result
}

export function safeNumericId(value, name = 'ID') {
  const result = String(value ?? '').trim()
  if (!/^\d{1,20}$/.test(result)) throw new HttpError(400, `${name} tidak valid.`)
  return result
}

export function safeUuid(value, name = 'ID') {
  const result = String(value ?? '').trim().toLowerCase()
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(result)) {
    throw new HttpError(400, `${name} tidak valid.`)
  }
  return result
}

function isPrivateIpv4(hostname) {
  const match = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!match) return false
  const octets = match.slice(1).map(Number)
  if (octets.some(x => x > 255)) return true
  const [a, b] = octets
  return a === 0 || a === 10 || a === 100 && b >= 64 && b <= 127 || a === 127 ||
    a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 ||
    a === 192 && (b === 0 || b === 168) || a === 198 && [18, 19].includes(b) || a >= 224
}

function isPrivateAddress(address) {
  let value = String(address || '').toLowerCase().split('%')[0]
  if (value.startsWith('::ffff:')) value = value.slice(7)
  if (net.isIP(value) === 4) return isPrivateIpv4(value)
  if (net.isIP(value) !== 6) return true
  return value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd') || value.startsWith('fe8') || value.startsWith('fe9') || value.startsWith('fea') || value.startsWith('feb')
}

export function publicHttpUrl(value, { maxLength = 2000 } = {}) {
  const input = String(value || '').trim()
  if (!input || input.length > maxLength) throw new HttpError(400, 'URL tidak valid.')
  let url
  try { url = new URL(input) } catch { throw new HttpError(400, 'URL tidak valid.') }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new HttpError(400, 'URL tidak diizinkan.')
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host === '0.0.0.0' || host === 'metadata.google.internal' || isPrivateIpv4(host) || host === '::1' || host.startsWith('fe80:') || host.startsWith('fc') || host.startsWith('fd')) {
    throw new HttpError(400, 'URL jaringan privat tidak diizinkan.')
  }
  if (url.port && !['80', '443'].includes(url.port)) throw new HttpError(400, 'Port URL tidak diizinkan.')
  return url.toString()
}

export async function resolvedPublicHttpUrl(value, options = {}) {
  const normalized = publicHttpUrl(value, options)
  const url = new URL(normalized)
  if (net.isIP(url.hostname)) {
    if (isPrivateAddress(url.hostname)) throw new HttpError(400, 'URL jaringan privat tidak diizinkan.')
    return normalized
  }
  let records
  try {
    records = await dns.lookup(url.hostname, { all: true, verbatim: true })
  } catch {
    throw new HttpError(400, 'Hostname URL tidak dapat diverifikasi.')
  }
  if (!records.length || records.some(record => isPrivateAddress(record.address))) {
    throw new HttpError(400, 'Hostname mengarah ke jaringan privat dan ditolak.')
  }
  return normalized
}

export function noSniffUpload(file, allowedMime, allowedExtensions) {
  const filename = String(file?.originalFilename || '')
  const extension = filename.includes('.') ? filename.split('.').pop().toLowerCase() : ''
  if (!allowedMime.includes(String(file?.mimetype || '').toLowerCase()) || !allowedExtensions.includes(extension)) {
    throw new HttpError(400, 'Tipe file tidak diizinkan.')
  }
  if (!Number.isFinite(Number(file?.size)) || Number(file.size) < 1) throw new HttpError(400, 'File kosong atau tidak valid.')
  return extension
}
