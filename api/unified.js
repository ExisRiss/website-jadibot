import crypto from 'node:crypto'
import { readFile } from 'node:fs/promises'
import formidable from 'formidable'
import QRCode from 'qrcode'
import {
  assertBodySize,
  enforceSameOrigin,
  noSniffUpload,
  publicHttpUrl,
  rateLimit,
  safeId,
  safeUuid,
  securityHeaders,
} from './_security.js'

export const config = { api: { bodyParser: false } }

const DB_URL = () => String(process.env.UMI_DATA_SUPABASE_URL || process.env.SUPABASE_URL || '').replace(/\/+$/, '')
const SERVICE_KEY = () => String(process.env.UMI_DATA_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || '')
const ANON_KEY = () => String(process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_PUBLISHABLE_KEY || 'sb_publishable_ebpebtzCNxvsKWb0xtgX_A_ClzPlhob')
const APP_URL = 'https://website-jadibot-by-alzriss.vercel.app'
const OWNER_EMAIL = 'akunindo2011264@gmail.com'
const CORS_METHODS = 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
const CORS_HEADERS = 'Content-Type, X-API-Key, X-VAPIKEY, Authorization'

const clean = (v, n = 500) => String(v ?? '').trim().slice(0, n)
const hash = value => crypto.createHash('sha256').update(String(value)).digest('hex')
const token = prefix => prefix + crypto.randomBytes(32).toString('base64url')
const pathOf = req => (Array.isArray(req.query?.path) ? req.query.path.join('/') : String(req.query?.path || '')).replace(/^\/+|\/+$/g, '')
const bearer = req => clean(req.headers.authorization, 10000).replace(/^Bearer\s+/i, '')

function send(res, status, data, extra = {}) {
  securityHeaders(res)
  Object.entries(extra).forEach(([k, v]) => res.setHeader(k, v))
  if (status === 204) return res.status(status).end()
  return res.status(status).json(data)
}

function configureCors(req, res, path) {
  const origin = String(req.headers.origin || '')
  const publicApi = path === 'health' || path.startsWith('gateway/')
  if (publicApi) res.setHeader('Access-Control-Allow-Origin', '*')
  else if (origin === APP_URL || origin === `https://${req.headers.host}`) {
    res.setHeader('Access-Control-Allow-Origin', origin)
    res.setHeader('Vary', 'Origin')
  }
  res.setHeader('Access-Control-Allow-Headers', CORS_HEADERS)
  res.setHeader('Access-Control-Allow-Methods', CORS_METHODS)
}

async function parseJsonBody(req, maximumBytes = 1024 * 1024) {
  if (!['POST', 'PUT', 'PATCH'].includes(req.method) || !String(req.headers['content-type'] || '').includes('application/json')) return {}
  assertBodySize(req, maximumBytes)
  const chunks = []
  let total = 0
  for await (const chunk of req) {
    total += chunk.length
    if (total > maximumBytes) throw Object.assign(new Error('Request body too large'), { status: 413 })
    chunks.push(chunk)
  }
  if (!chunks.length) return {}
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { throw Object.assign(new Error('Invalid JSON body'), { status: 400 }) }
}

const formValue = value => Array.isArray(value) ? String(value[0] || '') : String(value || '')

async function storageUpload(bucket, path, file) {
  const bytes = await readFile(file.filepath)
  const response = await fetch(`${DB_URL()}/storage/v1/object/${bucket}/${path.split('/').map(encodeURIComponent).join('/')}`, {
    method: 'POST', headers: { apikey: SERVICE_KEY(), Authorization: `Bearer ${SERVICE_KEY()}`, 'Content-Type': file.mimetype || 'application/octet-stream', 'x-upsert': 'false' },
    body: bytes, signal: AbortSignal.timeout(60000),
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw Object.assign(new Error(data.message || data.error || 'Storage upload failed'), { status: response.status })
  return data
}

async function signedStorageUrl(bucket, path, expiresIn = 31536000) {
  const response = await fetch(`${DB_URL()}/storage/v1/object/sign/${bucket}/${path.split('/').map(encodeURIComponent).join('/')}`, {
    method: 'POST', headers: { apikey: SERVICE_KEY(), Authorization: `Bearer ${SERVICE_KEY()}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ expiresIn }), signal: AbortSignal.timeout(15000),
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw Object.assign(new Error(data.message || 'Unable to sign storage URL'), { status: response.status })
  return data.signedURL || data.signedUrl
}

async function rest(path, { method = 'GET', body, headers = {} } = {}) {
  if (!DB_URL() || !SERVICE_KEY()) throw Object.assign(new Error('Unified database is not configured'), { status: 503 })
  const response = await fetch(`${DB_URL()}/rest/v1/${path}`, {
    method,
    headers: {
      apikey: SERVICE_KEY(), Authorization: `Bearer ${SERVICE_KEY()}`, Accept: 'application/json',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000),
  })
  const raw = await response.text(); let data
  try { data = raw ? JSON.parse(raw) : null } catch { data = raw }
  if (!response.ok) {
    const error = new Error(response.status === 409 ? 'Data conflict' : 'Database request rejected')
    error.status = response.status >= 500 ? 502 : response.status
    error.internalMessage = data?.message || data?.error || raw
    throw error
  }
  return { data, count: response.headers.get('content-range') }
}

async function userFromToken(req) {
  const jwt = bearer(req)
  if (!jwt) throw Object.assign(new Error('Authorization required'), { status: 401 })
  const response = await fetch(`${DB_URL()}/auth/v1/user`, { headers: { apikey: ANON_KEY(), Authorization: `Bearer ${jwt}` }, signal: AbortSignal.timeout(12000) })
  if (!response.ok) throw Object.assign(new Error('Invalid or expired session'), { status: 401 })
  const auth = await response.json()
  const { data } = await rest(`api_profiles?id=eq.${encodeURIComponent(auth.id)}&select=*,api_roles(*)&limit=1`)
  const profile = data?.[0]
  if (!profile || profile.banned) throw Object.assign(new Error('Account unavailable'), { status: 403 })
  return { ...profile, jwt, auth }
}

function staff(profile, ownerOnly = false) {
  const allowed = ownerOnly ? profile.role === 'owner' : ['admin', 'owner'].includes(profile.role)
  if (!allowed) throw Object.assign(new Error(ownerOnly ? 'Owner access required' : 'Staff access required'), { status: 403 })
}

async function usernameLogin(req, res) {
  rateLimit(req, 'unified:login', 10, 15 * 60 * 1000)
  const username = clean(req.body?.username, 40), password = String(req.body?.password || '')
  if (!/^[A-Za-z0-9_.-]{3,40}$/.test(username) || password.length < 8 || password.length > 256) return send(res, 401, { error: 'Invalid credentials' })
  const { data } = await rest(`api_profiles?username=ilike.${encodeURIComponent(username)}&select=email,banned&limit=1`)
  if (!data?.[0] || data[0].banned) return send(res, 401, { error: 'Invalid credentials' })
  const response = await fetch(`${DB_URL()}/auth/v1/token?grant_type=password`, {
    method: 'POST', headers: { apikey: ANON_KEY(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: data[0].email, password }), signal: AbortSignal.timeout(15000),
  })
  const result = await response.json().catch(() => ({}))
  if (!response.ok || !result.access_token) return send(res, 401, { error: 'Invalid credentials' })
  return send(res, 200, { access_token: result.access_token, refresh_token: result.refresh_token, expires_in: result.expires_in })
}

async function keys(req, res) {
  const profile = await userFromToken(req)
  if (req.method === 'GET') {
    const { data } = await rest(`api_access_keys?owner_id=eq.${profile.id}&select=id,name,key_prefix,status,daily_limit,monthly_limit,daily_count,monthly_count,total_count,last_used_at,created_at&order=created_at.desc`)
    return send(res, 200, { data })
  }
  const id = ['DELETE', 'PATCH'].includes(req.method) ? safeUuid(req.query?.id, 'API key ID') : ''
  if (req.method === 'DELETE') {
    await rest(`api_access_keys?id=eq.${encodeURIComponent(id)}&owner_id=eq.${profile.id}`, { method: 'PATCH', body: { status: 'revoked', revoked_at: new Date().toISOString() } })
    return send(res, 200, { ok: true })
  }
  if (req.method === 'PATCH') {
    const raw = token('alzriss_')
    await rest(`api_access_keys?id=eq.${encodeURIComponent(id)}&owner_id=eq.${profile.id}`, { method: 'PATCH', body: { key_prefix: raw.slice(0, 14), key_hash: hash(raw), daily_count: 0, monthly_count: 0, daily_reset: new Date().toISOString().slice(0, 10), status: 'active' } })
    return send(res, 200, { ok: true, apiKey: raw })
  }
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' })
  const { data: active } = await rest(`api_access_keys?owner_id=eq.${profile.id}&status=eq.active&select=id`)
  const max = profile.api_roles?.max_keys
  if (max !== null && max !== undefined && active.length >= max) throw Object.assign(new Error(`Role ${profile.role} maksimal ${max} API key`), { status: 400 })
  if (profile.role === 'reseller') {
    const today = new Date().toISOString().slice(0, 10)
    const { data: daily } = await rest(`api_access_keys?owner_id=eq.${profile.id}&created_at=gte.${today}&select=id`)
    if (daily.length >= 3) throw Object.assign(new Error('Reseller maksimal membuat 3 API key per hari'), { status: 429 })
  }
  const raw = token('alzriss_')
  const { data } = await rest('api_access_keys', { method: 'POST', body: { owner_id: profile.id, name: clean(req.body?.name || 'API Key', 60), key_prefix: raw.slice(0, 14), key_hash: hash(raw), daily_limit: profile.role === 'basic' ? 1000 : 50000, monthly_limit: profile.role === 'basic' ? 20000 : 1000000 }, headers: { Prefer: 'return=representation' } })
  return send(res, 201, { ...data[0], apiKey: raw })
}

async function database(req, res, resource) {
  if (req.method !== 'GET') return send(res, 405, { error: 'Read-only endpoint' })
  const p = await userFromToken(req)
  const queries = {
    profile: `api_profiles?id=eq.${p.id}&select=id,email,username,avatar_url,role,premium_until,request_mode,online_at,created_at,api_roles(*)`,
    roles: 'api_roles?select=*&order=rank.asc',
    endpoints: 'api_endpoints?select=*&order=category.asc,name.asc',
    keys: `api_access_keys?owner_id=eq.${p.id}&select=id,name,key_prefix,status,daily_limit,monthly_limit,daily_count,monthly_count,total_count,last_used_at,created_at&order=created_at.desc`,
    plans: 'api_premium_plans?active=eq.true&select=*&order=price.asc',
    payments: `api_payments?user_id=eq.${p.id}&select=*,api_premium_plans(*)&order=created_at.desc`,
    plugins: `api_plugins?or=(status.eq.published,uploader_id.eq.${p.id})&select=*&order=created_at.desc`,
    notifications: `api_notifications?user_id=eq.${p.id}&select=*&order=created_at.desc&limit=100`,
    announcements: 'api_announcements?active=eq.true&select=*&order=created_at.desc',
    status: 'api_server_status?select=*&order=name.asc',
  }
  let query = queries[resource]
  if (resource === 'profiles') { staff(p); query = 'api_profiles?select=id,email,username,role,premium_until,request_mode,banned,online_at,created_at&order=created_at.desc' }
  if (!query) return send(res, 404, { error: 'Database resource not found' })
  const { data } = await rest(query)
  return send(res, 200, { data })
}

async function owner(req, res) {
  const p = await userFromToken(req), action = clean(req.query?.action, 50)
  if (req.method === 'GET') {
    staff(p)
    if (action === 'vapikeys') { const { data } = await rest('api_vapikeys?select=id,name,key_prefix,status,partner_name,expires_at,last_used_at,total_count,created_at&order=created_at.desc'); return send(res, 200, { data }) }
  }
  if (req.method === 'POST') {
    staff(p, true)
    if (action === 'settings') { await rest('api_settings?on_conflict=key', { method: 'POST', body: { key: clean(req.body?.key, 100), value: req.body?.value, updated_by: p.id, updated_at: new Date().toISOString() }, headers: { Prefer: 'resolution=merge-duplicates' } }); return send(res, 200, { ok: true }) }
    if (action === 'vapikeys') { const raw = token('vapikey_alzriss_'); const { data } = await rest('api_vapikeys', { method: 'POST', body: { name: clean(req.body?.name || 'Master key', 100), key_prefix: raw.slice(0, 20), key_hash: hash(raw), created_by: p.id }, headers: { Prefer: 'return=representation' } }); return send(res, 201, { ...data[0], vapikey: raw }) }
  }
  if (req.method === 'PATCH' && action === 'user') {
    staff(p)
    const targetId = safeUuid(req.body?.id, 'User ID')
    const nextRole = clean(req.body?.role, 30)
    if (!['basic', 'premium', 'reseller', 'admin', 'owner'].includes(nextRole)) return send(res, 400, { error: 'Invalid role' })
    const { data } = await rest(`api_profiles?id=eq.${encodeURIComponent(targetId)}&select=email,role&limit=1`), target = data?.[0]
    if (!target) return send(res, 404, { error: 'User not found' })
    if (target.email === OWNER_EMAIL) return send(res, 403, { error: 'Owner account is immutable' })
    if (p.role === 'admin' && nextRole === 'owner') return send(res, 403, { error: 'Only owner can assign owner' })
    await rest(`api_profiles?id=eq.${encodeURIComponent(targetId)}`, { method: 'PATCH', body: { role: nextRole, created_by: nextRole === 'reseller' ? p.id : null } })
    return send(res, 200, { ok: true })
  }
  return send(res, 400, { error: 'Unknown owner action' })
}

async function pluginUpload(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' })
  rateLimit(req, 'unified:plugin-upload', 5, 60 * 60 * 1000)
  const p = await userFromToken(req)
  staff(p, true)
  const [fields, files] = await formidable({ maxFileSize: 512 * 1024, maxFiles: 1, maxFields: 10, maxFieldsSize: 32 * 1024, allowEmptyFiles: false }).parse(req)
  const file = Array.isArray(files.file) ? files.file[0] : files.file
  if (!file) return send(res, 400, { error: 'File required' })
  const filename = clean(file.originalFilename || 'plugin', 180).replace(/[^\w.-]/g, '_')
  const ext = filename.split('.').pop()?.toLowerCase()
  if (!['zip', 'js', 'ts'].includes(ext)) return send(res, 400, { error: 'Only ZIP, JS, and TS' })
  const bytes = await readFile(file.filepath)
  const mime = String(file.mimetype || '').toLowerCase()
  const zipOk = ext === 'zip' && ['application/zip', 'application/x-zip-compressed'].includes(mime) && bytes[0] === 0x50 && bytes[1] === 0x4b
  const codeOk = ['js', 'ts'].includes(ext) && ['text/plain', 'text/javascript', 'application/javascript', 'application/typescript', 'text/typescript'].includes(mime) && !bytes.includes(0)
  if (!zipOk && !codeOk) return send(res, 400, { error: 'File signature or MIME type is invalid' })
  const name = formValue(fields.name).slice(0, 100)
  if (!name) return send(res, 400, { error: 'Plugin name required' })
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') + '-' + Date.now().toString(36)
  const storagePath = `${p.id}/${crypto.randomUUID()}/${filename}`
  await storageUpload('api-plugins', storagePath, file)
  try {
    const { data } = await rest('api_plugins', { method: 'POST', body: { uploader_id: p.id, name, slug, version: formValue(fields.version).slice(0, 30), author: formValue(fields.author).slice(0, 80), description: formValue(fields.description).slice(0, 2000), changelog: formValue(fields.changelog).slice(0, 5000), storage_path: storagePath, filename, file_size: file.size, status: ['admin', 'owner'].includes(p.role) ? 'published' : 'pending' }, headers: { Prefer: 'return=representation' } })
    return send(res, 201, { plugin: data[0] })
  } catch (error) {
    fetch(`${DB_URL()}/storage/v1/object/api-plugins/${storagePath.split('/').map(encodeURIComponent).join('/')}`, { method: 'DELETE', headers: { apikey: SERVICE_KEY(), Authorization: `Bearer ${SERVICE_KEY()}` } }).catch(() => {})
    throw error
  }
}

async function chatUpload(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' })
  rateLimit(req, 'unified:chat-upload', 20, 60 * 60 * 1000)
  const p = await userFromToken(req)
  const [, files] = await formidable({ maxFileSize: 10 * 1024 * 1024, maxFiles: 1, maxFields: 5, maxFieldsSize: 8 * 1024, allowEmptyFiles: false }).parse(req)
  const file = Array.isArray(files.file) ? files.file[0] : files.file
  if (!file) return send(res, 400, { error: 'File required' })
  const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'application/pdf', 'text/plain']
  const extensions = ['jpg', 'jpeg', 'png', 'webp', 'gif', 'pdf', 'txt']
  const ext = noSniffUpload(file, allowed, extensions)
  const bytes = await readFile(file.filepath)
  const signatures = {
    jpg: bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff,
    jpeg: bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff,
    png: bytes.subarray(0, 8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])),
    gif: ['GIF87a', 'GIF89a'].includes(bytes.subarray(0, 6).toString('ascii')),
    webp: bytes.subarray(0, 4).toString('ascii') === 'RIFF' && bytes.subarray(8, 12).toString('ascii') === 'WEBP',
    pdf: bytes.subarray(0, 5).toString('ascii') === '%PDF-',
    txt: !bytes.includes(0),
  }
  if (!signatures[ext]) return send(res, 400, { error: 'File signature does not match its extension' })
  const filename = clean(file.originalFilename || 'file', 180).replace(/[^\w.-]/g, '_')
  const storagePath = `${p.id}/${crypto.randomUUID()}/${filename}`
  await storageUpload('api-chat', storagePath, file)
  const signed = await signedStorageUrl('api-chat', storagePath)
  return send(res, 200, { url: signed ? `${DB_URL()}/storage/v1${signed}` : null, path: storagePath })
}

async function premium(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' })
  const p = await userFromToken(req)
  const planId = safeUuid(req.body?.planId, 'Plan ID')
  const { data } = await rest(`api_premium_plans?id=eq.${encodeURIComponent(planId)}&active=eq.true&select=*&limit=1`), plan = data?.[0]
  if (!plan) return send(res, 404, { error: 'Plan unavailable' })
  const created = await rest('api_payments', { method: 'POST', body: { user_id: p.id, plan_id: plan.id, amount: plan.price, status: 'pending' }, headers: { Prefer: 'return=representation' } })
  return send(res, 201, { payment: created.data[0] })
}

async function gateway(req, res, gatewayPath) {
  rateLimit(req, 'unified:gateway', 120, 60 * 1000)
  if (!/^[a-z0-9][a-z0-9/_-]{0,100}$/.test(gatewayPath) || gatewayPath.includes('..')) return send(res, 400, { success: false, error: 'Invalid gateway path' })
  const started = Date.now(), method = req.method
  let key = null, vapi = null, profile = null, endpoint = null, status = 500
  try {
    const raw = clean(req.headers['x-api-key'] || bearer(req), 1000), master = clean(req.headers['x-vapikey'], 1000)
    if (master) {
      const { data } = await rest(`api_vapikeys?key_hash=eq.${hash(master)}&status=eq.active&select=*&limit=1`); vapi = data?.[0]
      if (!vapi || (vapi.expires_at && new Date(vapi.expires_at) < new Date())) throw Object.assign(new Error('Invalid VAPIKEY'), { status: 401 })
    } else {
      if (!raw.startsWith('alzriss_')) throw Object.assign(new Error('API key required'), { status: 401 })
      const found = await rest(`api_access_keys?key_hash=eq.${hash(raw)}&status=eq.active&select=*&limit=1`); key = found.data?.[0]
      if (!key || (key.expires_at && new Date(key.expires_at) < new Date())) throw Object.assign(new Error('Invalid or expired API key'), { status: 401 })
      const profiles = await rest(`api_profiles?id=eq.${key.client_id || key.owner_id}&select=*,api_roles(*)&limit=1`); profile = profiles.data?.[0]
      if (!profile || profile.banned) throw Object.assign(new Error('Account unavailable'), { status: 403 })
      const today = new Date().toISOString().slice(0, 10), month = today.slice(0, 7) + '-01'
      const daily = key.daily_reset === today ? key.daily_count : 0, monthly = key.monthly_reset === month ? key.monthly_count : 0
      if (profile.request_mode !== 'unlimited' && (daily >= key.daily_limit || monthly >= key.monthly_limit)) throw Object.assign(new Error('Request limit exceeded'), { status: 429 })
      await rest(`api_access_keys?id=eq.${key.id}`, { method: 'PATCH', body: { daily_count: daily + 1, monthly_count: monthly + 1, total_count: Number(key.total_count) + 1, daily_reset: today, monthly_reset: month, last_used_at: new Date().toISOString() } })
    }
    const found = await rest(`api_endpoints?slug=eq.${encodeURIComponent(gatewayPath)}&method=eq.${method}&select=*&limit=1`); endpoint = found.data?.[0]
    if (!endpoint) throw Object.assign(new Error('Endpoint not found'), { status: 404 })
    if (endpoint.status !== 'active') throw Object.assign(new Error(`Endpoint ${endpoint.status}`), { status: 503 })
    if (endpoint.is_premium && !vapi && !profile?.api_roles?.can_premium) throw Object.assign(new Error('Premium access required'), { status: 403 })
    let result
    if (gatewayPath === 'tools/qrcode') {
      const value = clean(req.query?.text, 2001); if (!value || value.length > 2000) throw Object.assign(new Error('text query is required (max 2000)'), { status: 400 })
      result = { dataUrl: await QRCode.toDataURL(value, { width: 512, margin: 2 }) }
    } else if (gatewayPath === 'tools/shorturl') {
      const targetUrl = publicHttpUrl(req.body?.url)
      const id = crypto.randomUUID().replaceAll('-', '').slice(0, 8); await rest('api_short_urls', { method: 'POST', body: { id, target_url: targetUrl, owner_id: profile?.id || null } }); result = { id, shortUrl: `${APP_URL}/s/${id}` }
    } else if (gatewayPath === 'ai/chat' || gatewayPath === 'download/tiktok') throw Object.assign(new Error('Native provider is not configured for this endpoint'), { status: 503 })
    else result = { ready: true, path: gatewayPath }
    status = 200
    await rest(`api_endpoints?id=eq.${endpoint.id}`, { method: 'PATCH', body: { request_count: Number(endpoint.request_count) + 1 } })
    return send(res, 200, { success: true, data: result })
  } catch (error) {
    status = error.status || 400
    return send(res, status, { success: false, error: error.message || 'Gateway error' })
  } finally {
    try { await rest('api_requests', { method: 'POST', body: { key_id: key?.id, vapikey_id: vapi?.id, user_id: profile?.id, endpoint_id: endpoint?.id, path: gatewayPath, method, status_code: status, duration_ms: Date.now() - started, ip_hash: hash(req.headers['x-forwarded-for'] || ''), user_agent: clean(req.headers['user-agent'], 400) } }) } catch {}
  }
}

export default async function handler(req, res) {
  const path = pathOf(req)
  securityHeaders(res)
  configureCors(req, res, path)
  if (req.method === 'OPTIONS') return send(res, 204, null)
  try {
    if (!/^[A-Za-z0-9_./-]{0,180}$/.test(path) || path.includes('..')) throw Object.assign(new Error('Invalid API path'), { status: 400 })
    rateLimit(req, 'unified:all', 600, 60 * 1000)
    if (!path.startsWith('gateway/')) enforceSameOrigin(req)
    req.body = await parseJsonBody(req)
    if (path === 'health') return send(res, 200, { ok: true, service: 'Jadibot Unified API', version: '1.0.0', database: 'Supabase', website: APP_URL })
    if (path.startsWith('short/')) {
      rateLimit(req, 'unified:short', 120, 60 * 1000)
      const id = safeId(path.slice(6), 'Short URL ID', 6, 32)
      const { data } = await rest(`api_short_urls?id=eq.${encodeURIComponent(id)}&select=target_url,clicks&limit=1`)
      if (!data?.[0]) return send(res, 404, { error: 'Short URL not found' })
      const redirectTarget = publicHttpUrl(data[0].target_url)
      rest(`api_short_urls?id=eq.${encodeURIComponent(id)}`, { method: 'PATCH', body: { clicks: Number(data[0].clicks) + 1 } }).catch(() => {})
      res.setHeader('Cache-Control', 'no-store')
      return res.redirect(307, redirectTarget)
    }
    if (path === 'auth/username-login' && req.method === 'POST') return usernameLogin(req, res)
    if (path === 'keys') return keys(req, res)
    if (path === 'owner') return owner(req, res)
    if (path === 'plugins') return pluginUpload(req, res)
    if (path === 'chat/upload') return chatUpload(req, res)
    if (path === 'premium') return premium(req, res)
    if (path.startsWith('database/')) return database(req, res, path.slice(9))
    if (path.startsWith('gateway/')) return gateway(req, res, path.slice(8))
    return send(res, 404, { error: 'Unified endpoint not found', docs: `${APP_URL}/api/v1/health` })
  } catch (error) {
    if (error?.retryAfter) res.setHeader('Retry-After', String(error.retryAfter))
    if (!error.status || error.status >= 500) console.error('[UNIFIED API]', error)
    return send(res, error.status || 500, { error: error.status && error.status < 500 ? error.message : 'Unified API request failed' })
  }
}
