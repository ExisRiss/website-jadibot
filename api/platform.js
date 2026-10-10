import crypto from 'node:crypto'
import {
  assertBodySize,
  enforceSameOrigin,
  resolvedPublicHttpUrl,
  rateLimit,
  safeNumericId,
  safeUuid,
  securityHeaders,
} from './_security.js'

const FIXED_OWNER = 'akunindo2011264@gmail.com'
const VALID_ROLES = new Set(['user', 'admin', 'partner', 'owner', 'developer'])
const DATA_URL = () => String(process.env.UMI_DATA_SUPABASE_URL || '').replace(/\/+$/, '')
const DATA_KEY = () => String(process.env.UMI_DATA_SERVICE_ROLE_KEY || '')
const AUTH_URL = () => String(process.env.SUPABASE_URL || 'https://tlcvkksfgdyeiypzcwdj.supabase.co').replace(/\/+$/, '')
const AUTH_ANON = () => String(process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_PUBLISHABLE_KEY || 'sb_publishable_ebpebtzCNxvsKWb0xtgX_A_ClzPlhob')
const AUTH_ADMIN = () => String(process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || '')
const BOT_ORIGIN = () => String(process.env.UMI_API_ORIGIN || 'http://ikyydenia-node.nebuladnezar.web.id:2144').replace(/\/+$/, '')
const usernameCache = new Map()
const USERNAME_CACHE_TTL = 10 * 60 * 1000

const send = (res, status, data) => {
  securityHeaders(res)
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  return res.status(status).json(data)
}
const text = (value, max = 500) => String(value ?? '').trim().slice(0, max)
const email = value => text(value, 320).toLowerCase()
const fixedRoles = value => email(value) === FIXED_OWNER ? ['owner', 'developer'] : null

function routePath(req) {
  const value = req.query?.path
  return (Array.isArray(value) ? value.join('/') : String(value || '')).replace(/^\/+|\/+$/g, '')
}

function bearer(req) {
  return text(req.headers.authorization, 10000).replace(/^Bearer\s+/i, '')
}

async function authUser(req) {
  const token = bearer(req)
  if (!token) throw Object.assign(new Error('Silakan masuk terlebih dahulu.'), { status: 401 })
  const response = await fetch(`${AUTH_URL()}/auth/v1/user`, {
    headers: { Authorization: `Bearer ${token}`, apikey: AUTH_ANON() },
    signal: AbortSignal.timeout(12000),
  })
  if (!response.ok) throw Object.assign(new Error('Sesi login tidak valid atau sudah berakhir.'), { status: 401 })
  const data = await response.json()
  const username = text(data.user_metadata?.username || data.user_metadata?.name || '', 40)
  return { id: data.id, email: email(data.email), username, token }
}

async function dataRequest(path, { method = 'GET', body, headers = {} } = {}) {
  if (!DATA_URL() || !DATA_KEY()) throw Object.assign(new Error('Database platform belum dikonfigurasi.'), { status: 503 })
  const response = await fetch(`${DATA_URL()}/rest/v1/${path}`, {
    method,
    headers: {
      apikey: DATA_KEY(),
      Authorization: `Bearer ${DATA_KEY()}`,
      Accept: 'application/json',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  })
  const raw = await response.text()
  let data
  try { data = raw ? JSON.parse(raw) : null } catch { data = raw }
  if (!response.ok) {
    const error = new Error(response.status === 409 ? 'Data bertentangan dengan data yang sudah ada.' : 'Permintaan database ditolak.')
    error.status = response.status >= 500 ? 502 : response.status
    error.internalMessage = data?.message || data?.error || raw
    throw error
  }
  return data
}

async function ensureProfile(user) {
  const locked = user.email === FIXED_OWNER
  const forced = fixedRoles(user.email)
  const rows = await dataRequest(`platform_profiles?auth_id=eq.${encodeURIComponent(user.id)}&select=*`)
  let profile = rows?.[0]
  if (!profile) {
    const created = await dataRequest('platform_profiles', {
      method: 'POST',
      body: { auth_id: user.id, email: user.email, username: user.username || '', roles: forced || ['user'], locked, banned: false },
      headers: { Prefer: 'return=representation' },
    })
    profile = created?.[0]
  } else {
    const resolvedUsername = user.username || profile.username || ''
    const lastSeen = new Date(profile.last_seen_at || 0).getTime()
    const stale = !Number.isFinite(lastSeen) || Date.now() - lastSeen > 5 * 60 * 1000
    const ownerMismatch = Boolean(forced) && (profile.email !== FIXED_OWNER || !profile.locked || profile.banned || !forced.every(role => profile.roles?.includes(role)))
    if (stale || resolvedUsername !== profile.username || ownerMismatch) {
      const patch = { last_seen_at: new Date().toISOString(), username: resolvedUsername }
      if (forced) Object.assign(patch, { roles: forced, locked: true, banned: false, email: FIXED_OWNER })
      const updated = await dataRequest(`platform_profiles?auth_id=eq.${encodeURIComponent(user.id)}`, {
        method: 'PATCH', body: patch, headers: { Prefer: 'return=representation' },
      })
      profile = updated?.[0] || { ...profile, ...patch }
    }
  }
  if (profile?.banned && !forced) throw Object.assign(new Error('Akun ini diblokir dari platform.'), { status: 403 })
  return profile
}

function requireOwner(profile) {
  if (!profile?.roles?.includes('owner')) throw Object.assign(new Error('Hanya owner platform yang diizinkan.'), { status: 403 })
}

async function audit(user, action, target = '', metadata = {}) {
  try {
    await dataRequest('platform_audit_logs', { method: 'POST', body: { actor_id: user.id, actor_email: user.email, action, target: text(target, 500), metadata } })
  } catch {}
}

async function authAdmin(path, { method = 'GET', body } = {}) {
  if (!AUTH_ADMIN()) throw Object.assign(new Error('Admin Auth belum dikonfigurasi.'), { status: 503 })
  const response = await fetch(`${AUTH_URL()}/auth/v1/admin/${path}`, {
    method,
    headers: { apikey: AUTH_ADMIN(), Authorization: `Bearer ${AUTH_ADMIN()}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(15000),
  })
  const raw = await response.text(); let data
  try { data = raw ? JSON.parse(raw) : {} } catch { data = {} }
  if (!response.ok) throw Object.assign(new Error(data.msg || data.message || data.error_description || 'Operasi akun gagal.'), { status: response.status })
  return data
}

async function botRequest(path, user, { method = 'GET', body, headers = {} } = {}) {
  const response = await fetch(`${BOT_ORIGIN()}/api/${path}`, {
    method,
    headers: { Authorization: `Bearer ${user.token}`, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(55000),
  })
  const raw = await response.text(); let data
  try { data = raw ? JSON.parse(raw) : {} } catch { data = { error: raw } }
  if (!response.ok) throw Object.assign(new Error(data.error || 'Backend bot gagal merespons.'), { status: response.status })
  return data
}

function normalizedRoles(input, targetEmail) {
  if (targetEmail === FIXED_OWNER) return ['owner', 'developer']
  const roles = [...new Set((Array.isArray(input) ? input : []).map(x => text(x, 20).toLowerCase()).filter(x => VALID_ROLES.has(x)))]
  return roles.length ? roles : ['user']
}

function pluginSummary(row, includeCode = false) {
  const output = { id: row.id, slug: row.slug, filename: row.filename, description: row.description, active: row.active, uploader_email: row.uploader_email, created_at: row.created_at, updated_at: row.updated_at }
  if (includeCode) output.code = row.code
  return output
}

export default async function handler(req, res) {
  try {
    securityHeaders(res)
    if (!['GET', 'POST', 'PATCH', 'DELETE'].includes(req.method)) return send(res, 405, { error: 'Metode tidak diizinkan.' })
    assertBodySize(req, 768 * 1024)
    rateLimit(req, 'platform:all', 300, 60 * 1000)
    enforceSameOrigin(req)
    const path = routePath(req)
    if (!/^[A-Za-z0-9_./-]{0,180}$/.test(path) || path.includes('..')) return send(res, 400, { error: 'Path tidak valid.' })
    if (path === 'health' && req.method === 'GET') {
      await dataRequest('platform_profiles?select=auth_id&limit=1')
      return send(res, 200, { ok: true, service: 'usanagi-umi-platform', database: 'connected', time: new Date().toISOString() })
    }
    if (path === 'auth/login' && req.method === 'POST') {
      rateLimit(req, 'platform:login', 10, 15 * 60 * 1000)
      const identifier = text(req.body?.identifier, 320)
      const password = String(req.body?.password || '')
      if (!identifier || !password || password.length > 256) return send(res, 400, { error: 'Username/email atau password salah.' })
      let loginEmail = email(identifier)
      let knownProfile = null
      if (!identifier.includes('@')) {
        if (!/^[A-Za-z0-9_.-]{3,40}$/.test(identifier)) return send(res, 400, { error: 'Username/email atau password salah.' })
        const cleanUsername = identifier
        const cacheKey = cleanUsername.toLowerCase()
        const cached = usernameCache.get(cacheKey)
        if (cached && cached.expires > Date.now()) {
          loginEmail = cached.email || ''
        } else {
          const rows = await dataRequest(`platform_profiles?username=ilike.${encodeURIComponent(cleanUsername)}&select=*&limit=1`)
          knownProfile = rows?.[0] || null
          loginEmail = knownProfile?.email || ''
          if (knownProfile) usernameCache.set(cacheKey, { email: knownProfile.email, expires: Date.now() + USERNAME_CACHE_TTL })
        }
      }
      if (!loginEmail) return send(res, 400, { error: 'Username/email atau password salah.' })
      const profilePromise = knownProfile ? Promise.resolve([knownProfile]) : dataRequest(`platform_profiles?email=eq.${encodeURIComponent(loginEmail)}&select=*&limit=1`).catch(() => [])
      const response = await fetch(`${AUTH_URL()}/auth/v1/token?grant_type=password`, {
        method: 'POST',
        headers: { apikey: AUTH_ANON(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: loginEmail, password }),
        signal: AbortSignal.timeout(15000),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok || !data.access_token || !data.refresh_token) return send(res, 400, { error: 'Username/email atau password salah.' })
      knownProfile = knownProfile || (await profilePromise)?.[0] || null
      const loginUser = {
        id: data.user?.id,
        email: email(data.user?.email || loginEmail),
        username: text(data.user?.user_metadata?.username || data.user?.user_metadata?.name || '', 40),
        token: data.access_token,
      }
      const profile = knownProfile || await ensureProfile(loginUser)
      if (profile?.banned && loginUser.email !== FIXED_OWNER) return send(res, 403, { error: 'Akun ini diblokir dari platform.' })
      return send(res, 200, {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_in: data.expires_in,
        user: { id: loginUser.id, email: loginUser.email, username: profile.username || loginUser.username, roles: profile.roles, locked: profile.locked },
      })
    }
    if (path === 'auth/register' && req.method === 'POST') {
      rateLimit(req, 'platform:register', 5, 60 * 60 * 1000)
      const username = text(req.body?.username, 40)
      const registerEmail = email(req.body?.email)
      const password = String(req.body?.password || '')
      if (!/^[A-Za-z0-9_.-]{3,40}$/.test(username)) return send(res, 400, { error: 'Username harus 3–40 karakter dan hanya boleh berisi huruf, angka, titik, garis bawah, atau tanda minus.' })
      const gmailLocal = registerEmail.endsWith('@gmail.com') ? registerEmail.slice(0, -10) : ''
      if (!gmailLocal || !/^[a-z0-9]+(?:\.?[a-z0-9]+)*$/.test(gmailLocal)) return send(res, 400, { error: 'Gunakan alamat Gmail yang valid, contoh nama@gmail.com.' })
      if (password.length < 8 || password.length > 128) return send(res, 400, { error: 'Password harus 8–128 karakter.' })
      const duplicateUsername = await dataRequest(`platform_profiles?username=ilike.${encodeURIComponent(username.replace(/[*,()]/g, ''))}&select=auth_id&limit=1`)
      if (duplicateUsername?.length) return send(res, 409, { error: 'Username sudah digunakan.' })
      let created
      try {
        created = await authAdmin('users', { method: 'POST', body: { email: registerEmail, password, email_confirm: true, user_metadata: { username } } })
      } catch (error) {
        const message = String(error.message || '').toLowerCase()
        if (message.includes('already') || message.includes('registered') || error.status === 422) return send(res, 409, { error: 'Email sudah terdaftar. Silakan masuk.' })
        throw error
      }
      try {
        await dataRequest('platform_profiles', {
          method: 'POST',
          body: { auth_id: created.id, email: registerEmail, username, roles: fixedRoles(registerEmail) || ['user'], locked: registerEmail === FIXED_OWNER, banned: false },
          headers: { Prefer: 'return=minimal' },
        })
      } catch (error) {
        await authAdmin(`users/${created.id}`, { method: 'DELETE' }).catch(() => {})
        throw error
      }
      return send(res, 201, { ok: true, message: 'Akun berhasil dibuat. Silakan masuk.' })
    }
    const user = await authUser(req)
    const profile = await ensureProfile(user)

    if (path === 'me' && req.method === 'GET') return send(res, 200, { user: { id: user.id, email: user.email, username: profile.username || user.username || '', roles: profile.roles, locked: profile.locked } })

    if (path === 'chat' && req.method === 'GET') {
      const limit = Math.max(1, Math.min(200, Number(req.query.limit) || 100))
      const rows = await dataRequest(`global_messages?select=id,auth_id,roles,body,created_at&order=created_at.desc&limit=${limit}`)
      const profiles = await dataRequest('platform_profiles?select=auth_id,username,roles&limit=1000')
      const profileMap = new Map((profiles || []).map(item => [item.auth_id, item]))
      return send(res, 200, { messages: (rows || []).reverse().map(message => {
        const current = profileMap.get(message.auth_id)
        return { ...message, display_name: current?.username || `User ${String(message.auth_id).slice(0, 8)}`, roles: current?.roles || message.roles }
      }) })
    }
    if (path === 'chat' && req.method === 'POST') {
      rateLimit(req, `platform:chat:${user.id}`, 30, 60 * 1000)
      const body = text(req.body?.body, 1000)
      if (!body) return send(res, 400, { error: 'Pesan tidak boleh kosong.' })
      const recent = await dataRequest(`global_messages?auth_id=eq.${encodeURIComponent(user.id)}&select=created_at&order=created_at.desc&limit=1`)
      if (recent?.[0] && Date.now() - new Date(recent[0].created_at).getTime() < 1500) return send(res, 429, { error: 'Tunggu sebentar sebelum mengirim pesan lagi.' })
      const inserted = await dataRequest('global_messages', { method: 'POST', body: { auth_id: user.id, email: user.email, roles: profile.roles, body }, headers: { Prefer: 'return=representation' } })
      const saved = inserted?.[0]
      return send(res, 201, { message: saved ? { id: saved.id, auth_id: saved.auth_id, display_name: profile.username || `User ${String(user.id).slice(0, 8)}`, roles: profile.roles, body: saved.body, created_at: saved.created_at } : null })
    }
    if (path.startsWith('chat/') && req.method === 'DELETE') {
      if (!profile.roles.some(r => ['owner', 'admin'].includes(r))) return send(res, 403, { error: 'Role tidak diizinkan menghapus pesan.' })
      const id = safeNumericId(path.split('/')[1], 'ID pesan')
      await dataRequest(`global_messages?id=eq.${encodeURIComponent(id)}`, { method: 'DELETE' })
      await audit(user, 'chat.delete', id)
      return send(res, 200, { ok: true })
    }

    if (path === 'admin/users' && req.method === 'GET') {
      requireOwner(profile)
      const auth = await authAdmin('users?page=1&per_page=1000')
      let profiles = await dataRequest('platform_profiles?select=*&order=created_at.desc&limit=1000')
      let pmap = new Map((profiles || []).map(x => [x.auth_id, x]))
      const missing = (auth.users || []).filter(item => !pmap.has(item.id)).map(item => {
        const itemEmail = email(item.email)
        return { auth_id: item.id, email: itemEmail, username: text(item.user_metadata?.username || item.user_metadata?.name || '', 40), roles: fixedRoles(itemEmail) || ['user'], locked: itemEmail === FIXED_OWNER, banned: false }
      })
      if (missing.length) {
        const added = await dataRequest('platform_profiles', { method: 'POST', body: missing, headers: { Prefer: 'resolution=merge-duplicates,return=representation' } })
        profiles = [...(profiles || []), ...(added || [])]
        pmap = new Map(profiles.map(x => [x.auth_id, x]))
      }
      let sessions = []
      try { sessions = (await botRequest('sessions?all=1', user)).sessions || [] } catch {}
      return send(res, 200, {
        users: (auth.users || []).map(item => {
          const p = pmap.get(item.id)
          const itemEmail = email(item.email)
          return { id: item.id, email: itemEmail, username: p?.username || text(item.user_metadata?.username || item.user_metadata?.name || '', 40), roles: fixedRoles(itemEmail) || p?.roles || ['user'], locked: itemEmail === FIXED_OWNER || Boolean(p?.locked), banned: Boolean(p?.banned), created_at: item.created_at, last_sign_in_at: item.last_sign_in_at, sessions: sessions.filter(s => s.userId === item.id) }
        }),
        totals: { users: (auth.users || []).length, sessions: sessions.length, online: sessions.filter(s => s.status === 'connected').length, offline: sessions.filter(s => s.status !== 'connected').length },
      })
    }
    if (path === 'admin/users' && req.method === 'POST') {
      requireOwner(profile)
      const targetEmail = email(req.body?.email)
      const username = text(req.body?.username, 40)
      const password = String(req.body?.password || '')
      if (!/^\S+@\S+\.\S+$/.test(targetEmail) || password.length < 8 || password.length > 128 || !/^[A-Za-z0-9_.-]{3,40}$/.test(username)) return send(res, 400, { error: 'Username valid, email valid, dan password 8–128 karakter diperlukan.' })
      const created = await authAdmin('users', { method: 'POST', body: { email: targetEmail, password, email_confirm: true, user_metadata: { username } } })
      const roles = normalizedRoles(req.body?.roles, targetEmail)
      await dataRequest('platform_profiles', { method: 'POST', body: { auth_id: created.id, email: targetEmail, username, roles, locked: targetEmail === FIXED_OWNER, banned: false }, headers: { Prefer: 'resolution=merge-duplicates,return=representation' } })
      await audit(user, 'account.create', created.id, { email: targetEmail, username, roles })
      return send(res, 201, { user: { id: created.id, email: targetEmail, username, roles } })
    }
    if (path.startsWith('admin/users/') && req.method === 'DELETE') {
      requireOwner(profile)
      const id = safeUuid(path.split('/')[2], 'ID akun')
      const rows = await dataRequest(`platform_profiles?auth_id=eq.${encodeURIComponent(id)}&select=*`)
      if (rows?.[0]?.email === FIXED_OWNER || id === user.id) return send(res, 403, { error: 'Akun owner utama dikunci dan tidak dapat dihapus.' })
      await authAdmin(`users/${encodeURIComponent(id)}`, { method: 'DELETE' })
      await dataRequest(`platform_profiles?auth_id=eq.${encodeURIComponent(id)}`, { method: 'DELETE' })
      await audit(user, 'account.delete', id, { email: rows?.[0]?.email })
      return send(res, 200, { ok: true })
    }
    if (/^admin\/users\/[^/]+\/roles$/.test(path) && req.method === 'PATCH') {
      requireOwner(profile)
      const id = safeUuid(path.split('/')[2], 'ID akun')
      const rows = await dataRequest(`platform_profiles?auth_id=eq.${encodeURIComponent(id)}&select=*`)
      const target = rows?.[0]
      if (!target) return send(res, 404, { error: 'Profil akun tidak ditemukan.' })
      if (target.email === FIXED_OWNER) return send(res, 403, { error: 'Role owner utama dikunci.' })
      const roles = normalizedRoles(req.body?.roles, target.email)
      const updated = await dataRequest(`platform_profiles?auth_id=eq.${encodeURIComponent(id)}`, { method: 'PATCH', body: { roles, updated_at: new Date().toISOString() }, headers: { Prefer: 'return=representation' } })
      await audit(user, 'account.roles', id, { email: target.email, roles })
      return send(res, 200, { profile: updated?.[0] })
    }
    if (/^admin\/users\/[^/]+\/ban$/.test(path) && req.method === 'PATCH') {
      requireOwner(profile)
      const id = safeUuid(path.split('/')[2], 'ID akun')
      const rows = await dataRequest(`platform_profiles?auth_id=eq.${encodeURIComponent(id)}&select=*`)
      const target = rows?.[0]
      if (!target) return send(res, 404, { error: 'Profil akun tidak ditemukan.' })
      if (target.email === FIXED_OWNER) return send(res, 403, { error: 'Owner utama tidak dapat diblokir.' })
      const banned = Boolean(req.body?.banned)
      await authAdmin(`users/${encodeURIComponent(id)}`, { method: 'PUT', body: { ban_duration: banned ? '876000h' : 'none' } })
      await dataRequest(`platform_profiles?auth_id=eq.${encodeURIComponent(id)}`, { method: 'PATCH', body: { banned, updated_at: new Date().toISOString() } })
      await audit(user, banned ? 'account.ban' : 'account.unban', id, { email: target.email })
      return send(res, 200, { ok: true, banned })
    }

    if (path === 'plugins' && req.method === 'GET') {
      const rows = await dataRequest(`plugin_catalog?select=*&active=eq.true&order=created_at.desc&limit=200`)
      return send(res, 200, { plugins: (rows || []).map(row => pluginSummary(row, false)) })
    }
    if (path === 'plugins' && req.method === 'POST') {
      requireOwner(profile)
      rateLimit(req, `platform:plugin-upload:${user.id}`, 10, 60 * 60 * 1000)
      const filename = text(req.body?.filename, 100).replace(/[^a-zA-Z0-9_.-]/g, '-')
      const code = String(req.body?.code || '')
      const slug = text(req.body?.slug || filename.replace(/\.js$/i, ''), 64).toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^-+|-+$/g, '')
      if (!filename.endsWith('.js') || !/^[a-z0-9][a-z0-9_-]{1,63}$/.test(slug)) return send(res, 400, { error: 'Nama plugin atau slug tidak valid.' })
      if (!code || Buffer.byteLength(code) > 524288 || code.includes('\0')) return send(res, 400, { error: 'File plugin kosong atau melebihi 512 KB.' })
      const blocked = [
        /(?:node:)?child_process/i,
        /process\.env/i,
        /fs(?:\/promises)?['"]?\s*\)?\s*\.\s*(?:rm|unlink|rmdir)/i,
        /\beval\s*\(/i,
        /new\s+Function\s*\(/i,
        /(?:node:)?vm(?:['"]|\b)/i,
        /worker_threads/i,
      ]
      const violations = blocked.filter(rx => rx.test(code)).map(rx => rx.source)
      if (violations.length) return send(res, 400, { error: 'Plugin mengandung operasi berisiko tinggi dan ditolak.', violations })
      const inserted = await dataRequest('plugin_catalog', { method: 'POST', body: { slug, filename, description: text(req.body?.description, 1000), code, uploader_id: user.id, uploader_email: user.email, active: true }, headers: { Prefer: 'return=representation' } })
      await audit(user, 'plugin.upload', inserted?.[0]?.id, { slug, filename, security_scan: 'passed' })
      return send(res, 201, { plugin: pluginSummary(inserted?.[0], false), warnings: [] })
    }
    if (/^plugins\/[^/]+$/.test(path) && req.method === 'GET') {
      const id = safeUuid(path.split('/')[1], 'ID plugin')
      const rows = await dataRequest(`plugin_catalog?id=eq.${encodeURIComponent(id)}&select=*`)
      if (!rows?.[0]) return send(res, 404, { error: 'Plugin tidak ditemukan.' })
      return send(res, 200, { plugin: pluginSummary(rows[0], true) })
    }
    if (/^plugins\/[^/]+$/.test(path) && req.method === 'DELETE') {
      requireOwner(profile)
      const id = safeUuid(path.split('/')[1], 'ID plugin')
      await dataRequest(`plugin_catalog?id=eq.${encodeURIComponent(id)}`, { method: 'PATCH', body: { active: false, updated_at: new Date().toISOString() } })
      await audit(user, 'plugin.disable', id)
      return send(res, 200, { ok: true })
    }
    if (/^plugins\/[^/]+\/install$/.test(path) && req.method === 'POST') {
      const id = safeUuid(path.split('/')[1], 'ID plugin')
      const sessionId = text(req.body?.session_id, 20).replace(/\D/g, '')
      const rows = await dataRequest(`plugin_catalog?id=eq.${encodeURIComponent(id)}&active=eq.true&select=*`)
      if (!rows?.[0]) return send(res, 404, { error: 'Plugin tidak ditemukan.' })
      const plugin = rows[0]
      const installBody = { session_id: sessionId, filename: plugin.filename, code: plugin.code, catalog_id: plugin.id }
      const timestamp = String(Date.now())
      const digest = crypto.createHash('sha256').update(JSON.stringify(installBody)).digest('hex')
      const privateKey = String(process.env.UMI_PLUGIN_SIGNING_PRIVATE_KEY || '')
      if (!privateKey) throw Object.assign(new Error('Penandatanganan plugin belum dikonfigurasi.'), { status: 503 })
      const signature = crypto.sign(null, Buffer.from(`${timestamp}.${digest}`), privateKey).toString('base64')
      const result = await botRequest('plugin/install', user, { method: 'POST', body: installBody, headers: { 'X-Umi-Timestamp': timestamp, 'X-Umi-Signature': signature } })
      await dataRequest('plugin_installs', { method: 'POST', body: { plugin_id: plugin.id, auth_id: user.id, session_id: sessionId, status: 'installed', installed_at: new Date().toISOString(), updated_at: new Date().toISOString() }, headers: { Prefer: 'resolution=merge-duplicates' } })
      await audit(user, 'plugin.install', id, { session_id: sessionId })
      return send(res, 200, { ok: true, result })
    }

    if (path === 'media/sign' && req.method === 'POST') {
      rateLimit(req, `platform:media-sign:${user.id}`, 20, 60 * 60 * 1000)
      const sessionId = text(req.body?.session_id, 20).replace(/\D/g, '')
      const kind = text(req.body?.kind, 30)
      const mime = text(req.body?.mime_type, 100).toLowerCase()
      const extMap = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif', 'video/mp4': 'mp4', 'video/webm': 'webm', 'audio/mpeg': 'mp3', 'audio/mp4': 'm4a', 'audio/ogg': 'ogg', 'audio/opus': 'opus' }
      const expectedType = kind === 'menu_audio' ? 'audio/' : kind === 'menu_video' ? 'video/' : 'image/'
      if (!/^\d{7,15}$/.test(sessionId) || !['logo','menu_banner','menu_video','menu_audio','welcome_image','goodbye_image','thumbnail'].includes(kind) || !extMap[mime] || !mime.startsWith(expectedType)) return send(res, 400, { error: 'Data media tidak valid.' })
      await botRequest(`session/status?session_id=${encodeURIComponent(sessionId)}`, user)
      const objectPath = `${user.id}/${sessionId}/${kind}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}.${extMap[mime]}`
      const response = await fetch(`${DATA_URL()}/storage/v1/object/upload/sign/umi-media/${objectPath}`, { method: 'POST', headers: { apikey: DATA_KEY(), Authorization: `Bearer ${DATA_KEY()}`, 'Content-Type': 'application/json', 'x-upsert': 'true' }, body: '{}', signal: AbortSignal.timeout(15000) })
      const signed = await response.json()
      if (!response.ok) throw Object.assign(new Error(signed.message || 'Gagal membuat izin upload.'), { status: response.status })
      const signedUrl = /^https?:\/\//i.test(String(signed.url || ''))
        ? String(signed.url)
        : `${DATA_URL()}/storage/v1${String(signed.url || '').startsWith('/') ? '' : '/'}${signed.url}`
      return send(res, 200, { path: objectPath, token: new URL(signedUrl).searchParams.get('token'), signed_url: signedUrl })
    }
    if (path === 'media/apply' && req.method === 'POST') {
      const sessionId = text(req.body?.session_id, 20).replace(/\D/g, '')
      const kind = text(req.body?.kind, 30)
      let sourceUrl = text(req.body?.url, 2000)
      const storagePath = text(req.body?.storage_path, 1000)
      if (!/^\d{7,15}$/.test(sessionId)) return send(res, 400, { error: 'Session tidak valid.' })
      if (storagePath) {
        const expectedPrefix = `${user.id}/${sessionId}/`
        if (!storagePath.startsWith(expectedPrefix) || storagePath.includes('..') || !/^[A-Za-z0-9_./-]+$/.test(storagePath)) return send(res, 403, { error: 'Path media tidak diizinkan.' })
        sourceUrl = `${DATA_URL()}/storage/v1/object/public/umi-media/${storagePath.split('/').map(encodeURIComponent).join('/')}`
      }
      try { sourceUrl = await resolvedPublicHttpUrl(sourceUrl) } catch (error) { return send(res, error.status || 400, { error: error.message }) }
      if (!['logo','menu_banner','menu_video','menu_audio','welcome_image','goodbye_image','thumbnail'].includes(kind)) return send(res, 400, { error: 'Jenis media tidak valid.' })
      const sizeBytes = Math.max(0, Number(req.body?.size_bytes) || 0)
      const maxBytes = ['menu_video'].includes(kind) ? 15 * 1024 * 1024 : 8 * 1024 * 1024
      if (storagePath && (!Number.isFinite(sizeBytes) || sizeBytes < 1 || sizeBytes > maxBytes)) return send(res, 400, { error: 'Ukuran media tidak valid atau terlalu besar.' })
      const result = await botRequest('media/apply', user, { method: 'POST', body: { session_id: sessionId, kind, url: sourceUrl } })
      const mediaAsset = { auth_id: user.id, session_id: sessionId, kind, storage_path: storagePath || null, source_url: sourceUrl, mime_type: text(req.body?.mime_type, 100) || null, size_bytes: sizeBytes }
      try {
        await dataRequest('media_assets', { method: 'POST', body: mediaAsset })
      } catch (error) {
        // Existing installations may still have the older media_assets CHECK
        // constraint until the supplied SQL migration is run. The bot setting
        // and audit entry remain correct; retain the asset history compatibly.
        if (kind !== 'goodbye_image') throw error
        await dataRequest('media_assets', { method: 'POST', body: { ...mediaAsset, kind: 'welcome_image' } })
      }
      await audit(user, 'media.apply', sessionId, { kind, source_url: sourceUrl })
      return send(res, 200, { ok: true, url: sourceUrl, result })
    }

    if (path === 'audit' && req.method === 'GET') {
      requireOwner(profile)
      const rows = await dataRequest('platform_audit_logs?select=*&order=created_at.desc&limit=200')
      return send(res, 200, { logs: rows || [] })
    }

    return send(res, 404, { error: 'Endpoint platform tidak ditemukan.' })
  } catch (error) {
    const status = Number(error?.status) || 500
    if (error?.retryAfter) res.setHeader('Retry-After', String(error.retryAfter))
    if (status >= 500) console.error('[PLATFORM]', error?.message)
    return send(res, status, { error: status >= 500 ? 'Layanan platform sedang bermasalah.' : error.message })
  }
}
