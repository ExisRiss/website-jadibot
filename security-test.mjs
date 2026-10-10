import assert from 'node:assert/strict'
const BASE='https://website-jadibot-by-alzriss.vercel.app'
const results=[]
async function request(name,path,options={},expect={}){
  const started=Date.now();let response,text,error
  try{response=await fetch(BASE+path,{redirect:'manual',signal:AbortSignal.timeout(15000),...options});text=await response.text()}catch(e){error=e.message;text=''}
  const headers=response?Object.fromEntries(response.headers):{}
  const row={name,path,status:response?.status||0,ms:Date.now()-started,body:text.slice(0,300),headers,error,pass:true,notes:''}
  if(expect.status&&!([].concat(expect.status).includes(row.status))){row.pass=false;row.notes+=`expected status ${expect.status}; `}
  if(expect.notContains&&text.toLowerCase().includes(expect.notContains.toLowerCase())){row.pass=false;row.notes+=`leaked/reflected ${expect.notContains}; `}
  if(expect.contains&&!text.includes(expect.contains)){row.pass=false;row.notes+=`missing expected response; `}
  results.push(row);return row
}

// Baseline + HTTP security headers
await request('Homepage baseline','/',{}, {status:200})
await request('Platform health','/api/platform/health',{}, {status:200})
await request('Unified health','/api/v1/health',{}, {status:200})

// Sensitive files / source leakage (SPA fallback is acceptable only if no secret content)
for(const path of ['/.env','/.git/config','/.git/HEAD','/vercel.json','/package.json','/api/platform.js','/api/_security.js','/server.js','/robots.txt']){
  await request(`Sensitive path ${path}`,path,{}, {status:[200,404],notContains:'service_role'})
}

// Dangerous methods
for(const method of ['TRACE','CONNECT','PUT']) await request(`Dangerous method ${method}`,'/api/platform/health',{method},{status:[400,404,405]})

// Proxy auth bypass and endpoint allowlist
for(const path of ['/api/sessions','/api/settings/get?session_id=6280000000000','/api/console/logs?session_id=6280000000000','/api/backup/list?session_id=6280000000000']){
  await request(`Unauthenticated ${path}`,path,{}, {status:401})
}
for(const path of ['/api/internal/secrets','/api/admin','/api/../api/sessions','/api/%2e%2e/internal','/api/%252e%252e/internal','/api/session%2Fstatus']){
  await request(`Proxy traversal ${path}`,path,{}, {status:[400,404]})
}

// Malformed/forged JWT attempts
const forged=[
  'null','undefined','Bearer','eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJvd25lciJ9.',
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJvd25lciJ9.invalid'
]
for(const token of forged) await request('Forged JWT','/api/sessions',{headers:{Authorization:`Bearer ${token}`}}, {status:[401,403]})

// SQL/PostgREST/NoSQL-style injection against login
const injections=[
  "admin' OR '1'='1", 'admin.or.(roles.cs.{owner})', '*,owner', 'admin%00',
  '{"$ne":null}', '../../owner', 'a'.repeat(500)
]
for(const identifier of injections){
  await request(`Login injection ${identifier.slice(0,24)}`,'/api/platform/auth/login',{
    method:'POST',headers:{Origin:BASE,'Content-Type':'application/json'},body:JSON.stringify({identifier,password:'NotARealPassword123!'})
  },{status:[400,401],notContains:'syntax error'})
}

// XSS/reflection payloads
const xss=['<script>alert(1)</script>','\"><img src=x onerror=alert(1)>','javascript:alert(document.domain)']
for(const identifier of xss){
  await request('XSS reflection login','/api/platform/auth/login',{
    method:'POST',headers:{Origin:BASE,'Content-Type':'application/json'},body:JSON.stringify({identifier,password:'NotARealPassword123!'})
  },{status:[400,401],notContains:identifier})
}

// CSRF/CORS against management endpoints
for(const origin of ['https://evil.example','null','http://localhost:3000']){
  await request(`Cross-origin register ${origin}`,'/api/platform/auth/register',{
    method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:'{}'
  },{status:403})
  await request(`Cross-origin preflight ${origin}`,'/api/platform/auth/register',{
    method:'OPTIONS',headers:{Origin:origin,'Access-Control-Request-Method':'POST'}
  },{status:[403,405]})
}

// JSON parser, content-type confusion and oversized declaration
await request('Malformed JSON','/api/platform/auth/login',{method:'POST',headers:{Origin:BASE,'Content-Type':'application/json'},body:'{"identifier":'}, {status:400})
await request('Wrong content type','/api/platform/auth/login',{method:'POST',headers:{Origin:BASE,'Content-Type':'text/plain'},body:'identifier=admin'}, {status:400})
await request('Deep object login','/api/platform/auth/login',{method:'POST',headers:{Origin:BASE,'Content-Type':'application/json'},body:JSON.stringify({identifier:{toString:'admin'},password:['x']})}, {status:[400,500]})

// HPP and route parser probes
await request('Duplicate path parameter','/api/platform/health?path=admin&path=health',{}, {status:[200,400,404]})
await request('Huge query value','/api/sessions?x='+encodeURIComponent('a'.repeat(1200)),{}, {status:[400,401,414]})
await request('CRLF query injection','/api/sessions?x='+encodeURIComponent('a\r\nX-Evil: injected'),{}, {status:[400,401]})

// Public gateway CORS and unauthenticated key enforcement
await request('Gateway without API key','/api/gateway/tools/qrcode?text=test',{headers:{Origin:'https://client.example'}},{status:401})
await request('Gateway preflight','/api/gateway/tools/qrcode',{method:'OPTIONS',headers:{Origin:'https://client.example','Access-Control-Request-Method':'GET'}},{status:204})

// Short URL path validation / redirect safety
for(const id of ['javascript:alert(1)','..%2Fadmin','%0d%0aLocation:%20https://evil.example','a']){
  await request('Short URL malicious ID','/s/'+id,{}, {status:[400,404]})
}

// Conservative login rate-limit test (11 requests; no credential brute force)
const rateStatuses=[]
for(let i=0;i<11;i++){
  const r=await request(`Rate limit login ${i+1}`,'/api/platform/auth/login',{
    method:'POST',headers:{Origin:BASE,'Content-Type':'application/json'},body:JSON.stringify({identifier:'rate-limit-test-user',password:'DefinitelyWrong123!'})
  },{status:[400,429]});rateStatuses.push(r.status)
}

const home=results[0]
const requiredHeaders=['content-security-policy','strict-transport-security','x-frame-options','x-content-type-options','referrer-policy','permissions-policy','cross-origin-opener-policy','cross-origin-resource-policy']
for(const header of requiredHeaders) if(!home.headers[header]) results.push({name:`Header ${header}`,path:'/',status:home.status,ms:0,body:'',headers:{},pass:false,notes:'missing security header'})
const csp=home.headers['content-security-policy']||''
for(const directive of ["object-src 'none'","frame-ancestors 'none'","script-src 'self'"]) if(!csp.includes(directive)) results.push({name:`CSP ${directive}`,path:'/',status:home.status,ms:0,body:'',headers:{},pass:false,notes:'missing CSP directive'})

const failures=results.filter(x=>!x.pass)
const statusCounts=Object.fromEntries([...new Set(results.map(x=>x.status))].sort().map(s=>[s,results.filter(x=>x.status===s).length]))
const summary={total:results.length,passed:results.length-failures.length,failed:failures.length,statusCounts,rateStatuses,rateLimitObserved:rateStatuses.includes(429),failures:failures.map(x=>({name:x.name,path:x.path,status:x.status,notes:x.notes,body:x.body}))}
console.log(JSON.stringify(summary,null,2))
await import('node:fs/promises').then(fs=>fs.writeFile('/home/user/umi-jadibot-web/security-test-results.json',JSON.stringify({testedAt:new Date().toISOString(),base:BASE,summary,results},null,2)))
