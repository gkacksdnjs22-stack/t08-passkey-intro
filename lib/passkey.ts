import { env } from 'cloudflare:workers';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse, type AuthenticatorTransport } from '@simplewebauthn/server';

const LIVE_ORIGIN = 'https://t01-chanwon-network-intro.gkacksdnjs22.chatgpt.site';
const SESSION_COOKIE = 't08_session';
const FLOW_COOKIE = 't08_flow';
const PAIR_COOKIE = 't08_pair';
const TTL = 12 * 60 * 60 * 1000;
type Row = Record<string, any>;
class HttpError extends Error { constructor(public status: number, message: string) { super(message); } }
const db = () => { if (!env.DB) throw new HttpError(503, '저장소를 준비 중입니다. 잠시 뒤 다시 시도하세요.'); return env.DB; };
const now = () => Date.now();
const iso = () => new Date().toISOString();
function random() { return encode(crypto.getRandomValues(new Uint8Array(32))); }
function encode(value: Uint8Array) { return btoa(String.fromCharCode(...value)).replaceAll('+','-').replaceAll('/','_').replaceAll('=',''); }
function decode(value: string) { return Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')), c => c.charCodeAt(0)); }
async function hash(value: string) { return encode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))); }
function cookie(req: Request, name: string) { return req.headers.get('cookie')?.split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='))?.slice(name.length+1) ?? ''; }
function setCookie(req: Request, name: string, value: string, age: number) { return `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${new URL(req.url).protocol === 'https:' ? '; Secure' : ''}`; }
function json(data: unknown, status = 200, cookies: string[] = []) { const headers = new Headers({ 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store, private', 'X-Content-Type-Options':'nosniff' }); for (const c of cookies) headers.append('Set-Cookie', c); return new Response(JSON.stringify(data), { status, headers }); }
function config(req: Request) {
  const url = new URL(req.url);
  const local = (url.hostname === 'localhost' || url.hostname === '127.0.0.1') && url.protocol === 'http:';
  const origin = local ? url.origin : LIVE_ORIGIN;
  if (!local && url.origin !== LIVE_ORIGIN) throw new HttpError(403, '허용되지 않은 사이트 주소입니다.');
  return { origin, rpID: new URL(origin).hostname };
}
function checkOrigin(req: Request) { if (req.headers.get('origin') !== config(req).origin) throw new HttpError(403, '이 사이트에서 다시 시도하세요.'); }
async function body(req: Request) {
  if (!req.headers.get('content-type')?.includes('application/json')) throw new HttpError(400, 'JSON 요청이 필요합니다.');
  const text = await req.text(); if (text.length > 24000) throw new HttpError(413, '요청이 너무 큽니다.');
  try { return JSON.parse(text); } catch { throw new HttpError(400, '요청 형식을 확인하세요.'); }
}
function text(value: unknown, label: string, max = 60) { if (typeof value !== 'string' || !value.trim() || value.trim().length > max) throw new HttpError(400, `${label}을 확인하세요.`); return value.trim(); }
function handle(value: unknown) { const h = text(value, '별명', 24).toLowerCase(); if (!/^[a-z0-9가-힣_-]{2,24}$/.test(h)) throw new HttpError(400, '별명은 한글·영문·숫자·밑줄·하이픈으로 2~24자 입력하세요.'); return h; }
async function session(req: Request, required = true) {
  const token = cookie(req, SESSION_COOKIE); if (!token) { if (required) throw new HttpError(401, '패스키로 먼저 들어오세요.'); return null; }
  const s = await db().prepare('SELECT s.*, u.handle FROM passkey_sessions s JOIN passkey_users u ON u.id=s.user_id JOIN passkeys p ON p.id=s.credential_id WHERE s.hash=? AND s.expires_at>? AND p.revoked_at IS NULL').bind(await hash(token), now()).first<Row>();
  if (!s && required) throw new HttpError(401, '로그인이 끝났습니다. 패스키로 다시 들어오세요.'); return s;
}
async function createSession(req: Request, userId: string, credentialId: string) {
  const token = random();
  const results = await db().batch([
    db().prepare('DELETE FROM passkey_sessions WHERE hash=?').bind(await hash(cookie(req,SESSION_COOKIE))),
    db().prepare('INSERT INTO passkey_sessions (hash,user_id,credential_id,expires_at,created_at) SELECT ?,user_id,id,?,? FROM passkeys WHERE id=? AND user_id=? AND revoked_at IS NULL').bind(await hash(token),now()+TTL,iso(),credentialId,userId),
  ]);
  if (!results[1].meta.changes) throw new HttpError(401,'삭제된 패스키입니다. 남은 패스키로 다시 들어오세요.');
  return setCookie(req,SESSION_COOKIE,token,TTL/1000);
}
async function consume(req: Request, id: unknown, kinds: string[]) {
  if (typeof id !== 'string') throw new HttpError(400, '인증 질문이 없습니다.');
  const flow = cookie(req,FLOW_COOKIE); if (!flow) throw new HttpError(401, '인증 질문이 만료됐습니다. 다시 시작하세요.');
  // DELETE RETURNING consumes the challenge atomically before any verification, including failed attempts.
  const c = await db().prepare('DELETE FROM passkey_challenges WHERE id=? AND browser_hash=? AND expires_at>? RETURNING *').bind(id,await hash(flow),now()).first<Row>();
  if (!c || !kinds.includes(c.kind)) throw new HttpError(401, '이미 사용했거나 만료된 인증 질문입니다. 다시 시작하세요.');
  if (c.pair_id) {
    const pair=await db().prepare('SELECT id FROM phone_pairs WHERE id=? AND state=? AND expires_at>?').bind(c.pair_id,'pending',now()).first();
    if (!pair) throw new HttpError(410,'QR 연결 시간이 끝났습니다. PC에서 새 QR을 띄우세요.');
  }
  if (c.session_hash) {
    if(c.pair_id){const s=await db().prepare('SELECT s.hash FROM passkey_sessions s JOIN passkeys p ON p.id=s.credential_id WHERE s.hash=? AND s.user_id=? AND s.expires_at>? AND p.revoked_at IS NULL').bind(c.session_hash,c.user_id,now()).first();if(!s)throw new HttpError(401,'PC 로그인이 끝났습니다. PC에서 다시 들어오세요.');}
    else { const s = await session(req); if (s!.hash !== c.session_hash || s!.user_id !== c.user_id) throw new HttpError(403, '다른 로그인에서 만든 질문입니다.'); }
  }
  return c;
}
async function options(req: Request, action: string, input: Row) {
  const { rpID } = config(req); const s = await session(req,false);
  const pair=input.pairTicket?await pairByTicket(input.pairTicket):null;
  const flow = random(), id = random(); let kind: string, userId: string, userHandle: string, name = '', storage = '', sessionHash = null;
  let result;
  if (action === 'register-options') {
    if(pair&&pair.mode==='login')throw new HttpError(403,'이 QR은 로그인용입니다.');
    name = text(pair?.name??input.name,'패스키 이름'); storage = text(pair?.storage??input.storage,'저장 위치');
    if (!['구글 비밀번호 관리자','기기 자체','보안 키','기타 패스키 관리자'].includes(storage)) throw new HttpError(400,'저장 위치를 선택하세요.');
    kind = pair?(pair.mode==='add'?'add':'signup'):(s?'add':'signup'); userId=pair?.user_id??s?.user_id??crypto.randomUUID();userHandle=pair?.handle??s?.handle??handle(input.handle);sessionHash=pair?pair.session_hash:(s?.hash??null);
    if (kind==='signup' && await db().prepare('SELECT id FROM passkey_users WHERE handle=?').bind(userHandle).first()) throw new HttpError(409,'이미 사용 중인 별명입니다. 기존 패스키로 들어오거나 다른 별명을 쓰세요.');
    const keys = kind==='add' ? (await db().prepare('SELECT id,transports FROM passkeys WHERE user_id=? AND revoked_at IS NULL').bind(userId).all<Row>()).results : [];
    result = await generateRegistrationOptions({ rpName:'함찬원의 비공개 노트', rpID, userName:userHandle, userID:new TextEncoder().encode(userId), attestationType:'none', timeout:120000, preferredAuthenticatorType:storage==='보안 키'?'securityKey':pair?'localDevice':'remoteDevice', supportedAlgorithmIDs:[-7,-257], excludeCredentials:keys.map(k=>({ id:k.id, transports:JSON.parse(k.transports) })), authenticatorSelection:{residentKey:'required',userVerification:'required'} });
  } else {
    if(pair&&pair.mode!=='login')throw new HttpError(403,'이 QR은 등록용입니다.');
    kind = 'login'; userHandle = pair?.handle??handle(input.handle);
    const u = await db().prepare('SELECT id FROM passkey_users WHERE handle=?').bind(userHandle).first<Row>(); userId = u?.id ?? 'missing';
    const keys = u ? (await db().prepare('SELECT id,transports FROM passkeys WHERE user_id=? AND revoked_at IS NULL').bind(u.id).all<Row>()).results : [];
    const authentication = await generateAuthenticationOptions({ rpID, timeout:120000, userVerification:'required', allowCredentials:keys.length ? keys.map(k=>({id:k.id,transports:pair?JSON.parse(k.transports):['hybrid']})) : [{id:random()}] });
    result = { ...authentication, hints:[pair?'client-device':'hybrid'] };
  }
  await db().batch([
    db().prepare('DELETE FROM passkey_challenges WHERE expires_at<=? OR browser_hash=?').bind(now(),await hash(cookie(req,FLOW_COOKIE))),
    db().prepare('DELETE FROM passkey_sessions WHERE expires_at<=?').bind(now()),
    db().prepare('INSERT INTO passkey_challenges (id,browser_hash,kind,challenge,user_id,handle,name,storage,session_hash,expires_at,pair_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind(id,await hash(flow),kind,result.challenge,userId,userHandle,name,storage,sessionHash,now()+5*60*1000,pair?.id??null),
  ]);
  return json({ flowId:id, options:result },200,[setCookie(req,FLOW_COOKIE,flow,300)]);
}
async function register(req: Request, input: Row) {
  const c = await consume(req,input.flowId,['signup','add']); const { origin, rpID } = config(req);
  let verified;
  try { verified = await verifyRegistrationResponse({ response:input.credential, expectedChallenge:c.challenge, expectedOrigin:origin, expectedRPID:rpID, requireUserVerification:true }); } catch { throw new HttpError(401,'패스키 등록을 확인하지 못했습니다. 다시 시도하세요.'); }
  if (!verified.verified || !verified.registrationInfo) throw new HttpError(401,'패스키 등록이 거절됐습니다.');
  const info = verified.registrationInfo, key = info.credential;
  const cmds = [];
  if (c.kind === 'signup') {
    cmds.push(db().prepare('INSERT INTO passkey_users (id,handle,created_at) VALUES (?,?,?)').bind(c.user_id,c.handle,iso()));
    const examples = [ ['프로젝트 메모',`가상 자료 · ${c.handle}의 실습 A: 방화벽 규칙을 세 가지 경우로 나누어 확인한다.`], ['지원 계획',`가상 자료 · ${c.handle}의 가상 기업 B: 네트워크 실습 과정을 정리한 뒤 지원 준비를 한다.`], ['나의 회고',`가상 자료 · ${c.handle}의 회고 C: 오류가 나면 로그를 먼저 읽고 변경은 한 번에 하나씩 한다.`] ];
    for (const [title,content] of examples) cmds.push(db().prepare('INSERT INTO private_notes (id,user_id,title,content,updated_at) VALUES (?,?,?,?,?)').bind(crypto.randomUUID(),c.user_id,title,content,iso()));
  }
  const values=[key.id,c.user_id,encode(key.publicKey),key.counter,JSON.stringify(key.transports ?? []),c.name,c.storage,info.credentialDeviceType,info.credentialBackedUp?1:0,iso()];
  const columns='(id,user_id,public_key,counter,transports,name,storage,device_type,backed_up,created_at)';
  // Adding a key must still have the same live session when the transaction writes it.
  cmds.push(c.kind==='add'
    ? db().prepare(`INSERT INTO passkeys ${columns} SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM passkey_sessions s JOIN passkeys p ON p.id=s.credential_id WHERE s.hash=? AND s.user_id=? AND s.expires_at>? AND p.revoked_at IS NULL)`).bind(...values,c.session_hash,c.user_id,now())
    : db().prepare(`INSERT INTO passkeys ${columns} VALUES (?,?,?,?,?,?,?,?,?,?)`).bind(...values));
  let results;
  try { results=await db().batch(cmds); } catch { throw new HttpError(409,'별명 또는 패스키가 이미 등록됐습니다. 다시 시작하세요.'); }
  if (!results.at(-1)?.meta.changes) throw new HttpError(401,'등록 중 로그인이 끝났습니다. 다시 들어오세요.');
  if(c.pair_id) await readyPair(c,key.id);
  return json({verified:true,user:{id:c.user_id,handle:c.handle},publicKey:encode(key.publicKey),keyType:'COSE 공개키 · 개인키와 비밀번호는 저장하지 않음'},200,[await createSession(req,c.user_id,key.id),setCookie(req,FLOW_COOKIE,'',0)]);
}
async function login(req: Request, input: Row) {
  const c = await consume(req,input.flowId,['login']); const { origin,rpID } = config(req);
  const k = await db().prepare('SELECT * FROM passkeys WHERE id=? AND user_id=? AND revoked_at IS NULL').bind(input.credential?.id ?? '',c.user_id).first<Row>();
  if (!k) throw new HttpError(401,'패스키를 확인하지 못했습니다. 별명과 패스키를 확인하세요.');
  if (input.credential?.response?.userHandle && input.credential.response.userHandle !== encode(new TextEncoder().encode(c.user_id))) throw new HttpError(401,'패스키를 확인하지 못했습니다.');
  let verified;
  try { verified = await verifyAuthenticationResponse({response:input.credential,expectedChallenge:c.challenge,expectedOrigin:origin,expectedRPID:rpID,credential:{id:k.id,publicKey:decode(k.public_key),counter:k.counter,transports:JSON.parse(k.transports) as AuthenticatorTransport[]},requireUserVerification:true}); } catch { throw new HttpError(401,'패스키 서명이 거절됐습니다. 다시 시도하세요.'); }
  if (!verified.verified) throw new HttpError(401,'패스키 서명이 거절됐습니다.');
  const update = await db().prepare('UPDATE passkeys SET counter=? WHERE id=? AND user_id=? AND counter=? AND revoked_at IS NULL').bind(verified.authenticationInfo.newCounter,k.id,c.user_id,k.counter).run();
  if (!update.meta.changes) throw new HttpError(401,'패스키 상태가 바뀌었습니다. 다시 들어오세요.');
  if(c.pair_id) await readyPair(c,k.id);
  return json({verified:true,user:{id:c.user_id,handle:c.handle}},200,[await createSession(req,c.user_id,k.id),setCookie(req,FLOW_COOKIE,'',0)]);
}
export async function authRoute(req: Request, action: string) {
  try {
    config(req);
    if (req.method === 'GET' && action === 'session') { const s = await session(req,false); return json({user:s?{id:s.user_id,handle:s.handle}:null}); }
    if (req.method === 'GET' && action === 'keys') { const s=await session(req); const keys=await db().prepare('SELECT id,name,storage,created_at,public_key,device_type,backed_up FROM passkeys WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at').bind(s!.user_id).all(); return json({keys:keys.results}); }
    checkOrigin(req); const input = await body(req);
    if (req.method === 'POST' && ['register-options','login-options'].includes(action)) return await options(req,action,input);
    if (req.method === 'POST' && action === 'register-verify') return await register(req,input);
    if (req.method === 'POST' && action === 'login-verify') return await login(req,input);
    if (req.method === 'POST' && action === 'cancel') { const flow=cookie(req,FLOW_COOKIE); if(flow) await db().prepare('DELETE FROM passkey_challenges WHERE browser_hash=?').bind(await hash(flow)).run(); return json({cancelled:true},200,[setCookie(req,FLOW_COOKIE,'',0)]); }
    if (req.method === 'POST' && action === 'logout') { const token=cookie(req,SESSION_COOKIE); if(token) await db().prepare('DELETE FROM passkey_sessions WHERE hash=?').bind(await hash(token)).run(); const flow=cookie(req,FLOW_COOKIE); if(flow) await db().prepare('DELETE FROM passkey_challenges WHERE browser_hash=?').bind(await hash(flow)).run(); return json({loggedOut:true},200,[setCookie(req,SESSION_COOKIE,'',0),setCookie(req,FLOW_COOKIE,'',0)]); }
    if (req.method === 'POST' && action === 'delete-key') {
      const s=await session(req); const id=text(input.id,'패스키');
      const owned=await db().prepare('SELECT id FROM passkeys WHERE id=? AND user_id=? AND revoked_at IS NULL').bind(id,s!.user_id).first(); if(!owned) throw new HttpError(403,'이 패스키를 삭제할 수 없습니다.');
      await db().batch([
        db().prepare('DELETE FROM passkey_sessions WHERE credential_id=? AND user_id=?').bind(id,s!.user_id),
        db().prepare('UPDATE passkeys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL').bind(iso(),id,s!.user_id),
        db().prepare('DELETE FROM passkey_challenges WHERE user_id=?').bind(s!.user_id),
      ]);
      const remaining = await db().prepare('SELECT COUNT(*) AS count FROM passkeys WHERE user_id=? AND revoked_at IS NULL').bind(s!.user_id).first<Row>();
      return json({deleted:true,remaining:remaining!.count,loggedOut:s!.credential_id===id},200,s!.credential_id===id?[setCookie(req,SESSION_COOKIE,'',0)]:[]);
    }
    throw new HttpError(405,'지원하지 않는 요청입니다.');
  } catch (e) { return failure(e); }
}
export async function notesRoute(req: Request) {
  try {
    config(req); const s=await session(req); const url=new URL(req.url);
    if (req.method === 'GET') {
      const id=url.searchParams.get('id');
      if (id) { const note=await db().prepare('SELECT * FROM private_notes WHERE id=? AND user_id=?').bind(id,s!.user_id).first(); if(!note) throw new HttpError(403,'이 자료를 열 수 없습니다.'); return json({note}); }
      // Client-supplied owner IDs are ignored; ownership always comes from the server session.
      const result=await db().prepare('SELECT * FROM private_notes WHERE user_id=? ORDER BY updated_at,id').bind(s!.user_id).all(); return json({notes:result.results,userId:s!.user_id});
    }
    checkOrigin(req); const input=await body(req);
    if(req.method==='PATCH') { const result=await db().prepare('UPDATE private_notes SET title=?,content=?,updated_at=? WHERE id=? AND user_id=?').bind(text(input.title,'제목',80),text(input.content,'내용',2000),iso(),text(input.id,'자료'),s!.user_id).run(); if(!result.meta.changes) throw new HttpError(403,'이 자료를 수정할 수 없습니다.'); return json({saved:true}); }
    throw new HttpError(405,'지원하지 않는 요청입니다.');
  } catch(e) { return failure(e); }
}
function failure(e: unknown) { return e instanceof HttpError ? json({error:e.message},e.status) : json({error:'요청을 처리하지 못했습니다. 잠시 뒤 다시 시도하세요.'},500); }

async function pairByTicket(ticket: unknown) {
  if(typeof ticket!=='string'||ticket.length!==43)throw new HttpError(400,'QR 연결 주소를 확인하세요.');
  const pair=await db().prepare('SELECT * FROM phone_pairs WHERE ticket_hash=? AND state=? AND expires_at>?').bind(await hash(ticket),'pending',now()).first<Row>();
  if(!pair)throw new HttpError(410,'이미 사용했거나 만료된 QR입니다. PC에서 새 QR을 띄우세요.');
  if(pair.mode==='add') {const valid=await db().prepare('SELECT s.hash FROM passkey_sessions s JOIN passkeys p ON p.id=s.credential_id WHERE s.hash=? AND s.user_id=? AND s.expires_at>? AND p.revoked_at IS NULL').bind(pair.session_hash,pair.user_id,now()).first();if(!valid)throw new HttpError(401,'PC 로그인이 끝났습니다. PC에서 다시 들어오세요.');}
  return pair;
}
async function readyPair(c: Row, credentialId: string) {
  const result=await db().prepare('UPDATE phone_pairs SET state=?,credential_id=?,user_id=? WHERE id=? AND state=? AND expires_at>?').bind('ready',credentialId,c.user_id,c.pair_id,'pending',now()).run();
  if(!result.meta.changes)throw new HttpError(410,'QR 연결 시간이 끝났습니다. 새 QR을 띄워 다시 들어오세요.');
}
export async function phoneRoute(req: Request, action: string) {
  try {
    config(req);
    if(req.method==='GET'&&action==='status') {
      const id=new URL(req.url).searchParams.get('id')??'';const secret=cookie(req,PAIR_COOKIE);
      if(!secret)throw new HttpError(401,'이 브라우저에서 만든 QR이 아닙니다.');
      const pair=await db().prepare('SELECT state,expires_at FROM phone_pairs WHERE id=? AND pc_hash=?').bind(id,await hash(secret)).first<Row>();
      if(!pair||pair.expires_at<=now())throw new HttpError(410,'QR이 만료됐습니다. 새 QR을 띄우세요.');
      return json({state:pair.state,expiresAt:pair.expires_at});
    }
    checkOrigin(req);const input=await body(req);
    if(req.method==='POST'&&action==='start') {
      const s=await session(req,false);const mode=s?'add':input.mode==='signup'?'signup':'login';
      const userHandle=s?.handle??handle(input.handle), id=crypto.randomUUID(),ticket=random(),pc=random(),expires=now()+5*60*1000;
      const u=mode==='signup'?null:await db().prepare('SELECT id FROM passkey_users WHERE handle=?').bind(userHandle).first<Row>();
      if(mode==='signup'&&await db().prepare('SELECT id FROM passkey_users WHERE handle=?').bind(userHandle).first())throw new HttpError(409,'이미 쓰는 별명입니다. 등록한 휴대폰으로 들어가기를 선택하세요.');
      const name=mode==='login'?'':text(input.name,'패스키 이름'),storage=mode==='login'?'':text(input.storage,'저장 위치');
      if(mode!=='login'&&!['구글 비밀번호 관리자','기기 자체','보안 키','기타 패스키 관리자'].includes(storage))throw new HttpError(400,'저장 위치를 선택하세요.');
      await db().batch([
        db().prepare('DELETE FROM phone_pairs WHERE expires_at<=? OR pc_hash=?').bind(now(),await hash(cookie(req,PAIR_COOKIE))),
        db().prepare('INSERT INTO phone_pairs (id,ticket_hash,pc_hash,mode,user_id,handle,name,storage,session_hash,state,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind(id,await hash(ticket),await hash(pc),mode,s?.user_id??u?.id??crypto.randomUUID(),userHandle,name,storage,s?.hash??null,'pending',expires),
      ]);
      return json({pairId:id,phoneUrl:config(req).origin+'/phone-connect#ticket='+ticket,expiresAt:expires},200,[setCookie(req,PAIR_COOKIE,pc,300)]);
    }
    if(req.method==='POST'&&action==='info') {const p=await pairByTicket(input.pairTicket);return json({handle:p.handle,mode:p.mode,name:p.name,storage:p.storage,expiresAt:p.expires_at});}
    if(req.method==='POST'&&action==='consume') {
      const secret=cookie(req,PAIR_COOKIE);if(!secret)throw new HttpError(401,'이 브라우저에서 만든 QR이 아닙니다.');
      const pair=await db().prepare('DELETE FROM phone_pairs WHERE id=? AND pc_hash=? AND state=? AND expires_at>? RETURNING *').bind(text(input.pairId,'QR 연결'),await hash(secret),'ready',now()).first<Row>();
      if(!pair)throw new HttpError(401,'QR 인증이 완료되지 않았거나 이미 사용됐습니다.');
      if(pair.mode==='add'){const s=await session(req);if(s!.hash!==pair.session_hash||s!.user_id!==pair.user_id)throw new HttpError(401,'PC 로그인이 바뀌었습니다. 다시 시작하세요.');}
      return json({connected:true,user:{id:pair.user_id,handle:pair.handle}},200,[await createSession(req,pair.user_id,pair.credential_id),setCookie(req,PAIR_COOKIE,'',0)]);
    }
    if(req.method==='POST'&&action==='cancel') {const secret=cookie(req,PAIR_COOKIE);if(secret)await db().prepare('DELETE FROM phone_pairs WHERE pc_hash=?').bind(await hash(secret)).run();return json({cancelled:true},200,[setCookie(req,PAIR_COOKIE,'',0)]);}
    throw new HttpError(405,'지원하지 않는 요청입니다.');
  }catch(e){return failure(e);}
}
