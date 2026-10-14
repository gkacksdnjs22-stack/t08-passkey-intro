// Software authenticators for reproducible protocol tests, not evidence of a person's physical-device use.
// Generated private keys live only in this process; no private key or cookie is written to the report.
import { generateKeyPairSync, randomBytes, createHash, sign } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import assert from 'node:assert/strict';
const origin=process.argv[2]||'http://localhost:8788', rpID=new URL(origin).hostname;
const reportPath=process.argv[3]||'outputs/security-check.json';
const runId=Date.now().toString(36), log=[], passed=[];
const b64=v=>Buffer.from(v).toString('base64url');
function redact(v){if(Array.isArray(v))return v.map(redact);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,/cookie|token|pairTicket|phoneUrl/i.test(k)?'[redacted]':redact(x)]));return v;}
const sha=v=>createHash('sha256').update(v).digest();
function cbor(v) {
  const head=(major,n)=>n<24?Buffer.from([major*32+n]):n<256?Buffer.from([major*32+24,n]):Buffer.from([major*32+25,n>>8,n&255]);
  if(typeof v==='number')return v>=0?head(0,v):head(1,-1-v);
  if(typeof v==='string'){const b=Buffer.from(v);return Buffer.concat([head(3,b.length),b]);}
  if(v instanceof Uint8Array)return Buffer.concat([head(2,v.length),v]);
  if(v instanceof Map)return Buffer.concat([head(5,v.size),...[...v].flatMap(([k,x])=>[cbor(k),cbor(x)])]);
  throw Error('Unsupported CBOR');
}
function authenticator() {
  const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const jwk=publicKey.export({format:'jwk'}),id=randomBytes(32);let counter=0,userHandle;
  const cose=cbor(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
  function header(flags){const count=Buffer.alloc(4);count.writeUInt32BE(counter);return Buffer.concat([sha(rpID),Buffer.from([flags]),count]);}
  function client(type,challenge,actualOrigin=origin){return Buffer.from(JSON.stringify({type,challenge,origin:actualOrigin,crossOrigin:false}));}
  return {
    id:b64(id),publicKey:b64(cose),
    register(options,flags=0x45){userHandle=options.user.id;const length=Buffer.alloc(2);length.writeUInt16BE(id.length);const authData=Buffer.concat([header(flags),Buffer.alloc(16),length,id,cose]);return {id:b64(id),rawId:b64(id),type:'public-key',authenticatorAttachment:'platform',clientExtensionResults:{credProps:{rk:true}},response:{clientDataJSON:b64(client('webauthn.create',options.challenge)),attestationObject:b64(cbor(new Map([['fmt','none'],['authData',authData],['attStmt',new Map()]]))),transports:['internal']}};},
    login(options,{bad=false,actualOrigin=origin,flags=5}={}){counter++;const authData=header(flags),data=client('webauthn.get',options.challenge,actualOrigin);const signature=sign('sha256',Buffer.concat([authData,sha(data)]),privateKey);if(bad)signature[signature.length-1]^=1;return {id:b64(id),rawId:b64(id),type:'public-key',authenticatorAttachment:'platform',clientExtensionResults:{},response:{clientDataJSON:b64(data),authenticatorData:b64(authData),signature:b64(signature),userHandle}};},
  };
}
function browser(label) {
  const jar=new Map();
  return {label,jar,async request(path,method='GET',data,expected=200,extraHeaders={}) {
    const cookie=[...jar].map(([k,v])=>`${k}=${v}`).join('; ');
    const response=await fetch(origin+path,{method,headers:{Origin:origin,...(cookie?{Cookie:cookie}:{}),...(data?{'Content-Type':'application/json'}:{}),...extraHeaders},body:data?JSON.stringify(data):undefined});
    for(const set of response.headers.getSetCookie()){const [k,v]=set.split(';')[0].split('=');if(v)jar.set(k,v);else jar.delete(k);}
    const raw=await response.text();let result;try{result=JSON.parse(raw);}catch{result=raw;}
    log.push({browser:label,method,path,request:redact(data??null),status:response.status,response:redact(result),cookie:'[not recorded]'});
    assert.equal(response.status,expected,`${label} ${method} ${path}: ${raw}`);return result;
  }};
}
const mark=name=>{passed.push(name);console.log('PASS '+name);};
const a=browser('A'),b=browser('B'),anonymous=browser('anonymous'),a1=authenticator(),a2=authenticator(),b1=authenticator();
const handleA='fixture-a-'+runId,handleB='fixture-b-'+runId;
async function register(actor,key,handle,name='소프트웨어 검사 키') {const o=await actor.request('/api/passkey/register-options','POST',{handle,name,storage:'기기 자체'});const v=await actor.request('/api/passkey/register-verify','POST',{flowId:o.flowId,credential:key.register(o.options)});assert.equal(v.publicKey,key.publicKey);return {o,v};}
async function login(actor,key,handle,flags) {const o=await actor.request('/api/passkey/login-options','POST',{handle});const credential=key.login(o.options,flags);const request={flowId:o.flowId,credential};return {o,request,v:await actor.request('/api/passkey/login-verify','POST',request)};}
await anonymous.request('/api/private-notes','GET',undefined,401);
const publicPage=await fetch(origin+'/').then(r=>r.text());assert(publicPage.includes('함찬원'));assert(!publicPage.includes('가상 기업 B'));
const lockedPage=await fetch(origin+'/private').then(r=>r.text());assert(!lockedPage.includes('가상 기업 B'));mark('미로그인 401 / 공개 소개와 잠긴 페이지에 비공개 원문 없음');
const regA=await register(a,a1,handleA),regB=await register(b,b1,handleB);mark('두 계정 등록 / 서버에 COSE 공개키 저장');
const beforeRotation=a.jar.get('t08_session');await register(a,a2,handleA,'두 번째 소프트웨어 검사 키');const keysA=await a.request('/api/passkey/keys');assert.equal(keysA.keys.length,2);assert(keysA.keys.every(k=>k.name&&k.created_at));mark('한 계정의 패스키 2개와 이름·등록일');
const prior=browser('prior-session');prior.jar.set('t08_session',beforeRotation);await prior.request('/api/private-notes','GET',undefined,401);mark('인증 후 세션 교체 / 이전 세션 재사용 401');
const notesA=await a.request('/api/private-notes'),notesB=await b.request('/api/private-notes');assert.equal(notesA.notes.length,3);assert.equal(notesB.notes.length,3);assert.notEqual(notesA.notes[0].content,notesB.notes[0].content);
await a.request('/api/private-notes?id='+notesB.notes[0].id,'GET',undefined,403);
await b.request('/api/private-notes?id='+notesA.notes[0].id,'GET',undefined,403);
await a.request('/api/private-notes','PATCH',{id:notesB.notes[0].id,title:'변조',content:'남의 자료'},403);
const afterB=await b.request('/api/private-notes');assert.deepEqual(afterB,notesB);
const own=await a.request('/api/private-notes?user_id='+notesB.userId);assert.equal(own.userId,notesA.userId);assert.deepEqual(own.notes,notesA.notes);mark('양방향 자료 읽기 403 / 수정 403 / 건수·내용 불변 / 위조 owner 무시');
await a.request('/api/passkey/delete-key','POST',{id:b1.id},403);mark('남의 패스키 삭제 403');
const oldCookie=a.jar.get('t08_session');await a.request('/api/passkey/logout','POST',{});const replay=browser('logged-out-token');replay.jar.set('t08_session',oldCookie);await replay.request('/api/private-notes','GET',undefined,401);mark('로그아웃 뒤 기존 쿠키 재사용 401');
await login(a,a2,handleA);const pendingAdd=await a.request('/api/passkey/register-options','POST',{name:'로그아웃 뒤 추가 검사',storage:'기기 자체'});await a.request('/api/passkey/logout','POST',{});await a.request('/api/passkey/register-verify','POST',{flowId:pendingAdd.flowId,credential:authenticator().register(pendingAdd.options)},401);mark('패스키 추가 중 로그아웃 / 추가 요청 거절 401');
const wrongKey=await a.request('/api/passkey/login-options','POST',{handle:handleA});await a.request('/api/passkey/login-verify','POST',{flowId:wrongKey.flowId,credential:b1.login(wrongKey.options)},401);mark('남의 패스키로 로그인 401');
const bad=await a.request('/api/passkey/login-options','POST',{handle:handleA});await a.request('/api/passkey/login-verify','POST',{flowId:bad.flowId,credential:a1.login(bad.options,{bad:true})},401);mark('변조 서명 401');
const originBad=await a.request('/api/passkey/login-options','POST',{handle:handleA});await a.request('/api/passkey/login-verify','POST',{flowId:originBad.flowId,credential:a1.login(originBad.options,{actualOrigin:'https://invalid.example'})},401);mark('다른 origin으로 서명한 인증 401');
const uvBad=await a.request('/api/passkey/login-options','POST',{handle:handleA});await a.request('/api/passkey/login-verify','POST',{flowId:uvBad.flowId,credential:a1.login(uvBad.options,{flags:1})},401);mark('기기 본인확인 UV 누락 401');
const success=await login(a,a1,handleA);assert.notEqual(success.o.options.challenge,bad.options.challenge);await a.request('/api/passkey/login-verify','POST',success.request,401);mark('정상 서명 성공 / 매번 다른 challenge / 같은 응답 재사용 401');
const cancellation=browser('cancel');const cancelled=await cancellation.request('/api/passkey/register-options','POST',{handle:'cancel-'+runId,name:'취소 검사',storage:'기기 자체'});await cancellation.request('/api/passkey/cancel','POST',{});await cancellation.request('/api/passkey/register-verify','POST',{flowId:cancelled.flowId,credential:authenticator().register(cancelled.options)},401);await cancellation.request('/api/passkey/register-options','POST',{handle:'cancel-'+runId,name:'재시도 검사',storage:'기기 자체'});await cancellation.request('/api/passkey/cancel','POST',{});mark('등록 취소 시 계정·패스키 저장 없음 / 동일 별명 재시도 가능');
const removeA=await a.request('/api/passkey/delete-key','POST',{id:a1.id});assert.equal(removeA.remaining,1);assert.equal(removeA.loggedOut,true);
await login(a,a2,handleA);const deletedKey=await a.request('/api/passkey/login-options','POST',{handle:handleA});await a.request('/api/passkey/login-verify','POST',{flowId:deletedKey.flowId,credential:a1.login(deletedKey.options)},401);mark('패스키 삭제 뒤 남은 키 로그인 성공 / 삭제한 키 로그인 401');
const simultaneous=await a.request('/api/passkey/login-options','POST',{handle:handleA});const raceRequest={flowId:simultaneous.flowId,credential:a2.login(simultaneous.options)};
const cookieString=[...a.jar].map(([k,v])=>k+'='+v).join('; ');
const race=await Promise.all([1,2].map(()=>fetch(origin+'/api/passkey/login-verify',{method:'POST',headers:{Origin:origin,Cookie:cookieString,'Content-Type':'application/json'},body:JSON.stringify(raceRequest)}).then(async r=>({status:r.status,response:await r.json()}))));assert.deepEqual(race.map(r=>r.status).sort(),[200,401]);log.push({name:'parallel challenge replay',results:race});mark('동시 challenge 재사용: 한 요청만 200, 나머지 401');
// The concurrent fetch above rotates the session without updating our browser jar; obtain the new session normally.
await login(a,a2,handleA);await a.request('/api/passkey/delete-key','POST',{id:a2.id});await a.request('/api/private-notes','GET',undefined,401);await b.request('/api/passkey/delete-key','POST',{id:b1.id});mark('마지막 패스키 삭제 시 즉시 비공개 접근 401');
const pc=browser('QR PC'),phone=browser('QR phone'),otherPC=browser('other PC'),mobile1=authenticator(),mobile2=authenticator(),qrHandle='qr-'+runId;
const newPair=await pc.request('/api/phone-pair/start','POST',{mode:'signup',handle:qrHandle,name:'휴대폰 검사 1',storage:'기기 자체'});
const getTicket=p=>new URLSearchParams(new URL(p.phoneUrl).hash.slice(1)).get('ticket');
const ticket=getTicket(newPair);await phone.request('/api/phone-pair/info','POST',{pairTicket:ticket});await pc.request('/api/phone-pair/consume','POST',{pairId:newPair.pairId},401);
const mobileOptions=await phone.request('/api/passkey/register-options','POST',{pairTicket:ticket});assert.equal(mobileOptions.options.authenticatorSelection.authenticatorAttachment,'platform');
await phone.request('/api/passkey/register-verify','POST',{flowId:mobileOptions.flowId,credential:mobile1.register(mobileOptions.options)});
const pairState=await pc.request('/api/phone-pair/status?id='+newPair.pairId);assert.equal(pairState.state,'ready');
await otherPC.request('/api/phone-pair/consume','POST',{pairId:newPair.pairId},401);
await pc.request('/api/phone-pair/consume','POST',{pairId:newPair.pairId});const pcNotes=await pc.request('/api/private-notes');assert.equal(pcNotes.notes.length,3);mark('QR 등록: 휴대폰 플랫폼 인증 후 원래 PC만 로그인 / 인증 전·다른 PC 401');
await pc.request('/api/phone-pair/consume','POST',{pairId:newPair.pairId},401);await phone.request('/api/phone-pair/info','POST',{pairTicket:ticket},410);mark('QR 일회용 소비 / QR 재사용 401·410');
const extraPair=await pc.request('/api/phone-pair/start','POST',{mode:'signup',name:'휴대폰 검사 2',storage:'기기 자체'});const extraOptions=await phone.request('/api/passkey/register-options','POST',{pairTicket:getTicket(extraPair)});await phone.request('/api/passkey/register-verify','POST',{flowId:extraOptions.flowId,credential:mobile2.register(extraOptions.options)});await pc.request('/api/phone-pair/consume','POST',{pairId:extraPair.pairId});const mobileKeys=await pc.request('/api/passkey/keys');assert.equal(mobileKeys.keys.length,2);mark('QR로 기존 계정에 두 번째 휴대폰 키 추가');
await pc.request('/api/passkey/logout','POST',{});const loginPair=await pc.request('/api/phone-pair/start','POST',{mode:'login',handle:qrHandle});const phoneLoginOptions=await phone.request('/api/passkey/login-options','POST',{pairTicket:getTicket(loginPair),handle:handleA});assert.equal(phoneLoginOptions.options.hints[0],'client-device');await phone.request('/api/passkey/login-verify','POST',{flowId:phoneLoginOptions.flowId,credential:mobile2.login(phoneLoginOptions.options)});await pc.request('/api/phone-pair/consume','POST',{pairId:loginPair.pairId});mark('QR 로그인: 휴대폰 실제 서명 뒤 PC 세션 발급 / 요청 별명 위조 무시');
const cancelPair=await pc.request('/api/phone-pair/start','POST',{name:'취소 키',storage:'기기 자체'});const cancelOptions=await phone.request('/api/passkey/register-options','POST',{pairTicket:getTicket(cancelPair)});await pc.request('/api/phone-pair/cancel','POST',{});await phone.request('/api/passkey/register-verify','POST',{flowId:cancelOptions.flowId,credential:authenticator().register(cancelOptions.options)},410);mark('PC의 QR 취소 뒤 휴대폰 등록 거절 410');
const stalePair=await pc.request('/api/phone-pair/start','POST',{name:'로그아웃 키',storage:'기기 자체'});await pc.request('/api/passkey/logout','POST',{});await phone.request('/api/passkey/register-options','POST',{pairTicket:getTicket(stalePair)},401);mark('PC 로그아웃 뒤 QR로 새 키 추가 거절 401');
await login(pc,mobile2,qrHandle);await pc.request('/api/passkey/delete-key','POST',{id:mobile1.id});await pc.request('/api/passkey/delete-key','POST',{id:mobile2.id});
// Cloud-manager protocol fixtures use independent software keys. This does not claim a real Bitwarden extension was operated.
const cloud=browser('manager protocol fixture'),cloudPhone=authenticator(),cloudBackup=authenticator(),cloudHandle='cloud-'+runId;
await anonymous.request('/api/passkey/register-options','POST',{channel:'manager',handle:cloudHandle,name:'무단 예비 키',storage:'Bitwarden'},403);
await register(cloud,cloudPhone,cloudHandle,'휴대폰 프로토콜 검사');
const cloudOptions=await cloud.request('/api/passkey/register-options','POST',{channel:'manager',handle:handleB,name:'관리자 프로토콜 검사',storage:'Bitwarden'});
assert.equal(cloudOptions.options.authenticatorSelection.userVerification,'required');assert.equal(cloudOptions.options.authenticatorSelection.residentKey,'required');assert.equal(cloudOptions.options.authenticatorSelection.authenticatorAttachment,undefined);assert(!cloudOptions.options.hints?.includes('hybrid'));
const backupResponse=await cloud.request('/api/passkey/register-verify','POST',{flowId:cloudOptions.flowId,credential:cloudBackup.register(cloudOptions.options,0x5d)});assert.equal(backupResponse.publicKey,cloudBackup.publicKey);
const cloudKeys=await cloud.request('/api/passkey/keys');assert.equal(cloudKeys.keys.length,2);assert.equal(new Set(cloudKeys.keys.map(k=>k.public_key)).size,2);assert(cloudKeys.keys.some(k=>k.id===cloudBackup.id&&k.storage==='Bitwarden'&&k.backed_up===1));assert.equal(backupResponse.user.handle,cloudHandle);
mark('관리자 예비 키: 기존 인증 필요 403 / 같은 계정에 별도 공개키 저장 / 소유자 위조 무시');
await cloud.request('/api/passkey/logout','POST',{});
const mismatched=await cloud.request('/api/passkey/login-options','POST',{channel:'manager',handle:cloudHandle});assert.deepEqual(mismatched.options.allowCredentials.map(k=>k.id),[cloudBackup.id]);assert.equal(mismatched.options.allowCredentials[0].transports,undefined);assert.equal(mismatched.options.hints,undefined);
await cloud.request('/api/passkey/login-verify','POST',{flowId:mismatched.flowId,credential:cloudPhone.login(mismatched.options)},401);mark('관리자 로그인은 예비 키만 허용 / 휴대폰 키로 요청하면 401');
async function managerLogin(){const o=await cloud.request('/api/passkey/login-options','POST',{channel:'manager',handle:cloudHandle});const input={flowId:o.flowId,credential:cloudBackup.login(o.options)};await cloud.request('/api/passkey/login-verify','POST',input);return input;}
const managerProof=await managerLogin();await cloud.request('/api/passkey/login-verify','POST',managerProof,401);const cloudNotes=await cloud.request('/api/private-notes');assert.equal(cloudNotes.notes.length,3);await cloud.request('/api/private-notes?id='+notesA.notes[0].id,'GET',undefined,403);mark('관리자 키의 실제 서명으로 로그인 / 재사용 401 / 남의 노트 403');
await cloud.request('/api/passkey/delete-key','POST',{id:cloudPhone.id});await cloud.request('/api/passkey/logout','POST',{});await managerLogin();await cloud.request('/api/private-notes');const oldPhone=await cloud.request('/api/passkey/login-options','POST',{handle:cloudHandle});await cloud.request('/api/passkey/login-verify','POST',{flowId:oldPhone.flowId,credential:cloudPhone.login(oldPhone.options)},401);await cloud.request('/api/passkey/delete-key','POST',{id:cloudBackup.id});await cloud.request('/api/private-notes','GET',undefined,401);mark('휴대폰 키 삭제 후 관리자 키로 로그인 성공 / 지운 휴대폰 키 거절 / 마지막 키 삭제 401');
await anonymous.request('/api/passkey/register-options','POST',{handle:'csrf-'+runId,name:'검사',storage:'기기 자체'},403,{Origin:'https://invalid.example'});mark('다른 사이트의 변경 요청 403');
mkdirSync(new URL('../outputs/',import.meta.url),{recursive:true});
writeFileSync(reportPath,JSON.stringify({testedAt:new Date().toISOString(),origin,authenticator:'Node 소프트웨어 인증기 · 실제 기기 확인과 구분',passed,log},null,2));
console.log(`${passed.length} checks passed; report: ${reportPath}`);
