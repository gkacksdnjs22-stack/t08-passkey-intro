'use client';
import { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { Fingerprint, LockKeyhole, KeyRound, LogOut, Plus, Download, ArrowLeft, Smartphone, X, ShieldCheck } from 'lucide-react';
type User = { id:string; handle:string };
type Note = { id:string; title:string; content:string; updated_at:string };
type Key = { id:string; name:string; storage:string; created_at:string; public_key:string };
type Audit = { time:string; method:string; url:string; request:unknown; status:number; response:unknown };
const locations = ['구글 비밀번호 관리자','기기 자체','보안 키','기타 패스키 관리자'];
function clean(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(clean);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,/token|cookie|secret|sessionHash|browserHash|phoneUrl|pairTicket/i.test(k)?'[가림]':clean(v)]));
  return value;
}
export default function PrivateSpace() {
  const [user,setUser]=useState<User|null>(null), [notes,setNotes]=useState<Note[]>([]), [keys,setKeys]=useState<Key[]>([]);
  const [mode,setMode]=useState<'login'|'signup'>('login'), [handle,setHandle]=useState(''), [keyName,setKeyName]=useState('내 휴대폰'), [storage,setStorage]=useState(locations[0]);
  const [loginMethod,setLoginMethod]=useState<'phone'|'manager'>('phone'),[managerReady,setManagerReady]=useState(false),[managerName,setManagerName]=useState('Bitwarden 예비 패스키');
  const [busy,setBusy]=useState(false), [loading,setLoading]=useState(true), [supported,setSupported]=useState(true), [message,setMessage]=useState(''), [error,setError]=useState(false), [audit,setAudit]=useState<Audit[]>([]);
  const [deleting,setDeleting]=useState<string|null>(null), [editing,setEditing]=useState<Note|null>(null);
  const [pair,setPair]=useState<{pairId:string;qr:string;expiresAt:number}|null>(null);
  const qrDialog=useRef<HTMLDialogElement>(null);
  const qrReturnFocus=useRef<HTMLElement|null>(null);
  async function api(path:string, method='GET', request?:unknown) {
    const response=await fetch(path,{method,credentials:'same-origin',cache:'no-store',headers:request?{'Content-Type':'application/json'}:undefined,body:request?JSON.stringify(request):undefined});
    const data:any=await response.json();
    setAudit(prev=>[...prev,{time:new Date().toISOString(),method,url:path,request:clean(request??null),status:response.status,response:clean(data)}].slice(-100));
    if (!response.ok) { if(response.status===401&&(path==='/api/private-notes'||path==='/api/passkey/keys')){setUser(null);setNotes([]);setKeys([]);setEditing(null);} throw new Error(data.error||'요청을 처리하지 못했습니다.'); } return data;
  }
  async function refresh() {
    const data=await api('/api/passkey/session'); setUser(data.user);
    if(data.user) { const [n,k]=await Promise.all([api('/api/private-notes'),api('/api/passkey/keys')]); setNotes(n.notes);setKeys(k.keys); }
    else {setNotes([]);setKeys([]);}
  }
  useEffect(()=>{setSupported(window.isSecureContext);refresh().catch(e=>{setMessage(e.message);setError(true);}).finally(()=>setLoading(false));},[]);
  useEffect(()=>{
    const dialog=qrDialog.current;if(!pair||!dialog)return;
    const previousFocus=qrReturnFocus.current??document.activeElement;dialog.showModal();const previousOverflow=document.body.style.overflow;document.body.style.overflow='hidden';
    return()=>{if(dialog.open)dialog.close();document.body.style.overflow=previousOverflow;if(previousFocus instanceof HTMLElement&&previousFocus.isConnected)previousFocus.focus();};
  },[pair]);
  useEffect(()=>{
    if(!pair)return;let ended=false,inFlight=false;
    const check=async()=>{if(ended||inFlight)return;inFlight=true;try{
      const status=await api('/api/phone-pair/status?id='+pair.pairId);
      if(ended)return;
      if(status.state==='ready'){ended=true;await api('/api/phone-pair/consume','POST',{pairId:pair.pairId});setPair(null);await refresh();setMessage('휴대폰에서 인증했습니다. 비공개 공간이 열렸습니다.');setError(false);setKeyName('내 예비 패스키');}
    }catch(e){ended=true;setPair(null);setMessage((e as Error).message);setError(true);}finally{inFlight=false;}};
    const timer=window.setInterval(check,1500);check();return()=>{ended=true;window.clearInterval(timer);};
  },[pair]);
  useEffect(()=>{
    const relock=()=>{api('/api/passkey/session').then(data=>{if(!data.user){setUser(null);setNotes([]);setKeys([]);setEditing(null);}}).catch(()=>{setUser(null);setNotes([]);setKeys([]);setEditing(null);});};
    window.addEventListener('focus',relock); const interval=window.setInterval(relock,60000); return()=>{window.removeEventListener('focus',relock);window.clearInterval(interval);};
  },[]);
  async function authenticate(register:boolean) {
    qrReturnFocus.current=document.activeElement instanceof HTMLElement?document.activeElement:null;
    setBusy(true);setMessage('');setError(false);
    try {
      if(!supported) throw new Error('HTTPS 공개 주소에서 다시 열어주세요.');
      const result=await api('/api/phone-pair/start','POST',{mode:register?'signup':'login',handle,name:keyName,storage});
      const qr=await QRCode.toDataURL(result.phoneUrl,{width:320,margin:4,color:{dark:'#14211f',light:'#ffffff'}});
      setPair({pairId:result.pairId,qr,expiresAt:result.expiresAt});setMessage('QR코드를 휴대폰 카메라로 스캔하고 휴대폰에서 지문 인증을 완료해주세요.');
    } catch(e) {
      await api('/api/phone-pair/cancel','POST',{}).catch(()=>{});
      setError(true);const err=e as Error;
      setMessage(err.message||'QR 연결을 시작하지 못했습니다. 다시 시도하세요.');
    } finally {setBusy(false);}
  }
  async function cancelPair(){setPair(null);setMessage('휴대폰 연결을 취소했습니다.');setError(false);await api('/api/phone-pair/cancel','POST',{}).catch(()=>{});}
  async function managerAuthenticate(register:boolean) {
    setBusy(true);setMessage('');setError(false);
    try {
      if(!supported)throw new Error('HTTPS 공개 주소에서 다시 열어주세요.');
      if(!managerReady)throw new Error('먼저 Bitwarden 확장에 로그인하고 패스키 사용 설정을 확인해주세요.');
      if(register&&!user)throw new Error('휴대폰 패스키로 먼저 로그인해주세요.');
      const {startRegistration,startAuthentication,browserSupportsWebAuthn}=await import('@simplewebauthn/browser');
      if(!browserSupportsWebAuthn())throw new Error('Bitwarden 확장을 설치한 Chrome 또는 Edge에서 열어주세요.');
      const prefix=register?'register':'login';
      const options=await api('/api/passkey/'+prefix+'-options','POST',{channel:'manager',handle,name:managerName,storage:'Bitwarden'});
      const credential=register?await startRegistration({optionsJSON:options.options}):await startAuthentication({optionsJSON:options.options});
      await api('/api/passkey/'+prefix+'-verify','POST',{flowId:options.flowId,credential});
      await refresh();setMessage(register?'Bitwarden 예비 패스키를 등록했습니다. 휴대폰 없이도 이 키로 로그인할 수 있습니다.':'Bitwarden 패스키로 인증했습니다. 비공개 공간이 열렸습니다.');
    }catch(e){await api('/api/passkey/cancel','POST',{}).catch(()=>{});const err=e as Error;setError(true);setMessage(err.name==='NotAllowedError'||err.name==='AbortError'?'패스키 인증을 취소했거나 시간이 지났습니다. Bitwarden 확장에 로그인한 뒤 다시 시도하세요.':err.name==='InvalidStateError'?'이미 등록한 패스키입니다. Bitwarden에 새 키를 따로 저장해주세요.':err.message||'Bitwarden 패스키를 확인하지 못했습니다.');}
    finally{setBusy(false);}
  }
  function managerGuide() {
    return <div className="manager-guide">
      <p>Bitwarden 확장을 설치한 <strong>Chrome 또는 Edge</strong>에서 사용하세요. 보관함 비밀번호와 이메일 인증 코드는 Bitwarden 쪽에서 확인합니다.</p>
      <div className="manager-links"><a href="https://bitwarden.com/download/" target="_blank" rel="noopener noreferrer">Bitwarden 설치 안내 ↗</a><a href="https://bitwarden.com/help/setup-two-step-login-email/" target="_blank" rel="noopener noreferrer">이메일 인증 설정 ↗</a></div>
      <label className="manager-ready"><input type="checkbox" checked={managerReady} onChange={e=>setManagerReady(e.target.checked)} disabled={busy}/><span>이 브라우저의 Bitwarden 확장에 로그인했고, 패스키 저장·사용을 켰어요.</span></label>
      <small>Bitwarden 화면에서 진행하세요. 확장이 응답하지 않으면 브라우저의 Windows 보안창이 나타날 수 있으므로, 먼저 확장 설정을 확인해주세요.</small>
    </div>;
  }
  async function logout() {
    setBusy(true);try {await api('/api/passkey/logout','POST',{});setUser(null);setNotes([]);setKeys([]);setEditing(null);setMessage('로그아웃했습니다. 비공개 공간이 잠겼습니다.');setError(false);}catch(e){setMessage((e as Error).message);setError(true);}finally{setBusy(false);}
  }
  async function remove() {
    if(!deleting)return;setBusy(true);
    try {const result=await api('/api/passkey/delete-key','POST',{id:deleting});setDeleting(null);await refresh();setMessage(result.remaining===0?'마지막 패스키를 삭제했습니다. 이 계정으로 다시 들어올 수 없습니다. 새 계정은 다른 별명으로 만드세요.':result.loggedOut?'사용 중인 패스키를 삭제해 로그아웃했습니다. 남은 패스키로 다시 들어오세요.':'패스키를 삭제했습니다. 남은 패스키로 들어올 수 있습니다.');setError(false);}catch(e){setMessage((e as Error).message);setError(true);}finally{setBusy(false);}
  }
  async function saveNote() {if(!editing)return;setBusy(true);try{await api('/api/private-notes','PATCH',editing);setEditing(null);await refresh();setMessage('노트를 저장했습니다.');setError(false);}catch(e){setMessage((e as Error).message);setError(true);}finally{setBusy(false);}}
  function download() {
    const contents={description:'브라우저에서 직접 수행한 요청·응답 기록. 쿠키와 세션 토큰은 수집하지 않음. 노트 내용은 가상 자료.',generatedAt:new Date().toISOString(),entries:audit};
    const link=document.createElement('a');link.href=URL.createObjectURL(new Blob([JSON.stringify(contents,null,2)],{type:'application/json'}));link.download='T08-직접확인기록.json';link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);
  }
  return <main className="private-page">
    <nav className="private-nav"><a href="/"><ArrowLeft size={17}/> 공개 소개로 돌아가기</a><span><LockKeyhole size={16}/> 비공개 공간</span></nav>
    <header className="private-header"><p className="eyebrow">PRIVATE NOTES</p><h1>나만의 준비 공간</h1><p>프로젝트를 준비하고, 다음 걸음을 적어두는 자리.</p><span className={`lock-badge ${user?'open':''}`}><LockKeyhole size={15}/>{user?'패스키 인증 완료':'패스키로 잠겨 있어요'}</span></header>
    {message&&<p role={error?'alert':'status'} className={`private-message ${error?'error':''}`}>{message}</p>}
    {pair&&<dialog ref={qrDialog} className="qr-dialog" aria-modal="true" aria-labelledby="qr-popup-title" aria-describedby="qr-popup-description" onCancel={e=>{e.preventDefault();void cancelPair();}} onClick={e=>{if(e.target!==e.currentTarget)return;const box=e.currentTarget.getBoundingClientRect();if(e.clientX<box.left||e.clientX>box.right||e.clientY<box.top||e.clientY>box.bottom)void cancelPair();}}>
      <div className="qr-popup-card">
        <button className="qr-popup-close" type="button" aria-label="QR 팝업 닫기" onClick={cancelPair} autoFocus><X size={22}/></button>
        <span className="qr-popup-icon"><Smartphone size={24}/></span><p className="eyebrow">PHONE CONNECT</p>
        <h2 id="qr-popup-title">휴대폰으로 스캔하세요</h2>
        <p id="qr-popup-description">휴대폰 카메라로 QR을 스캔하고<br/>열린 페이지에서 지문을 확인해주세요.</p>
        <img src={pair.qr} width={280} height={280} alt="휴대폰 지문 인증 페이지로 연결하는 일회용 QR코드"/>
        <p className="qr-popup-waiting" role="status"><span/>휴대폰 인증을 기다리고 있어요</p>
        <p className="qr-popup-expiry">{new Date(pair.expiresAt).toLocaleTimeString('ko-KR',{hour:'2-digit',minute:'2-digit',timeZone:'Asia/Seoul'})}까지 유효 · 한 번만 사용할 수 있어요</p>
        <button className="private-secondary" type="button" onClick={cancelPair}>연결 취소</button>
      </div>
    </dialog>}
    {loading?<section className="private-card"><p role="status">로그인 상태를 확인하고 있습니다…</p></section>:!user?<section className="private-card auth-card">
      <div className="auth-symbol">{mode==='login'&&loginMethod==='manager'?<ShieldCheck size={42}/>:<Fingerprint size={42}/>}</div><h2>{mode==='login'&&loginMethod==='manager'?'휴대폰 없이 예비 키로 들어오세요':'휴대폰 지문으로 들어오세요'}</h2><p>{mode==='login'&&loginMethod==='manager'?'같은 계정에 미리 등록한 Bitwarden 패스키로 이 공간을 엽니다.':'휴대폰에 저장한 패스키로 이 공간을 엽니다.'}</p>
      {(mode==='signup'||loginMethod==='phone')&&<ol className="phone-steps"><li><Smartphone size={17}/><span><strong>QR코드 띄우기</strong>아래에 별명을 입력하고 QR코드 버튼을 누르세요.</span></li><li><span className="step-digit">2</span><span><strong>휴대폰 카메라로 스캔</strong>PC와 휴대폰이 인터넷에 연결되어 있으면 됩니다.</span></li><li><Fingerprint size={17}/><span><strong>휴대폰에서 지문 확인</strong>휴대폰에 열린 페이지에서 인증하면 PC 화면이 열립니다.</span></li></ol>}
      {!supported&&<p role="alert" className="private-message error">HTTPS 공개 주소에서 이 페이지를 열어주세요.</p>}
      <div className="auth-tabs"><button type="button" aria-pressed={mode==='login'} onClick={()=>setMode('login')}>등록한 휴대폰으로 들어가기</button><button type="button" aria-pressed={mode==='signup'} onClick={()=>setMode('signup')}>휴대폰 처음 연결하기</button></div>
      {mode==='login'&&<div className="login-methods" aria-label="로그인할 패스키 선택"><button type="button" aria-pressed={loginMethod==='phone'} disabled={busy||!!pair} onClick={()=>setLoginMethod('phone')}><Smartphone size={18}/>휴대폰 QR</button><button type="button" aria-pressed={loginMethod==='manager'} disabled={busy||!!pair} onClick={()=>setLoginMethod('manager')}><ShieldCheck size={18}/>Bitwarden 예비 키</button></div>}
      <form onSubmit={e=>{e.preventDefault();if(mode==='login'&&loginMethod==='manager')void managerAuthenticate(false);else void authenticate(mode==='signup');}}>
        <label htmlFor="handle">내 계정 별명</label><input id="handle" value={handle} onChange={e=>setHandle(e.target.value)} autoComplete="username webauthn" required minLength={2} maxLength={24} placeholder="예: 찬원노트" disabled={busy}/>
        <small>실제 연락처 대신 기억할 수 있는 별명을 써주세요.</small>
        {mode==='signup'&&<><label htmlFor="key-name">패스키 이름</label><input id="key-name" value={keyName} onChange={e=>setKeyName(e.target.value)} required maxLength={60} disabled={busy}/><label htmlFor="storage">이번에 저장할 위치</label><select id="storage" value={storage} onChange={e=>setStorage(e.target.value)} disabled={busy}>{locations.map(l=><option key={l}>{l}</option>)}</select><small>기기 인증창에서 선택한 실제 위치와 맞춰주세요.</small></>}
        {mode==='login'&&loginMethod==='manager'?<>{managerGuide()}<button className="private-primary" type="submit" disabled={busy||!supported||!!pair||!managerReady}><ShieldCheck size={19}/>{busy?'Bitwarden에서 인증해주세요…':'Bitwarden 패스키로 들어가기'}</button></>:<><button className="private-primary" type="submit" disabled={busy||!supported||!!pair}><Smartphone size={19}/>{busy?'QR코드를 준비하고 있습니다…':mode==='signup'?'휴대폰 등록 QR코드 띄우기':'휴대폰 로그인 QR코드 띄우기'}</button><small className="biometric-note">QR 방식은 PC의 Windows 보안창을 호출하지 않습니다. 휴대폰 설정에 따라 지문·얼굴·PIN으로 확인합니다.</small></>}
      </form><div className="lost-note"><strong>기기를 잃어버렸나요?</strong><p>미리 등록한 Bitwarden 예비 키로 들어오세요. Bitwarden에 이메일 인증을 설정해두면 관리자 비밀번호와 이메일 코드로 보관함에 다시 로그인할 수 있습니다. 모든 키를 사이트에서 삭제했다면 보관함에 키가 남아 있어도 사용할 수 없습니다.</p></div>
    </section>:<>
      <div className="private-account"><div><strong>{user.handle}</strong><span>이 계정의 노트 {notes.length}개</span></div><button className="private-secondary" disabled={busy} onClick={logout}><LogOut size={16}/> 로그아웃</button></div>
      <p className="fiction-note">여기에 처음 들어 있는 내용은 과제 확인용 가상 자료입니다. 실제 연락처·신분증 번호·비밀키를 적지 마세요.</p>
      <section className="private-notes" aria-label="내 비공개 노트">{notes.map((n,i)=><article className="private-card note-card" key={n.id}><span className="note-number">0{i+1}</span><h2>{n.title}</h2><p>{n.content}</p><button className="private-secondary" disabled={busy} onClick={()=>setEditing(n)}>노트 수정</button></article>)}</section>
      {editing&&<section className="private-card edit-note"><h2>노트 수정</h2><label htmlFor="note-title">제목</label><input id="note-title" value={editing.title} maxLength={80} onChange={e=>setEditing({...editing,title:e.target.value})}/><label htmlFor="note-content">내용</label><textarea id="note-content" value={editing.content} maxLength={2000} onChange={e=>setEditing({...editing,content:e.target.value})}/><div className="private-actions"><button className="private-primary" disabled={busy} onClick={saveNote}>저장하기</button><button className="private-secondary" onClick={()=>setEditing(null)}>취소</button></div></section>}
      <section className="private-card key-panel"><div className="key-panel-heading"><KeyRound size={24}/><div><h2>내 패스키</h2><p>기기를 잃어버려도 들어올 수 있도록 두 개를 등록해두세요.</p></div></div>
        <ul className="key-list">{keys.map(k=><li key={k.id}><div><strong>{k.name}</strong><span>{k.storage} · {new Date(k.created_at).toLocaleDateString('ko-KR',{timeZone:'Asia/Seoul'})} 등록</span><details><summary>서버에 저장된 공개키 확인</summary><code>{k.public_key}</code><p>개인키는 패스키 관리자가 보관합니다. 이 서버에는 공개키만 저장됩니다.</p></details></div><button className="key-delete" disabled={busy} onClick={()=>setDeleting(k.id)}>삭제</button></li>)}</ul>
        {deleting&&<div className="delete-confirm" role="alert"><strong>이 패스키를 삭제할까요?</strong><p>{keys.length===1?'마지막 패스키입니다. 삭제하면 계정으로 다시 들어올 수 없습니다. 먼저 두 번째 패스키를 등록하는 것을 권합니다.':'삭제한 패스키는 이 사이트에서 사용할 수 없습니다. 사용 중인 패스키라면 로그아웃됩니다.'}</p><div className="private-actions"><button className="key-delete" disabled={busy} onClick={remove}>삭제 확인</button><button className="private-secondary" onClick={()=>setDeleting(null)}>취소</button></div></div>}
        <form className="add-key manager-add" onSubmit={e=>{e.preventDefault();void managerAuthenticate(true);}}><h3><ShieldCheck size={20}/> Bitwarden 예비 패스키 등록</h3><p>휴대폰 키와 다른 새 키를 Bitwarden 보관함에 저장합니다. 같은 계정의 노트에 들어오는 두 번째 열쇠입니다.</p><label htmlFor="manager-key-name">예비 패스키 이름</label><input id="manager-key-name" value={managerName} required maxLength={60} onChange={e=>setManagerName(e.target.value)} disabled={busy}/>{managerGuide()}<button className="private-primary" disabled={busy||!supported||!!pair||!managerReady}><Plus size={18}/>{busy?'Bitwarden에 저장해주세요…':'Bitwarden에 예비 패스키 저장'}</button><small>실제 저장 위치를 확인한 뒤 등록해주세요. 저장 위치는 사용자가 확인한 값으로 기록됩니다.</small></form>
        <details className="extra-phone-key"><summary>다른 휴대폰 키도 추가하려면</summary><form className="add-key" onSubmit={e=>{e.preventDefault();authenticate(true);}}><label htmlFor="second-key">패스키 이름</label><input id="second-key" value={keyName} required maxLength={60} onChange={e=>setKeyName(e.target.value)} disabled={busy}/><label htmlFor="second-storage">이번에 저장할 위치</label><select id="second-storage" value={storage} onChange={e=>setStorage(e.target.value)} disabled={busy}>{locations.map(l=><option key={l}>{l}</option>)}</select><button className="private-secondary" disabled={busy||!supported||!!pair}><Smartphone size={17}/>휴대폰 등록 QR코드 띄우기</button></form></details>
      </section>
    </>}
    <footer className="private-footer"><span>공개 소개는 누구나 볼 수 있고, 이 공간은 패스키로 인증한 계정만 볼 수 있습니다.</span><button className="private-secondary" onClick={download} disabled={!audit.length}><Download size={16}/> 이번 확인 기록 다운로드</button></footer>
  </main>;
}
