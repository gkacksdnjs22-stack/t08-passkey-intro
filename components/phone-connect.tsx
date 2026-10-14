'use client';
import { useEffect,useState } from 'react';
import { startAuthentication,startRegistration,browserSupportsWebAuthn } from '@simplewebauthn/browser';
import { Fingerprint,CheckCircle2,Smartphone } from 'lucide-react';
type Info={handle:string;mode:string;name:string;storage:string};
export default function PhoneConnect(){
  const [ticket,setTicket]=useState(''),[info,setInfo]=useState<Info|null>(null),[busy,setBusy]=useState(false),[done,setDone]=useState(false),[message,setMessage]=useState('연결 정보를 확인하고 있습니다…'),[supported,setSupported]=useState(true);
  async function api(path:string,input:unknown){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',cache:'no-store',body:JSON.stringify(input)});const d:any=await r.json();if(!r.ok)throw new Error(d.error||'연결하지 못했습니다.');return d;}
  useEffect(()=>{
    const value=new URLSearchParams(location.hash.slice(1)).get('ticket')??'';setTicket(value);setSupported(browserSupportsWebAuthn()&&window.isSecureContext);
    if(!value){setMessage('PC에서 띄운 QR코드를 휴대폰으로 스캔해주세요.');return;}
    api('/api/phone-pair/info',{pairTicket:value}).then(d=>{setInfo(d);setMessage('내가 시작한 PC 연결인지 확인하고 인증해주세요.');}).catch(e=>setMessage(e.message));
  },[]);
  async function approve(){
    if(!info)return;setBusy(true);setMessage('휴대폰에서 지문 인증을 완료해주세요.');
    try{
      const register=info.mode!=='login';const o=await api(`/api/passkey/${register?'register':'login'}-options`,{pairTicket:ticket});
      const credential=register?await startRegistration({optionsJSON:o.options}):await startAuthentication({optionsJSON:o.options});
      await api(`/api/passkey/${register?'register':'login'}-verify`,{flowId:o.flowId,credential});
      setDone(true);setMessage('인증했습니다. PC의 비공개 공간이 곧 열립니다.');
      history.replaceState(null,'','/phone-connect');setTicket('');
    }catch(e){await api('/api/passkey/cancel',{}).catch(()=>{});const err=e as Error;setMessage(err.name==='NotAllowedError'||err.name==='AbortError'?'인증을 취소했거나 시간이 지났습니다. 다시 시도할 수 있습니다.':err.name==='InvalidStateError'?'이미 이 휴대폰에 등록된 패스키입니다. 다른 휴대폰 또는 패스키 저장 위치를 사용하세요.':err.message);}
    finally{setBusy(false);}
  }
  return <main className="phone-page"><a href="/">함찬원의 공개 소개</a><section className="private-card phone-card"><div className="auth-symbol">{done?<CheckCircle2 size={42}/>:<Smartphone size={42}/>}</div><p className="eyebrow">PHONE AUTHENTICATION</p><h1>{done?'PC 연결을 인증했어요':'휴대폰 지문으로 인증'}</h1><p role="status">{message}</p>{info&&!done&&<><div className="phone-account"><strong>{info.handle}</strong><span>{info.mode==='login'?'등록한 패스키로 PC 로그인':info.mode==='add'?'이 계정에 예비 패스키 추가':'새 계정의 첫 패스키 등록'}</span>{info.mode!=='login'&&<small>{info.name} · {info.storage}</small>}</div><p className="phone-warning">직접 시작한 PC의 QR코드일 때만 인증해주세요.</p>{!supported&&<p role="alert" className="private-message error">휴대폰의 Chrome 또는 Safari에서 열어주세요. 패스키를 지원하는 휴대폰과 화면 잠금 설정이 필요합니다.</p>}<button className="private-primary" disabled={busy||!supported} onClick={approve}><Fingerprint size={20}/>{busy?'지문 인증을 기다리고 있습니다…':info.mode==='login'?'지문으로 PC 로그인 승인':'지문으로 패스키 등록'}</button><small>지문 정보는 휴대폰에서 처리됩니다. 휴대폰 설정에 따라 얼굴·PIN 확인도 제공될 수 있습니다.</small></>}{done&&<a className="private-secondary" href="/private">휴대폰에서도 내 노트 열기</a>}</section></main>;
}
