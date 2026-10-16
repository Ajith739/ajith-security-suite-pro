/* Native login form integration; WordPress retains the final authentication pipeline. */
(() => {
 'use strict';
 const form=document.getElementById('loginform'),cfg=window.GWQSH_LOGIN;
 if(!form || !cfg) return;
 const encode=buffer=>btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
 const post=async(action,data)=>{const r=await fetch(cfg.url,{method:'POST',body:new URLSearchParams({action,nonce:cfg.nonce,...data})});const j=await r.json();if(!j.success)throw new Error(j.data?.message || 'Authentication failed.');return j.data;};
 const status=document.createElement('p');status.setAttribute('role','status');status.style.cssText='line-height:1.5;margin:12px 0';form.append(status);
 if(cfg.passkeys && window.isSecureContext && navigator.credentials){
  const button=document.createElement('button');button.type='button';button.className='button button-secondary';button.textContent='Sign in with a passkey';button.style.marginTop='12px';form.append(button);
  button.addEventListener('click',async()=>{
   button.disabled=true;status.textContent='';
   try{
    const username=form.querySelector('#user_login').value.trim();if(!username)throw new Error('Enter your username first.');
    const issued=await post('gwqsh_passkey_login',{operation:'options',username});const options=issued.options;
    options.publicKey.challenge=decode(options.publicKey.challenge);options.publicKey.allowCredentials.forEach(x=>x.id=decode(x.id));
    const credential=await navigator.credentials.get(options);
    const result=await post('gwqsh_passkey_login',{operation:'verify',token:issued.token,id:encode(credential.rawId),clientDataJSON:encode(credential.response.clientDataJSON),authenticatorData:encode(credential.response.authenticatorData),signature:encode(credential.response.signature)});
    const ticket=document.createElement('input');ticket.type='hidden';ticket.name='gwqsh_passkey_ticket';ticket.value=result.ticket;form.append(ticket);
    form.querySelector('#user_login').value=result.username;form.querySelectorAll('input[type=password]').forEach(x=>{x.value='';x.required=false;});form.querySelector('[name=gwqsh_2fa_challenge]')?.remove();form.submit();
   }catch(error){status.textContent=error.name==='NotAllowedError'?'Passkey request cancelled or unavailable.':error.message;}finally{button.disabled=false;}
  });
 }
 const challenge=form.querySelector('[name=gwqsh_2fa_challenge]');
 if(challenge){
  ['email','sms'].forEach(method=>{
   const button=document.createElement('button');button.type='button';button.className='button button-secondary';button.textContent='Send '+method.toUpperCase()+' backup code';button.style.margin='10px 6px 0 0';form.append(button);
   button.addEventListener('click',async()=>{button.disabled=true;try{const result=await post('gwqsh_recovery_send',{challenge:challenge.value,method});status.textContent=result.message;form.querySelector('#gwqsh_2fa_code')?.focus();setTimeout(()=>button.disabled=false,60000);}catch(error){status.textContent=error.message;button.disabled=false;}});
  });
 }
})();
