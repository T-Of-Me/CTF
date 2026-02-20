      const base = "http://localhost:5000"; // domain app thật
      let sid = null;

      // 1. Lấy SID
      fetch(base + "/socket.io/", {credentials: "include"})
        .then(r => r.text())
        .then(txt => {
          sid = txt.split('"sid":"')[1].split('"')[0];
          console.log("SID=", sid);

          // 2. Handshake
          fetch(base + "/socket.io/?EIO=3&transport=polling&sid=" + sid, {
            method: "POST",
            credentials: "include",
            body: "8:40/"
          }).then(() => {
            console.log("Handshake done");

            // 3. Join game room (giả sử code=ABCD12)
            let payload = genPayload('["join",{}]');
            fetch(base + "/socket.io/?EIO=3&transport=polling&sid=" + sid, {
              method: "POST",
              credentials: "include",
              body: payload
            });
          });
        });

      function genPayload(body) {
        let data = "42/" + body;
        return data.length + ":" + data;
      }