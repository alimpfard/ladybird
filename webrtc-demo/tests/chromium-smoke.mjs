const tabs = await (await fetch((process.env.CDP_URL || 'http://127.0.0.1:9223') + '/json')).json();
const tab = tabs.find(t => t.type === 'page');
const ws = new WebSocket(tab.webSocketDebuggerUrl);
await new Promise(resolve => ws.addEventListener('open', resolve, { once: true }));
let id = 0;
const pending = new Map();
ws.addEventListener('message', event => {
  const msg = JSON.parse(event.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  }
});
function call(method, params = {}) {
  return new Promise((resolve, reject) => { const n = ++id; pending.set(n, { resolve, reject }); ws.send(JSON.stringify({ id: n, method, params })); });
}
async function evaluate(expression) {
  const r = await call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
  return r.result.value;
}
async function until(expression, ms = 40000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await evaluate(expression)) return;
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error('Timed out: ' + expression + '\n' + await evaluate('document.getElementById("log").textContent'));
}
try {
  await call('Page.navigate', { url: process.env.ECHO_URL || 'https://apps.cxbyte.me/webrtc/' });
  await until('typeof start === "function"');
  for (const [mode, rate] of [['tone','48000'], ['tone','44100'], ['none','48000']]) {
    await evaluate(`document.getElementById('clear').click(); document.getElementById('source').value=${JSON.stringify(mode)}; document.getElementById('rate').value=${JSON.stringify(rate)}; document.getElementById('start').click()`);
    await until('!document.getElementById("send").disabled');
    if (mode === 'tone') await until('document.getElementById("log").textContent.includes("PASS: non-silent audio")');
    await evaluate('document.getElementById("message").value="smoke echo 123"; document.getElementById("send").click()');
    await until('document.getElementById("echo").textContent.includes("smoke echo 123")');
    await evaluate('document.getElementById("binary").click()');
    await until('document.getElementById("log").textContent.includes("PASS: binary echo matches")');
    console.log('PASS', mode, rate, 'text and binary echo', mode === 'tone' ? 'and returned audio' : '');
    await evaluate('stop()');
    await until('!document.getElementById("start").disabled');
  }

} finally { ws.close(); }
