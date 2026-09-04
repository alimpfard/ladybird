const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const code = fs.readFileSync(require('node:path').join(__dirname, '../public/app.js'), 'utf8');

function harness({ attachError = false } = {}) {
    const elements = new Map();
    const element = id => {
        if (!elements.has(id)) elements.set(id, { value: '', textContent: '', disabled: false, checked: false });
        return elements.get(id);
    };
    element('source').value = 'none';
    element('ice').value = '[]';
    element('endpoint').value = './janus';
    const calls = [];
    const peers = [];
    let pendingPoll;
    const events = [];
    const emit = event => {
        if (pendingPoll) { const resolve = pendingPoll; pendingPoll = null; resolve(event); }
        else events.push(event);
    };
    class Peer {
        constructor() {
            this.connectionState = 'new';
            this.sent = [];
            peers.push(this);
        }
        addEventListener() {}
        createDataChannel() { return this.channel = { send: data => this.sent.push(data) }; }
        async createOffer() { return { type: 'offer', sdp: 'test-offer' }; }
        async setLocalDescription(offer) {
            this.local = offer;
            this.onicecandidate({ candidate: { toJSON: () => ({ candidate: 'test-candidate', sdpMid: '0' }) } });
            this.onicecandidate({ candidate: null });
        }
        async setRemoteDescription(answer) { this.remote = answer; }
        async addIceCandidate(candidate) { this.candidate = candidate; }
        close() { this.closed = true; }
    }
    const context = vm.createContext({
        console, URL, Blob, AbortController, setTimeout, clearTimeout, setInterval, clearInterval,
        document: { getElementById: element },
        window: { addEventListener() {} },
        location: { href: 'https://apps.cxbyte.me/webrtc/' },
        navigator: {}, RTCPeerConnection: Peer,
        fetch: async (url, options) => {
            const body = options.body && JSON.parse(options.body);
            calls.push({ url, body });
            let data;
            if (!body) {
                data = events.length ? events.shift() : await new Promise((resolve, reject) => {
                    pendingPoll = resolve;
                    options.signal.addEventListener('abort', () => { pendingPoll = null; reject(new Error('aborted')); }, { once: true });
                });
            } else if (body.janus === 'create') data = { janus: 'success', data: { id: 123 } };
            else if (body.janus === 'attach') data = attachError
                ? { janus: 'error', error: { code: 460, reason: 'plugin unavailable' } }
                : { janus: 'success', data: { id: 456 } };
            else {
                data = { janus: 'ack' };
                if (body.janus === 'message') emit({ janus: 'event', jsep: { type: 'answer', sdp: 'test-answer' } });
            }
            return { ok: true, json: async () => data };
        },
    });
    vm.runInContext(code, context);
    return { context, calls, peers, element, emit };
}
const tick = () => new Promise(resolve => setImmediate(resolve));

test('subpath signaling, trickle ICE, answer, data echo, disconnect and reconnect', async () => {
    const h = harness();
    try {
        await h.context.start();
        await tick();
        const peer = h.peers[0];
        assert.equal(h.calls[0].url, 'https://apps.cxbyte.me/webrtc/janus');
        assert.equal(peer.remote.sdp, 'test-answer');
        const trickle = h.calls.filter(call => call.body?.janus === 'trickle');
        assert.equal(trickle.length, 2);
        assert.equal(trickle[0].body.candidate.candidate, 'test-candidate');
        assert.equal(trickle[1].body.candidate.completed, true);
        assert.equal(h.calls.find(call => call.body?.janus === 'message').body.body.audio, false);
        peer.channel.onopen();
        assert.equal(h.element('send').disabled, false);
        h.element('message').value = 'hello';
        h.element('send').onclick();
        assert.equal(peer.sent[0], 'hello');
        await peer.channel.onmessage({ data: 'Janus EchoTest here! You wrote: hello' });
        assert.match(h.element('echo').textContent, /hello/);
        await h.context.stop();
        assert.equal(peer.closed, true);
        assert.ok(h.calls.some(call => call.body?.janus === 'destroy'));
        assert.equal(h.element('start').disabled, false);
        await h.context.start();
        assert.equal(h.peers.length, 2);
    } finally { await h.context.stop(); }
});

test('failed attach destroys the allocated session and permits retry', async () => {
    const h = harness({ attachError: true });
    await h.context.start();
    await tick();
    assert.ok(h.calls.some(call => call.body?.janus === 'destroy'));
    assert.match(h.element('status').textContent, /plugin unavailable/);
    assert.equal(h.element('start').disabled, false);
});

test('invalid connection options fail without allocating a session', async () => {
    const h = harness();
    h.element('ice').value = '{}';
    await h.context.start();
    await tick();
    assert.equal(h.calls.length, 0);
    assert.match(h.element('status').textContent, /JSON array/);
    assert.equal(h.element('start').disabled, false);
});
