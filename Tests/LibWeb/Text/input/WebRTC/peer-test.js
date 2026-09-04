function rtcTest(body) {
    promiseTest(() => body().catch(error => println(`FAIL: ${error}`)));
}

function check(value, message) {
    if (!value)
        throw new Error(message);
    println(`PASS: ${message}`);
}

function deadline(promise, description) {
    let timer;
    return Promise.race([
        promise,
        new Promise((_, reject) => timer = setTimeout(() => reject(new Error(`Timed out: ${description}`)), 10000)),
    ]).finally(() => clearTimeout(timer));
}

function nextEvent(target, type) {
    return deadline(new Promise(resolve => target.addEventListener(type, resolve, { once: true })), type);
}

function opened(channel) {
    return channel.readyState === "open" ? Promise.resolve() : nextEvent(channel, "open");
}

function peerPair() {
    const left = new RTCPeerConnection();
    const right = new RTCPeerConnection();
    const errors = [];
    const pending = new Map([[left, []], [right, []]]);
    const ready = new Set();
    for (const [source, target] of [[left, right], [right, left]]) {
        source.onicecandidate = event => {
            if (!event.candidate)
                return;
            const candidate = event.candidate.toJSON();
            if (ready.has(target))
                target.addIceCandidate(candidate).catch(error => errors.push(error));
            else
                pending.get(target).push(candidate);
        };
    }
    async function remote(target, description) {
        await target.setRemoteDescription(description);
        ready.add(target);
        for (const candidate of pending.get(target).splice(0))
            await target.addIceCandidate(candidate);
    }
    return {
        left, right,
        async negotiate() {
            await deadline((async () => {
                const offer = await left.createOffer();
                await left.setLocalDescription(offer);
                await remote(right, offer);
                const answer = await right.createAnswer();
                await right.setLocalDescription(answer);
                await remote(left, answer);
            })(), "offer/answer exchange");
        },
        checkICE() {
            if (errors.length)
                throw errors[0];
        },
        close() {
            left.onicecandidate = right.onicecandidate = null;
            left.close();
            right.close();
        },
    };
}

async function dataPair(pair) {
    const remote = nextEvent(pair.right, "datachannel");
    const local = pair.left.createDataChannel("test");
    await pair.negotiate();
    const incoming = (await remote).channel;
    await Promise.all([opened(local), opened(incoming)]);
    return [local, incoming];
}

async function bytes(data) {
    return new Uint8Array(data instanceof Blob ? await data.arrayBuffer() : data);
}
