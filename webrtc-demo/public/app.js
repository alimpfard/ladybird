/* A deliberately small Janus REST client, usable while browser APIs are incomplete. */
const $ = id => document.getElementById(id);
let active = null;
let sequence = 0;
const lines = [];
function log(message, detail) {
    const text = `${new Date().toISOString()} ${message}${detail === undefined ? "" : "\n" + JSON.stringify(detail, null, 2)}`;
    lines.push(text);
    if (lines.length > 500) lines.shift();
    $("log").textContent = lines.join("\n");
    $("log").scrollTop = $("log").scrollHeight;
}
function transaction() { return `echo-${Date.now()}-${++sequence}`; }

async function request(run, path, body, cleanup = false) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (!cleanup) {
        if (run.abort.signal.aborted) controller.abort();
        run.abort.signal.addEventListener("abort", abort, { once: true });
    }
    const timer = setTimeout(abort, cleanup ? 3000 : 40000);
    try {
        const response = await fetch(run.endpoint + path, {
            method: body ? "POST" : "GET",
            headers: body ? { "Content-Type": "application/json" } : {},
            body: body ? JSON.stringify({ ...body, transaction: transaction() }) : undefined,
            cache: "no-store",
            signal: controller.signal,
        });
        if (!response.ok) throw new Error(`Janus HTTP ${response.status}`);
        const data = await response.json();
        if (data.janus === "error") throw new Error(`Janus ${data.error.code}: ${data.error.reason}`);
        return data;
    } finally {
        clearTimeout(timer);
        run.abort.signal.removeEventListener("abort", abort);
    }
}

async function poll(run) {
    while (active === run) {
        const response = await request(run, `/${run.session}?rid=${Date.now()}&maxev=10`);
        for (const event of Array.isArray(response) ? response : [response]) {
            if (active !== run) return;
            if (event.janus !== "keepalive") log(`Janus ${event.janus}`, event);
            if (event.plugindata?.data?.error) throw new Error(event.plugindata.data.error);
            if (event.jsep) {
                await run.pc.setRemoteDescription(event.jsep);
                run.remoteReady = true;
                for (const candidate of run.remoteCandidates.splice(0)) await run.pc.addIceCandidate(candidate);
            }
            if (event.janus === "trickle" && event.candidate && !event.candidate.completed) {
                if (run.remoteReady) await run.pc.addIceCandidate(event.candidate);
                else run.remoteCandidates.push(event.candidate);
            }
            if (event.janus === "hangup" || event.janus === "detached" || event.janus === "timeout")
                throw new Error(event.reason || `Server ${event.janus}`);
        }
    }
}

function fail(run, error) {
    if (active !== run) return;
    log("ERROR", String(error));
    void stop(`Failed: ${error.message || error}`);
}

async function start() {
    if (active) return;
    const run = {
        abort: new AbortController(), tracks: [], contexts: [], remoteCandidates: [],
    };
    active = run;
    $("start").disabled = true;
    $("stop").disabled = false;
    $("status").textContent = "Connecting…";
    $("echo").textContent = "No echo yet";
    try {
        run.endpoint = new URL($("endpoint").value, location.href).href.replace(/\/$/, "");
        const iceServers = JSON.parse($("ice").value);
        if (!Array.isArray(iceServers)) throw new Error("ICE servers must be a JSON array");
        const mode = $("source").value;
        // Resume from the button's user activation, before network requests.
        if (mode !== "none") {
            run.receiving = new AudioContext({ sampleRate: 48000 });
            run.contexts.push(run.receiving);
            await run.receiving.resume();
        }
        if (active !== run) return;
        if (mode === "tone") {
            const context = new AudioContext({ sampleRate: Number($("rate").value) });
            run.contexts.push(context);
            const oscillator = new OscillatorNode(context, { frequency: 440 });
            const gain = new GainNode(context, { gain: 0.15 });
            const destination = context.createMediaStreamDestination();
            oscillator.connect(gain).connect(destination);
            oscillator.start();
            run.stream = destination.stream;
            run.tracks.push(...run.stream.getTracks());
            await context.resume();
        } else if (mode === "microphone") {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
            if (active !== run) { stream.getTracks().forEach(track => track.stop()); return; }
            run.stream = stream;
            run.tracks.push(...stream.getTracks());
        }
        if (active !== run) return;
        const created = await request(run, "", { janus: "create" });
        run.session = created.data.id;
        const attached = await request(run, `/${run.session}`, { janus: "attach", plugin: "janus.plugin.echotest" });
        run.handle = attached.data.id;
        if (active !== run) return;
        const pc = run.pc = new RTCPeerConnection({ iceServers });
        for (const name of ["connectionstatechange", "iceconnectionstatechange", "icegatheringstatechange", "signalingstatechange"]) {
            pc.addEventListener(name, () => {
                if (active !== run) return;
                log(name, { connection: pc.connectionState, ice: pc.iceConnectionState, gathering: pc.iceGatheringState, signaling: pc.signalingState });
                $("status").textContent = `Connection: ${pc.connectionState}; ICE: ${pc.iceConnectionState}`;
                if (pc.connectionState === "connected") clearTimeout(run.connectTimer);
                if (pc.connectionState === "failed") fail(run, new Error("ICE connection failed; check the advertised public IP and UDP firewall"));
            });
        }
        pc.onicecandidate = event => {
            if (active !== run) return;
            const candidate = event.candidate ? event.candidate.toJSON() : { completed: true };
            log("Local ICE candidate", candidate);
            request(run, `/${run.session}/${run.handle}`, { janus: "trickle", candidate }).catch(error => fail(run, error));
        };
        pc.onicecandidateerror = event => log("ICE candidate error", { code: event.errorCode, text: event.errorText });
        pc.ontrack = event => {
            log("Remote track", { kind: event.track.kind, id: event.track.id });
            if (event.track.kind !== "audio" || !run.receiving) return;
            const context = run.receiving;
            const stream = new MediaStream([event.track]);
            // Keep a muted media-element consumer too: Chromium can otherwise leave
            // remote WebRTC playout idle while a Web Audio graph consumes the track.
            run.playout = new Audio();
            run.playout.muted = true;
            run.playout.srcObject = stream;
            run.playout.play().catch(error => log("Media element playback", String(error)));
            const source = context.createMediaStreamSource(stream);
            const analyser = new AnalyserNode(context, { fftSize: 2048 });
            run.volume = new GainNode(context, { gain: $("listen").checked ? 1 : 0 });
            source.connect(analyser).connect(run.volume).connect(context.destination);
            const samples = new Float32Array(analyser.fftSize);
            clearInterval(run.meter);
            let reported = false;
            run.meter = setInterval(() => {
                analyser.getFloatTimeDomainData(samples);
                const rms = Math.sqrt(samples.reduce((sum, value) => sum + value * value, 0) / samples.length);
                $("level").value = rms;
                $("rms").textContent = rms.toFixed(4);
                if (!reported && rms > 0.01) { reported = true; log("PASS: non-silent audio returned by Janus"); }
            }, 100);
        };
        if (run.stream) for (const track of run.stream.getAudioTracks()) pc.addTrack(track, run.stream);
        const channel = run.channel = pc.createDataChannel("echo");
        channel.onopen = () => {
            if (active !== run) return;
            log("Data channel open");
            $("send").disabled = $("binary").disabled = false;
        };
        channel.onclose = () => {
            if (active !== run) return;
            log("Data channel closed");
            $("send").disabled = $("binary").disabled = true;
        };
        channel.onerror = () => log("Data channel error");
        channel.onmessage = async event => {
            if (active !== run) return;
            if (typeof event.data === "string") {
                $("echo").textContent = event.data;
                log("Text echo", event.data);
            } else {
                const buffer = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
                const bytes = [...new Uint8Array(buffer)];
                $("echo").textContent = `Binary echo: ${bytes.join(", ")}`;
                log(bytes.join(",") === "0,1,127,128,255" ? "PASS: binary echo matches" : "Unexpected binary echo", bytes);
            }
        };
        void poll(run).catch(error => fail(run, error));
        const offer = await pc.createOffer();
        log("Local offer", offer);
        await pc.setLocalDescription(offer);
        await request(run, `/${run.session}/${run.handle}`, {
            janus: "message", body: { audio: mode !== "none", video: false }, jsep: { type: offer.type, sdp: offer.sdp },
        });
        if (active === run && pc.connectionState !== "connected")
            run.connectTimer = setTimeout(() => fail(run, new Error("Connection timed out after 30 seconds")), 30000);
    } catch (error) { fail(run, error); }
}

async function stop(status = "Disconnected") {
    const run = active;
    if (!run) return;
    active = null;
    run.abort.abort();
    clearTimeout(run.connectTimer);
    clearInterval(run.meter);
    run.pc?.close();
    if (run.playout) {
        run.playout.pause();
        run.playout.srcObject = null;
    }
    for (const track of run.tracks) track.stop();
    $("stop").disabled = $("send").disabled = $("binary").disabled = true;
    $("status").textContent = status;
    $("level").value = 0;
    $("rms").textContent = "0.0000";
    await Promise.allSettled(run.contexts.map(context => context.close()));
    if (run.session) {
        try { await request(run, `/${run.session}`, { janus: "destroy" }, true); }
        catch (error) { log("Session cleanup", String(error)); }
    }
    $("start").disabled = false;
    log("Disconnected");
}
$("start").onclick = () => void start();
$("stop").onclick = () => void stop();
$("listen").onchange = () => { if (active?.volume) active.volume.gain.value = $("listen").checked ? 1 : 0; };
$("send").onclick = () => {
    try { active.channel.send($("message").value); log("Sent text", $("message").value); }
    catch (error) { log("Send failed", String(error)); }
};
$("binary").onclick = () => {
    try { active.channel.send(new Uint8Array([0, 1, 127, 128, 255])); log("Sent binary probe"); }
    catch (error) { log("Send failed", String(error)); }
};
$("clear").onclick = () => { lines.length = 0; $("log").textContent = ""; };
$("download").onclick = () => {
    const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/plain" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "webrtc-echo.log";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
};
window.addEventListener("pagehide", () => {
    if (!active) return;
    // Best effort: Janus also expires abandoned sessions after 60 seconds.
    if (active.session) navigator.sendBeacon(`${active.endpoint}/${active.session}`, new Blob([
        JSON.stringify({ janus: "destroy", transaction: transaction() }),
    ], { type: "application/json" }));
    void stop();
});
