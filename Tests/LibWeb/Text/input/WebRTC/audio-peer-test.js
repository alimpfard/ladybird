async function audioPeerTest(sampleRate, transform, replace) {
    const pair = peerPair();
    const context = new AudioContext({ sampleRate });
    // Opus is decoded at 48 kHz. Use an independent receiving graph at that rate.
    const receivingContext = new AudioContext({ sampleRate: 48000 });
    const workers = [];
    const transformedFrames = [];
    try {
        const oscillator = new OscillatorNode(context, { frequency: 440 });
        const gain = new GainNode(context, { gain: 0.2 });
        const destination = context.createMediaStreamDestination();
        oscillator.connect(gain).connect(destination);
        const sender = pair.left.addTrack(destination.stream.getAudioTracks()[0], destination.stream);
        if (transform) {
            const worker = new Worker("audio-peer-transform.js");
            workers.push(worker);
            transformedFrames.push(nextEvent(worker, "message"));
            sender.transform = new RTCRtpScriptTransform(worker);
        }
        const receivedTrack = nextEvent(pair.right, "track");
        await pair.negotiate();
        oscillator.start();
        await context.resume();
        const event = await receivedTrack;
        check(event.track.kind === "audio" && event.receiver.track === event.track, "remote track is the receiver's audio track");
        if (transform) {
            const worker = new Worker("audio-peer-transform.js");
            workers.push(worker);
            transformedFrames.push(nextEvent(worker, "message"));
            event.receiver.transform = new RTCRtpScriptTransform(worker);
        }
        const source = receivingContext.createMediaStreamSource(new MediaStream([event.track]));
        const analyser = new AnalyserNode(receivingContext, { fftSize: 2048 });
        const silent = new GainNode(receivingContext, { gain: 0 });
        source.connect(analyser).connect(silent).connect(receivingContext.destination);
        await receivingContext.resume();
        const samples = new Float32Array(analyser.fftSize);
        function signal() {
            analyser.getFloatTimeDomainData(samples);
            const rms = Math.sqrt(samples.reduce((sum, value) => sum + value * value, 0) / samples.length);
            let sine = 0;
            let cosine = 0;
            for (let index = 0; index < samples.length; ++index) {
                const phase = 2 * Math.PI * 440 * index / receivingContext.sampleRate;
                sine += samples[index] * Math.sin(phase);
                cosine += samples[index] * Math.cos(phase);
            }
            return { rms, toneAmplitude: 2 * Math.hypot(sine, cosine) / samples.length };
        }
        async function waitForAudio(audible) {
            const matched = await waitForCondition(() => {
                const { rms, toneAmplitude } = signal();
                return audible ? toneAmplitude > 0.08 && rms < 0.25 : rms < 0.001;
            }, 400, 20);
            if (!matched)
                throw new Error(`Remote audio did not become ${audible ? "audible" : "silent"}`);
        }
        await waitForAudio(true);
        if (transform) {
            await Promise.all(transformedFrames);
            check(true, "both workers transform encoded frames");
        }
        check(true, "decoded remote audio contains the transmitted tone");
        if (replace) {
            await sender.replaceTrack(null);
            await waitForAudio(false);
            check(true, "detaching the sender silences the remote track");
            const replacement = context.createMediaStreamDestination();
            gain.connect(replacement);
            await sender.replaceTrack(replacement.stream.getAudioTracks()[0]);
            await waitForAudio(true);
            check(true, "replacement track resumes audio without renegotiation");
        }
        pair.checkICE();
    } finally {
        pair.close();
        for (const worker of workers)
            worker.terminate();
        await Promise.all([context.close(), receivingContext.close()]);
    }
}
