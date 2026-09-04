self.onrtctransform = async event => {
    const transformer = event.transformer;
    const reader = transformer.readable.getReader();
    let frame;
    do {
        ({ value: frame } = await reader.read());
    } while (frame.data.byteLength <= 3);
    const clone = structuredClone(new RTCEncodedAudioFrame(frame));
    const metadata = clone.getMetadata();
    const writer = transformer.writable.getWriter();
    await writer.write(clone);
    self.postMessage(`${transformer.options.token}: ${clone.data.byteLength > 3 && metadata.mimeType === "audio/opus"}`);
    await reader.cancel();
};
