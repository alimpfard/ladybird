self.onrtctransform = async event => {
    const { readable, writable } = event.transformer;
    const reader = readable.getReader();
    const writer = writable.getWriter();
    let reported = false;
    while (true) {
        const { value: frame, done } = await reader.read();
        if (done)
            break;
        const data = new Uint8Array(frame.data);
        for (let index = 0; index < data.length; ++index)
            data[index] ^= 0x5a;
        await writer.write(frame);
        if (!reported) {
            reported = true;
            self.postMessage("transformed");
        }
    }
};
