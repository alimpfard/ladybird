class Passthrough extends AudioWorkletProcessor {
    process(inputs, outputs) {
        for (let channel = 0; channel < outputs[0].length; ++channel) {
            const input = inputs[0][channel] ?? inputs[0][0];
            if (input)
                outputs[0][channel].set(input);
        }
        return true;
    }
}
registerProcessor("passthrough", Passthrough);
