// The Python runner provides smokeOptions and the normal test-web include.js.
promiseTest(async () => {
    async function waitFor(check, description) {
        if (!await waitForCondition(check, 800, 25))
            throw new Error(`Timed out: ${description}`);
    }
    try {
        document.getElementById("endpoint").value = smokeOptions.endpoint;
        document.getElementById("source").value = smokeOptions.mode;
        document.getElementById("rate").value = smokeOptions.rate;
        await start();
        await waitFor(() => !document.getElementById("send").disabled, "data channel open");
        println("PASS: connected to deployed Janus");

        document.getElementById("message").value = "Ladybird live echo 👋";
        document.getElementById("send").click();
        await waitFor(() => document.getElementById("echo").textContent.includes("Ladybird live echo 👋"), "text echo");
        println("PASS: text echo");

        document.getElementById("binary").click();
        await waitFor(() => document.getElementById("log").textContent.includes("PASS: binary echo matches"), "binary echo");
        println("PASS: binary echo");

        if (smokeOptions.mode === "tone") {
            await waitFor(() => document.getElementById("log").textContent.includes("PASS: non-silent audio"), "returned audio");
            println("PASS: returned audio");
        }
    } catch (error) {
        println(`FAIL: ${error}`);
        println(document.getElementById("log").textContent);
    } finally {
        if (typeof stop === "function") await stop();
    }
});
