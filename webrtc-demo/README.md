# WebRTC echo lab

A self-contained Janus EchoTest instance and a small browser client for developing
Ladybird's WebRTC support. The client uses the Janus REST API directly, with no
JavaScript dependencies or CDN assets. The image installs Debian Bookworm's Janus
package, including SCTP data-channel support, and nginx.

## Current deployment

- Public page: https://apps.cxbyte.me/webrtc/
- Service: `dedi:/home/ubuntu/webrtc-demo`, Docker Compose service `echo`.
- HTTP: `100.64.0.14:8086` over Tailscale; public media: `51.75.117.5:20000–20100/udp`.
- Proxy: `calibre:/etc/nginx/nginx.conf`, `/webrtc/` in the `apps.cxbyte.me` server.
- Pre-deployment proxy backup: `/etc/nginx/nginx.conf.webrtc-backup-20260904-210715`.

Update from this checkout:

```sh
rsync -az --exclude=.env webrtc-demo/ dedi:webrtc-demo/
ssh dedi 'cd ~/webrtc-demo && docker compose up -d --build'
```

Chromium live checks passed for 48 kHz and 44.1 kHz generated audio, text and binary
echo, disconnect/reconnect, and data-only mode. Microphone permission/device
capture needs a manual check. The deployed container reports healthy. This
Ladybird branch also passed a live check for connection, text/binary echo, and
returned audio against the public HTTPS endpoint. Its test harness needed an explicit trusted CA file. The live test runner below
handles this automatically.

## Deploy a new instance

On a Linux Docker host with a public IPv4 address:

```sh
cd webrtc-demo
cp .env.example .env
# Set PUBLIC_IP in .env to the host's public IPv4 address.
docker compose up -d --build
```

Forward **UDP 20000–20100** from the public IP to the Docker host, preserving port
numbers, and permit those ports in the host/cloud firewall. `PUBLIC_IP` is the
address Janus advertises to browsers; it must identify the machine receiving that
UDP traffic, not an HTTP CDN or reverse proxy. No STUN server is required for this
server-side static mapping. TURN is not bundled.

The web service binds to `127.0.0.1:8080` on the host by default. Point your existing
HTTPS reverse proxy at that port. For an nginx proxy on the same host:

```nginx
location = /webrtc { return 308 /webrtc/; }
location /webrtc/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_buffering off;
    proxy_read_timeout 65s;
}
```

The container accepts both `/webrtc/` and `/`; proxies that strip the `/webrtc/`
prefix also work. Keep the trailing slash on the public page URL so its relative
asset and API URLs resolve correctly. A different public prefix works if your
proxy strips it before forwarding. If your reverse proxy is another container,
put both on a shared Docker network and proxy to `echo:8080`, or adjust `HTTP_BIND`
to an address reachable by that proxy.

HTTPS is needed for microphone access outside localhost. TLS is terminated by
your existing proxy; the media itself uses WebRTC's DTLS/SRTP transport. An
HTTP-only hosting platform cannot host the media endpoint: it must also support
the UDP ports above.

## Check the deployment

```sh
docker compose ps
curl --fail http://127.0.0.1:8080/webrtc/janus/info
docker compose logs -f echo
```

The info response should include `janus.plugin.echotest` and `data_channels` set
to `true` (Janus versions may encode that value as a string).

Open `https://apps.cxbyte.me/webrtc/` in Chrome or Firefox first, then Ladybird:

1. Leave **440 Hz test tone** selected and connect. The log should show a connected
   ICE state, a remote audio track, and a non-silent audio return. The meter measures
   the returned track, not the locally generated tone. Audio is muted by default;
   use **Listen to returned audio** to hear it.
2. Send text and a binary probe. Janus prefixes echoed text; the binary probe
   should return `0, 1, 127, 128, 255` unchanged.
3. Disconnect, choose **44100**, and reconnect to exercise outgoing resampling.
4. Try **Microphone** and **Data only** independently. The tone-rate selector only
   applies to generated tones. The microphone uses the device's settings.
5. Download the log when investigating differences. It includes offers, answers,
   ICE candidates, transport state changes, and received data.

The options panel accepts standard `iceServers` JSON for testing STUN/TURN from
browsers that support configuring them. The current Ladybird branch still has
incomplete configuration support; adding TURN credentials in the page does not
implement that browser feature. The default direct connection is the baseline.

This is an unauthenticated development service. Only EchoTest is enabled, and the
Janus admin API is disabled. If you put access control in your proxy, apply it to
both the page and its `/webrtc/janus` endpoints. Abandoned Janus sessions expire
after 60 seconds. The page also destroys its session on disconnect.

## Local development and checks

Without `PUBLIC_IP`, Docker's private candidate can work for a browser on the
Linux Docker host. For testing from other machines, set a reachable host IPv4 and
open the UDP ports as above.

```sh
node --check public/app.js
node --test tests/client.test.cjs
bash -n entrypoint.sh
docker compose config
docker compose build
```

Run the **Ladybird live test** from the repository root:

```sh
python3 webrtc-demo/tests/ladybird-smoke.py
```

It runs three cases against the deployed service: 48 kHz tone, 44.1 kHz tone, and
data-only. Each checks connection plus text/binary echo; the tone cases also check
returned audio. It uses `Build/release/bin/test-web` and loads the deployed client
JavaScript. The runner copies system CA roots into a sandbox-readable bundle, creates temporary
fixtures, and prints the path to retained test-web reports. It returns a nonzero
exit status on failure and is deliberately separate from the offline CI suite.

Use `--url https://your-host/webrtc/`, `--test-web /path/to/test-web`,
`--results-dir /path/to/reports`, or repeated `--certificate /path/to/root.pem`
to override the defaults. Run this from a Ladybird checkout with its test fixtures.
No microphone permission or device is required.

For a live Chromium smoke check, launch an isolated headless browser with remote
debugging on loopback, then run the script (requires Node with built-in WebSocket):

```sh
chromium --headless --remote-debugging-port=9223 \
  --user-data-dir=/tmp/webrtc-echo-check \
  --autoplay-policy=no-user-gesture-required about:blank
# In another terminal:
node tests/chromium-smoke.mjs
```

`ECHO_URL` and `CDP_URL` override the public page and debugging endpoint. The script
checks both tone rates and data-only mode, including text/binary echoes, and closes
each session. Close the temporary browser when finished.

The Node tests check the client's signaling and cleanup using a mock Janus
transport. They do not substitute for a live media test. The image is built on the deployment host; a local Docker daemon is not required
when deploying over SSH.

## References

- [Janus HTTP API](https://janus.conf.meetecho.com/docs/rest.html)
- [EchoTest plugin](https://janus.conf.meetecho.com/docs/echotest.html)
- [Janus source and license](https://github.com/meetecho/janus-gateway)

Janus is GPL-3.0 software, installed from Debian's package repositories. Rebuild
the image to pick up distribution package updates; the container's health check
probes the Janus API through nginx.
