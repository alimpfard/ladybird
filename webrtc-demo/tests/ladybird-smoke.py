#!/usr/bin/env python3
"""Opt-in live Janus checks, isolated from Ladybird's offline regression suite."""

import argparse
import html
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
from urllib.parse import urljoin, urlparse


def main():
    demo = Path(__file__).resolve().parents[1]
    repo = demo.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://apps.cxbyte.me/webrtc/", help="Deployed demo URL")
    parser.add_argument("--test-web", type=Path, default=repo / "Build/release/bin/test-web")
    parser.add_argument("--results-dir", type=Path, help="Keep test-web reports here (default: a new temporary directory)")
    parser.add_argument("--certificate", type=Path, action="append", default=[], help="Additional trusted PEM certificate or bundle; repeatable")
    args = parser.parse_args()
    if urlparse(args.url).scheme not in ("http", "https") or not args.url.endswith("/"):
        parser.error("--url must be an HTTP(S) URL with a trailing slash")
    if not args.test_web.is_file():
        parser.error(f"test-web not found: {args.test_web}; build it or pass --test-web")
    results = args.results_dir.resolve() if args.results_dir else Path(tempfile.mkdtemp(prefix="ladybird-janus-results-"))
    print(f"Live target: {args.url}\nReports: {results}", flush=True)

    with tempfile.TemporaryDirectory(prefix="ladybird-janus-tests-") as directory:
        root = Path(directory)
        inputs = root / "Text/input/WebRTC"
        expected = root / "Text/expected/WebRTC"
        inputs.mkdir(parents=True)
        expected.mkdir(parents=True)
        (root / "test-web").symlink_to(repo / "Tests/LibWeb/test-web", target_is_directory=True)
        (root / "Fixtures").symlink_to(repo / "Tests/LibWeb/Fixtures", target_is_directory=True)
        (inputs.parent / "wpt-import").symlink_to(repo / "Tests/LibWeb/Text/input/wpt-import", target_is_directory=True)
        shutil.copyfile(repo / "Tests/LibWeb/Text/input/include.js", inputs.parent / "include.js")
        page = (demo / "public/index.html").read_text()
        page = page.replace('<link rel="stylesheet" href="style.css">', '<script src="../include.js"></script>')
        # Exercise the deployed JavaScript, using the matching local page markup.
        page = page.replace('<script src="app.js"></script>',
                            f'<script src="{html.escape(urljoin(args.url, "app.js"), quote=True)}"></script>')
        script = (demo / "tests/ladybird-smoke.js").read_text()
        for name, mode, rate in [("tone-48000", "tone", "48000"), ("tone-44100", "tone", "44100"), ("data-only", "none", "48000")]:
            options = json.dumps({"endpoint": urljoin(args.url, "janus"), "mode": mode, "rate": rate}).replace("<", "\\u003c")
            test_script = f"<script>const smokeOptions = {options};\n{script}</script>"
            (inputs / f"{name}.html").write_text(page.replace("</html>", test_script + "\n</html>"))
            output = "PASS: connected to deployed Janus\nPASS: text echo\nPASS: binary echo\n"
            if mode == "tone":
                output += "PASS: returned audio\n"
            (expected / f"{name}.txt").write_text(output)

        command = [str(args.test_web.resolve()), "--test-path", str(root), "--filter", "*WebRTC/*",
                   "--test-concurrency", "1", "--per-test-timeout", "90", "--results-dir", str(results)]
        # RequestServer uses only the first --certificate. Combine the OS trust
        # store and optional roots into one regular PEM file inside the test root,
        # where its filesystem sandbox can read it (system bundles can be symlinks).
        certificates = ssl.create_default_context().get_ca_certs(binary_form=True)
        if not certificates and not args.certificate:
            parser.error("No system CA roots found; pass --certificate with the service's trusted root")
        bundle = "".join(ssl.DER_cert_to_PEM_cert(cert) for cert in certificates)
        for certificate in args.certificate:
            bundle += "\n" + certificate.read_text() + "\n"
        bundle_path = root / "trusted-roots.pem"
        bundle_path.write_text(bundle)
        command += ["--certificate", str(bundle_path)]
        return subprocess.run(command, cwd=repo).returncode


if __name__ == "__main__":
    raise SystemExit(main())
