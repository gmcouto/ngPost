#!/usr/bin/env python3
"""
CLI offline NNTP integration test suite for ngPost.
Spins up a local fake NNTP server and executes the real ngPost CLI binary
to verify:
  1. Explicit/generated archive vs transport passwords before compression/posting.
     --compress --gen_pass --encrypt generates an independent archive password.
     A distinct explicit archive password is accepted; the NZB carries the transport password.
  2. Authority of transport metadata:
     Transport encryption password authoritatively emitted in NZB.
     XML escaping and CR encoding (&#xD;) preserved.
  3. Merged config + CLI settings: accept CLI password when config enables encryption.
     Reject empty password with config-enabled encryption.
  4. Pre-posting refusal: XML-unrepresentable passwords refused before any post/NZB.
  5. Byte-stable retries: retried articles have 100% byte-identical wire content.
  6. Socket-level leading-dot bootstrap/footer dot-stuffing.
"""

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET


class FakeNntpServer:
    # Two views of every posted article are kept: raw_article_bodies holds the
    # exact wire lines as received (dot-stuffing preserved, terminator "."
    # line consumed as end-of-article), while received_articles holds the
    # RFC 3977 dot-unstuffed form (".." -> "."). Tests that verify wire-level
    # dot-stuffing must inspect raw_article_bodies; received_articles alone
    # cannot show it, because the unstuffing above removes exactly that dot.
    def __init__(self, fail_first_post=False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(5)
        self.fail_first_post = fail_first_post
        self.has_failed_once = False
        self.received_articles = []
        self.raw_article_bodies = []
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def _accept_loop(self):
        while self.running:
            try:
                self.sock.settimeout(0.5)
                client, _ = self.sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

    def _handle_client(self, client):
        try:
            client.sendall(b"200 Fake NNTP Ready (posting allowed)\r\n")
            buffer = b""
            in_article = False
            current_article = []

            while self.running:
                data = client.recv(4096)
                if not data:
                    break
                buffer += data

                while b"\r\n" in buffer:
                    line, buffer = buffer.split(b"\r\n", 1)
                    if in_article:
                        if line == b".":
                            in_article = False
                            full_raw = b"\r\n".join(current_article) + b"\r\n"
                            self.raw_article_bodies.append(full_raw)

                            # RFC 3977 dot-unstuffing:
                            unstuffed_lines = []
                            for art_line in current_article:
                                if art_line.startswith(b".."):
                                    unstuffed_lines.append(art_line[1:])
                                else:
                                    unstuffed_lines.append(art_line)
                            unstuffed_article = b"\r\n".join(unstuffed_lines) + b"\r\n"
                            self.received_articles.append(unstuffed_article)

                            if self.fail_first_post and not self.has_failed_once:
                                self.has_failed_once = True
                                client.sendall(b"441 Simulated temporary failure, retry required\r\n")
                            else:
                                client.sendall(b"240 Article received OK <msgid@test>\r\n")
                            current_article = []
                        else:
                            current_article.append(line)
                    else:
                        cmd = line.decode("ascii", errors="replace").strip().upper()
                        if cmd.startswith("AUTHINFO USER"):
                            client.sendall(b"381 PASS required\r\n")
                        elif cmd.startswith("AUTHINFO PASS"):
                            client.sendall(b"281 Authentication accepted\r\n")
                        elif cmd == "POST":
                            client.sendall(b"340 Send article to be posted\r\n")
                            in_article = True
                        elif cmd == "QUIT":
                            client.sendall(b"205 Bye\r\n")
                            return
                        elif cmd.startswith("MODE"):
                            client.sendall(b"200 Reader mode\r\n")
                        else:
                            client.sendall(b"500 Unknown command\r\n")
        except Exception:
            pass
        finally:
            client.close()

    def close(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass


def run_ngpost(ngpost_bin, tmpdir, server=None, extra_args=None, payload=b"test payload", config=None):
    sample_file = os.path.join(tmpdir, "test.txt")
    if payload is not None:
        with open(sample_file, "wb") as f:
            f.write(payload)

    nzb_out = os.path.join(tmpdir, "out.nzb")
    cmd = [ngpost_bin, "-s", "false"]

    if config:
        conf_file = os.path.join(tmpdir, "ngPost.conf")
        with open(conf_file, "w") as f:
            f.write(config)
        cmd.extend(["-c", conf_file])

    if server:
        cmd.extend(["--server", f"user:pass@@@127.0.0.1:{server.port}:1:nossl"])
    else:
        cmd.extend(["--server", "user:pass@@@127.0.0.1:11999:1:nossl"])

    cmd.extend([
        "-g", "alt.binaries.test",
        "-f", "tester@example.com",
        "-o", nzb_out,
    ])
    if payload is not None:
        cmd.extend(["-i", sample_file])

    if extra_args:
        cmd.extend(extra_args)

    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    nzb_content = ""
    if os.path.isfile(nzb_out):
        with open(nzb_out, "r", encoding="utf-8") as f:
            nzb_content = f.read()

    err = res.stderr.decode("utf-8", errors="replace") + res.stdout.decode("utf-8", errors="replace")
    return res.returncode, nzb_content, err


def run_test(name, func):
    sys.stdout.write(f"Testing {name}... ")
    sys.stdout.flush()
    try:
        func()
        print("PASS")
        return True
    except Exception as e:
        print(f"FAIL: {e}")
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", required=True, help="Path to ngPost CLI binary")
    args = parser.parse_args()
    ngpost_bin = os.path.abspath(args.bin)
    if not os.path.isfile(ngpost_bin) or not os.access(ngpost_bin, os.X_OK):
        print(f"Error: binary '{ngpost_bin}' does not exist or is not executable")
        sys.exit(1)

    print(f"Using ngPost CLI binary: {ngpost_bin}")
    all_passed = True

    def test_gen_pass_encrypt_keeps_transport_metadata():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server,
                    extra_args=["--compress", "--gen_pass", "--encrypt",
                                "--encrypt-password", "AuthoritativePass123",
                                "--tmp_dir", tmpdir, "--rar_path", "/bin/true"]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed (code {rc}): {err}")
                if '<meta type="yenc_encrypted">true</meta>' not in nzb:
                    raise AssertionError("NZB missing yenc_encrypted metadata")
                if '<meta type="password">AuthoritativePass123</meta>' not in nzb:
                    raise AssertionError("NZB missing authoritative transport password")
                if nzb.count('type="password"') != 1:
                    raise AssertionError(f"Expected 1 password tag, found {nzb.count('type=\"password\"')}")
            finally:
                server.close()

    all_passed &= run_test("--compress --gen_pass --encrypt keeps transport metadata", test_gen_pass_encrypt_keeps_transport_metadata)

    def test_gen_pass_encrypt_without_password_fails():
        with tempfile.TemporaryDirectory() as tmpdir:
            rc, _, err = run_ngpost(
                ngpost_bin, tmpdir,
                extra_args=["--compress", "--gen_pass", "--encrypt",
                            "--tmp_dir", tmpdir, "--rar_path", "/bin/true"]
            )
            if rc == 0:
                raise AssertionError("Expected non-zero exit code for --encrypt without password")
            if "non-empty password" not in err:
                raise AssertionError(f"Expected 'non-empty password' error, got: {err}")

    all_passed &= run_test("--compress --gen_pass --encrypt without password fails", test_gen_pass_encrypt_without_password_fails)

    def test_independent_archive_password():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server,
                    extra_args=["--compress", "--rar_pass", "RarPassDifferent",
                                "--encrypt", "--encrypt-password", "EncryptPass",
                                "--tmp_dir", tmpdir, "--rar_path", "/bin/true"]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed: {err}")
                if nzb.count('type="password"') != 1 or '<meta type="password">EncryptPass</meta>' not in nzb:
                    raise AssertionError("Expected exactly one transport password in NZB")
            finally:
                server.close()

    all_passed &= run_test("Independent archive and encryption passwords accepted", test_independent_archive_password)

    def test_encryption_password_overrides_meta_password():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server,
                    extra_args=["-m", "password=MetaPassDifferent",
                                "--encrypt", "--encrypt-password", "AuthoritativePass"]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed: {err}")
                if '<meta type="password">AuthoritativePass</meta>' not in nzb:
                    raise AssertionError("Authoritative encryption password did not override -m password")
                if nzb.count('type="password"') != 1:
                    raise AssertionError("Duplicate password tags in NZB")
            finally:
                server.close()

    all_passed &= run_test("Encryption password authoritatively overrides -m password", test_encryption_password_overrides_meta_password)

    def test_xml_escaping_and_single_password_emission():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server,
                    extra_args=["-m", "custom_key=custom_val",
                                "--encrypt", "--encrypt-password", "Special<&\"'>Pass"]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed: {err}")
                if '<meta type="password">Special&lt;&amp;&quot;&apos;&gt;Pass</meta>' not in nzb:
                    raise AssertionError(f"XML escaping failed in NZB: {nzb}")
                if nzb.count('type="password"') != 1:
                    raise AssertionError("Duplicate password tags in NZB")
                if '<meta type="custom_key">custom_val</meta>' not in nzb:
                    raise AssertionError("Custom metadata was lost")
            finally:
                server.close()

    all_passed &= run_test("XML escaping and single authoritative password emission", test_xml_escaping_and_single_password_emission)

    def test_encrypted_nzb_omits_unsupported_and_empty_version_cipher_meta():
        # NP-NEXT-1: In encrypted mode, writeNzbHead emits combined v1.2 content.
        # User-supplied or empty yenc_version and yenc_cipher must be omitted
        # while preserving other arbitrary metadata and transport metadata.
        # 1. Unsupported non-canonical values
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server,
                    extra_args=["-m", "yenc_version=0.1", "-m", "yenc_cipher=AES-GCM",
                                "-m", "category=test",
                                "--encrypt", "--encrypt-password", "AuthoritativePass123"]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed (code {rc}): {err}")
                if '<meta type="yenc_encrypted">true</meta>' not in nzb:
                    raise AssertionError("NZB missing yenc_encrypted metadata")
                if '<meta type="password">AuthoritativePass123</meta>' not in nzb:
                    raise AssertionError("NZB missing authoritative transport password")
                if '<meta type="category">test</meta>' not in nzb:
                    raise AssertionError("Custom metadata was lost")
                if "yenc_version" in nzb:
                    raise AssertionError(f"Contradictory yenc_version survived in encrypted NZB: {nzb}")
                if "yenc_cipher" in nzb:
                    raise AssertionError(f"Contradictory yenc_cipher survived in encrypted NZB: {nzb}")
            finally:
                server.close()

        # 2. Empty values
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server,
                    extra_args=["-m", "yenc_version=", "-m", "yenc_cipher=",
                                "-m", "category=test2",
                                "--encrypt", "--encrypt-password", "AuthoritativePass123"]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed (code {rc}): {err}")
                if '<meta type="yenc_encrypted">true</meta>' not in nzb:
                    raise AssertionError("NZB missing yenc_encrypted metadata")
                if '<meta type="password">AuthoritativePass123</meta>' not in nzb:
                    raise AssertionError("NZB missing authoritative transport password")
                if '<meta type="category">test2</meta>' not in nzb:
                    raise AssertionError("Custom metadata was lost")
                if "yenc_version" in nzb:
                    raise AssertionError(f"Empty yenc_version survived in encrypted NZB: {nzb}")
                if "yenc_cipher" in nzb:
                    raise AssertionError(f"Empty yenc_cipher survived in encrypted NZB: {nzb}")
            finally:
                server.close()

    all_passed &= run_test("Encrypted NZB omits unsupported and empty version/cipher metadata", test_encrypted_nzb_omits_unsupported_and_empty_version_cipher_meta)

    def test_ordinary_nzb_preserves_arbitrary_metadata():
        # Upstream ordinary metadata handling must remain untouched: arbitrary keys
        # including yenc_version / yenc_cipher are passed through when encryption is off.
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server,
                    extra_args=["-m", "yenc_version=0.1", "-m", "yenc_cipher=AES-GCM",
                                "-m", "category=movies"]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed (code {rc}): {err}")
                if '<meta type="yenc_version">0.1</meta>' not in nzb:
                    raise AssertionError("Ordinary NZB missing yenc_version metadata")
                if '<meta type="yenc_cipher">AES-GCM</meta>' not in nzb:
                    raise AssertionError("Ordinary NZB missing yenc_cipher metadata")
                if '<meta type="category">movies</meta>' not in nzb:
                    raise AssertionError("Ordinary NZB missing category metadata")
                if "yenc_encrypted" in nzb:
                    raise AssertionError("Ordinary NZB unexpectedly contains yenc_encrypted")
            finally:
                server.close()

    all_passed &= run_test("Ordinary NZB preserves arbitrary version/cipher metadata", test_ordinary_nzb_preserves_arbitrary_metadata)

    def test_config_encrypt_accepts_cli_password():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                conf = f"[server]\nhost = 127.0.0.1\nport = {server.port}\nuser = u\npass = p\nnbCons = 1\nssl = false\nENCRYPT = true\n"
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server, config=conf,
                    extra_args=["--encrypt-password", "CliSuppliedSecret"]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed: {err}")
                if '<meta type="yenc_encrypted">true</meta>' not in nzb:
                    raise AssertionError("NZB missing yenc_encrypted metadata")
                if '<meta type="password">CliSuppliedSecret</meta>' not in nzb:
                    raise AssertionError("NZB missing CLI-supplied password")
            finally:
                server.close()

    all_passed &= run_test("Config ENCRYPT=true accepts CLI --encrypt-password", test_config_encrypt_accepts_cli_password)

    def test_config_encrypt_empty_password_fails():
        with tempfile.TemporaryDirectory() as tmpdir:
            conf = "ENCRYPT = true\n"
            rc, _, err = run_ngpost(ngpost_bin, tmpdir, config=conf)
            if rc == 0:
                raise AssertionError("Expected failure when config enables encryption without password")
            if "password" not in err.lower():
                raise AssertionError(f"Expected password error message, got: {err}")

    all_passed &= run_test("Config ENCRYPT=true without password fails merged validation", test_config_encrypt_empty_password_fails)

    def test_xml_unrepresentable_password_rejected():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server,
                    extra_args=["--encrypt", "--encrypt-password", "Secret\x01Ctl"]
                )
                if rc == 0:
                    raise AssertionError("Expected non-zero exit for XML-unrepresentable password")
                if nzb:
                    raise AssertionError("NZB must not be written for a refused password")
                if "Secret" in err or "Ctl" in err:
                    raise AssertionError("Refusal message must not echo the password")
                if server.received_articles:
                    raise AssertionError("No article may be posted for a refused password")
            finally:
                server.close()

    all_passed &= run_test("XML-unrepresentable encryption password refused before posting", test_xml_unrepresentable_password_rejected)

    def test_xml_special_and_emoji_password_accepted():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                password = "Pa&<>\"'\U0001F600ss"
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server,
                    extra_args=["--encrypt", "--encrypt-password", password]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed: {err}")
                expected = '<meta type="password">Pa&amp;&lt;&gt;&quot;&apos;\U0001F600ss</meta>'
                if expected not in nzb:
                    raise AssertionError(f"Password meta not XML-escaped as expected: {nzb}")
            finally:
                server.close()

    all_passed &= run_test("XML-special and emoji encryption password accepted and escaped", test_xml_special_and_emoji_password_accepted)

    def test_cr_password_escaped_as_numeric_reference():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                password = "x\ry"
                rc, nzb, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server,
                    extra_args=["--encrypt", "--encrypt-password", password]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed: {err}")
                if '<meta type="password">x&#xD;y</meta>' not in nzb:
                    raise AssertionError(f"CR password not written as &#xD;: {nzb}")
                root = ET.fromstring(nzb)
                metas = [m for m in root.iter() if m.tag.endswith("meta") and m.get("type") == "password"]
                if not metas or metas[0].text != password:
                    raise AssertionError("CR password did not round-trip through XML parser")
            finally:
                server.close()

    all_passed &= run_test("CR encryption password written as &#xD; and round-tripped", test_cr_password_escaped_as_numeric_reference)

    def test_byte_stable_retries():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer(fail_first_post=True)
            try:
                rc, _, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server, payload=b"Payload for retry test",
                    extra_args=["--encrypt", "--encrypt-password", "StableRetryPass"]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed: {err}")
                if len(server.raw_article_bodies) < 2:
                    raise AssertionError(f"Expected >= 2 article attempts due to retry, got {len(server.raw_article_bodies)}")

                first_body = server.raw_article_bodies[0].split(b"\r\n\r\n", 1)[1]
                second_body = server.raw_article_bodies[1].split(b"\r\n\r\n", 1)[1]
                if first_body != second_body:
                    raise AssertionError(f"Retry was not byte-stable! Attempt 1 len={len(first_body)}, Attempt 2 len={len(second_body)}")

                first_line = first_body.split(b"\r\n")[0]
                # Line 1 may be dot-stuffed on the raw wire (a '.'-initial
                # encrypted control line is sent as ".."); strip the one
                # stuffing dot before reading the bootstrap, never waive.
                if first_line.startswith(b".."):
                    first_line = first_line[1:]
                if len(first_line) < 20:
                    raise AssertionError("Line 1 too short to contain bootstrap")
                index = first_line[16:20]
                if index != b"\x00\x00\x00\x01":
                    raise AssertionError(f"Expected segment index 1 in bootstrap, got {index.hex()}")
            finally:
                server.close()

    all_passed &= run_test("Byte-stable retries upon provider failure", test_byte_stable_retries)

    def test_socket_dot_stuffing():
        # NGPOST-TESTS-03 (2): wire-level leading-dot case. Inspect the RAW
        # wire (server.raw_article_bodies, dot-stuffing preserved; see the
        # FakeNntpServer comment) for a stuffed ".."-initial line, and check
        # the corresponding line in the unstuffed received_articles is
        # "."-initial (exactly one dot removed). The unstuffed ciphertext
        # being "."-initial is what makes this non-hollow: without the
        # poster's dot-stuffing (FF1Cipher::encryptControlLines prepends '.'
        # to '.'-initial control lines; the yEnc data encoder escapes a
        # '.'-initial byte as "=.") the raw line would be "."-initial instead
        # and this test fails -- verified by disabling the stuffing.
        #
        # Why this forces a leading dot, deterministically in effect: the
        # CLI salt/keys are random per run, so no single article can be
        # forced '.'-initial from outside. Instead we post ONE run of 500
        # small articles (-a 100 over a 50000-byte payload; segment indices
        # 1..500 in one upload). Each article has ~5 wire lines whose first
        # byte is (to the test) uniformly random over the alphabet, so the
        # run carries ~2500 leading-byte draws at '.' with p ~= 1/253 each;
        # P(no '.'-initial line) ~= (1-1/253)^2500 < 1e-4, and every local
        # run observed 5-9 stuffed lines. The payload bytes themselves are
        # fixed. The truly pinned deterministic case (segmentIndex 22 ->
        # '.'-initial =yend ciphertext, asserted as "..") lives in
        # CryptoTest::encryptControlLinesDotStuffsLeadingDot; this test is
        # the end-to-end wire counterpart through the real posting path.
        #
        # Assertion strength/exemption audit: `stuffed_seen` counts ALL raw
        # lines starting b".." across ALL articles (control lines stuffed by
        # FF1Cipher AND yEnc data lines, whose '.'-initial byte is escaped
        # as "=." by Yenc::encode and so can only reach ".." via a stuffed
        # control line in practice). The unstuffed-must-be-dot-initial check
        # below therefore fails if stuffing is missing: a '.'-initial line
        # would appear raw as "."-initial (or as the bare "." terminator).
        # Only control lines are stuffed in production
        # (FF1Cipher::encryptControlLines:521); data lines are never raw
        # '.'-initial because Yenc::encode escapes a line-initial '.'.
        payload = bytes((i * 37 + 11) % 256 for i in range(50000))
        stuffed = []  # (article_index, line_index, raw_line, unstuffed_line)
        stuffed_seen = 0
        inspected_lines = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                rc, _, err = run_ngpost(
                    ngpost_bin, tmpdir, server=server, payload=payload,
                    extra_args=["--encrypt", "--encrypt-password", "DotStuffPass",
                                "-a", "100"]
                )
                if rc != 0:
                    raise AssertionError(f"Process failed: {err}")
                if len(server.raw_article_bodies) < 100:
                    raise AssertionError(
                        f"Expected many small articles, got {len(server.raw_article_bodies)}")
                if len(server.received_articles) != len(server.raw_article_bodies):
                    raise AssertionError("Raw/unstuffed article counts differ")

                for art_idx, (raw, received) in enumerate(
                        zip(server.raw_article_bodies, server.received_articles)):
                    raw_lines = raw.split(b"\r\n\r\n", 1)[1].split(b"\r\n")
                    recv_lines = received.split(b"\r\n\r\n", 1)[1].split(b"\r\n")
                    if len(raw_lines) != len(recv_lines):
                        raise AssertionError(
                            f"Article {art_idx}: raw/unstuffed line counts differ "
                            f"({len(raw_lines)} vs {len(recv_lines)})")
                    for line_idx, (raw_line, recv_line) in enumerate(
                            zip(raw_lines, recv_lines)):
                        inspected_lines += 1
                        if raw_line.startswith(b".."):
                            stuffed_seen += 1
                        if raw_line == b".":
                            raise AssertionError(
                                f"Article {art_idx} line {line_idx}: bare '.' on raw wire")
                        if raw_line.startswith(b".."):
                            # Stuffed form on the wire; unstuffing must yield
                            # the '.'-initial line (one leading dot removed).
                            if recv_line != raw_line[1:] or not recv_line.startswith(b"."):
                                raise AssertionError(
                                    f"Article {art_idx} line {line_idx}: stuffed raw "
                                    f"{raw_line[:20]!r} did not unstuff to '.'-initial "
                                    f"{recv_line[:20]!r}")
                            stuffed.append((art_idx, line_idx, raw_line, recv_line))
                        elif raw_line.startswith(b"."):
                            raise AssertionError(
                                f"Article {art_idx} line {line_idx}: '.'-initial line "
                                f"reached the wire unstuffed: {raw_line[:20]!r}")
            finally:
                server.close()
        if not stuffed:
            raise AssertionError(
                "No '..'-initial (dot-stuffed) line on the raw wire across "
                "the 500 posted articles: the leading-dot case was not exercised")
        # stuffed_seen counts every raw ".." line across every article,
        # not just `stuffed` control lines verified above. With
        # inspected_lines (~500 articles x ~5 lines = ~2500) draws at
        # p ~= 1/253 per line, P(stuffed_seen == 0) ~= (1-1/253)^2500
        # < 1e-4 (<0.1% miss); inspected_lines is asserted >= 300 so the
        # bound stays meaningful even if article geometry changes.
        if inspected_lines < 300:
            raise AssertionError(
                f"Only {inspected_lines} raw lines inspected (<300): "
                "probability bound for stuffed_seen would be too weak")
        if stuffed_seen < 1:
            raise AssertionError(
                "stuffed_seen == 0: no dot-stuffed line on the raw wire")
        print(f"(dot-stuffed '..' lines on raw wire: {len(stuffed)} "
              f"[stuffed_seen={stuffed_seen} over {inspected_lines} lines], "
              f"first at article {stuffed[0][0]} line {stuffed[0][1]}) ", end="")

    all_passed &= run_test("Socket-level dot-stuffing on raw wire (leading-dot)", test_socket_dot_stuffing)

    def test_ordinary_post_body_snapshot():
        # The disconnected ordinary helper mode was removed (T08); ordinary posting
        # coverage comes from this real CLI fake-NNTP capture. The capture excludes
        # the trailing NNTP dot terminator (the server's POST acceptance already
        # checks that line). This short sample avoids the unrelated upstream
        # worst-case allocation path in NntpArticle.cpp.
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                payload = bytes.fromhex("48656c6c6f20576f726c642e747874ff")
                rc, _, err = run_ngpost(ngpost_bin, tmpdir, server=server, payload=payload)
                if rc != 0:
                    raise AssertionError(f"Process failed (code {rc}): {err}")
                if len(server.raw_article_bodies) != 1:
                    raise AssertionError(f"Expected 1 article body, got {len(server.raw_article_bodies)}")

                body = server.raw_article_bodies[0].split(b"\r\n\r\n", 1)[1]
                expected = (
                    b"=ybegin part=1 total=1 line=128 size=16 name=test.txt\r\n"
                    b"=ypart begin=1 end=16\r\n"
                    b"r\x8f\x96\x96\x99J\x81\x99\x9c\x96\x8eX\x9e\xa2\x9e)\r\n"
                    b"=yend size=16 pcrc32=615f3aca\r\n"
                )
                if body != expected:
                    raise AssertionError(
                        "Ordinary yEnc body mismatch:\n"
                        f"expected {expected!r}\n"
                        f"captured {body!r}"
                    )
            finally:
                server.close()

    all_passed &= run_test("Ordinary post body matches upstream-compatible yEnc snapshot", test_ordinary_post_body_snapshot)

    if not all_passed:
        print("\nSome CLI integration tests FAILED!")
        sys.exit(1)
    else:
        print("\nAll CLI integration tests PASSED successfully!")


if __name__ == "__main__":
    main()
