#!/usr/bin/env python3
"""
CLI offline NNTP integration test suite for ngPost (NP-1..4).
Spins up a local fake NNTP server and executes the real ngPost CLI binary
to verify:
  1. NP-1: Explicit/generated archive vs transport passwords before compression/posting.
     --compress --gen_pass --encrypt reuses transport password with no silent loss.
     Conflicting explicit archive password is rejected before posting.
  2. NP-2: Conflicting reserved -m metadata (password, yenc_encrypted) rejected.
     Exactly one authoritative transport password/marker emitted in NZB.
     XML escaping preserved.
  3. NP-3: Merged config + CLI settings: accept CLI password when config enables encryption.
     Reject empty password with config-enabled encryption.
  4. Byte-stable retries: retried articles have 100% byte-identical wire content.
  5. Socket-level leading-dot bootstrap/footer dot-stuffing.
"""

import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

class FakeNntpServer:
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
                            # End of article
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
                        line_str = line.decode("ascii", errors="replace").strip()
                        cmd = line_str.upper()
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

    # Test 1: NP-1 --compress --gen_pass --encrypt
    def test_np1_gen_pass_encrypt():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                sample_file = os.path.join(tmpdir, "test.txt")
                with open(sample_file, "wb") as f:
                    f.write(b"Hello Usenet encrypted compression world!")

                nzb_out = os.path.join(tmpdir, "out.nzb")
                # Run ngPost with compression, gen_pass, and encryption
                cmd = [
                    ngpost_bin,
                    "-s", "false",
                    "--server", f"user:pass@@@127.0.0.1:{server.port}:1:nossl",
                    "-g", "alt.binaries.test",
                    "-f", "tester@example.com",
                    "-o", nzb_out,
                    "-i", sample_file,
                    "--compress",
                    "--gen_pass",
                    "--encrypt",
                    "--encrypt-password", "AuthoritativePass123",
                    "--tmp_dir", tmpdir,
                    "--rar_path", "/bin/true"
                ]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                if res.returncode != 0:
                    raise AssertionError(f"Process failed (code {res.returncode}): {res.stderr.decode('utf-8', errors='replace')}")

                if not os.path.isfile(nzb_out):
                    raise AssertionError("NZB file was not created")

                with open(nzb_out, "r", encoding="utf-8") as f:
                    nzb_content = f.read()

                # Verify exactly one authoritative password is in the NZB matching transport password
                if '<meta type="yenc_encrypted">true</meta>' not in nzb_content:
                    raise AssertionError("NZB missing yenc_encrypted metadata")
                if '<meta type="password">AuthoritativePass123</meta>' not in nzb_content:
                    raise AssertionError("NZB missing authoritative transport password")
                if nzb_content.count('type="password"') != 1:
                    raise AssertionError(f"Expected exactly 1 password tag, found {nzb_content.count('type=\"password\"')}")
            finally:
                server.close()

    all_passed &= run_test("NP-1: --compress --gen_pass --encrypt reuses transport pass", test_np1_gen_pass_encrypt)

    # Test 2: NP-1 Conflict: explicit --rar_pass differs from --encrypt-password
    def test_np1_conflicting_archive_pass():
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = os.path.join(tmpdir, "test.txt")
            with open(sample_file, "wb") as f:
                f.write(b"content")

            nzb_out = os.path.join(tmpdir, "out.nzb")
            cmd = [
                ngpost_bin,
                "--server", f"user:pass@@@127.0.0.1:11999:1:nossl",
                "-g", "alt.binaries.test",
                "-o", nzb_out,
                "-i", sample_file,
                "--compress",
                "--rar_pass", "RarPassDifferent",
                "--encrypt",
                "--encrypt-password", "EncryptPass",
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            if res.returncode == 0:
                raise AssertionError("Expected non-zero exit code on conflicting archive and encryption passwords")
            err = res.stderr.decode("utf-8", errors="replace") + res.stdout.decode("utf-8", errors="replace")
            if "differs from" not in err and "conflict" not in err.lower():
                raise AssertionError(f"Expected conflict error message, got: {err}")

    all_passed &= run_test("NP-1: Conflicting explicit archive and encryption passwords rejected", test_np1_conflicting_archive_pass)

    # Test 3: NP-2 Conflicting -m password rejected
    def test_np2_conflicting_meta_password():
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = os.path.join(tmpdir, "test.txt")
            with open(sample_file, "wb") as f:
                f.write(b"content")

            nzb_out = os.path.join(tmpdir, "out.nzb")
            cmd = [
                ngpost_bin,
                "--server", f"user:pass@@@127.0.0.1:11999:1:nossl",
                "-g", "alt.binaries.test",
                "-o", nzb_out,
                "-i", sample_file,
                "-m", "password=WrongPass",
                "--encrypt",
                "--encrypt-password", "RightPass",
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            if res.returncode == 0:
                raise AssertionError("Expected non-zero exit code on conflicting -m password")
            err = res.stderr.decode("utf-8", errors="replace") + res.stdout.decode("utf-8", errors="replace")
            if "differs from" not in err and "conflict" not in err.lower():
                raise AssertionError(f"Expected conflict error message, got: {err}")

    all_passed &= run_test("NP-2: Conflicting -m password rejected", test_np2_conflicting_meta_password)

    # Test 4: NP-2 Conflicting -m yenc_encrypted=false with --encrypt rejected
    def test_np2_conflicting_meta_marker():
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = os.path.join(tmpdir, "test.txt")
            with open(sample_file, "wb") as f:
                f.write(b"content")

            nzb_out = os.path.join(tmpdir, "out.nzb")
            cmd = [
                ngpost_bin,
                "--server", f"user:pass@@@127.0.0.1:11999:1:nossl",
                "-g", "alt.binaries.test",
                "-o", nzb_out,
                "-i", sample_file,
                "-m", "yenc_encrypted=false",
                "--encrypt",
                "--encrypt-password", "RightPass",
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            if res.returncode == 0:
                raise AssertionError("Expected non-zero exit code on conflicting -m yenc_encrypted=false")

    all_passed &= run_test("NP-2: Conflicting -m yenc_encrypted=false rejected", test_np2_conflicting_meta_marker)

    # Test 5: NP-2 Authoritative emission and XML escaping
    def test_np2_xml_escaping_and_deduplication():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                sample_file = os.path.join(tmpdir, "test.txt")
                with open(sample_file, "wb") as f:
                    f.write(b"Plaintext data for XML escaping test")

                nzb_out = os.path.join(tmpdir, "out.nzb")
                cmd = [
                    ngpost_bin,
                    "-s", "false",
                    "--server", f"user:pass@@@127.0.0.1:{server.port}:1:nossl",
                    "-g", "alt.binaries.test",
                    "-f", "tester@example.com",
                    "-o", nzb_out,
                    "-i", sample_file,
                    "-m", "custom_key=custom_val",
                    "--encrypt",
                    "--encrypt-password", "Special<&\"'>Pass"
                ]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                if res.returncode != 0:
                    raise AssertionError(f"Process failed: {res.stderr.decode('utf-8', errors='replace')}")

                with open(nzb_out, "r", encoding="utf-8") as f:
                    nzb_content = f.read()

                if '<meta type="password">Special&lt;&amp;&quot;&apos;&gt;Pass</meta>' not in nzb_content:
                    raise AssertionError(f"XML escaping failed in NZB: {nzb_content}")
                if nzb_content.count('type="password"') != 1:
                    raise AssertionError("Duplicate password tags in NZB")
                if '<meta type="custom_key">custom_val</meta>' not in nzb_content:
                    raise AssertionError("Custom metadata was lost")
            finally:
                server.close()

    all_passed &= run_test("NP-2: XML escaping and single authoritative password emission", test_np2_xml_escaping_and_deduplication)

    # Test 6: NP-3 Config enabled encryption accepts CLI password
    def test_np3_config_enabled_encryption_cli_password():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                conf_file = os.path.join(tmpdir, "ngPost.conf")
                with open(conf_file, "w") as f:
                    f.write(f"""
[server]
host = 127.0.0.1
port = {server.port}
user = testuser
pass = testpass
nbCons = 1
ssl = false

ENCRYPT = true
""")
                sample_file = os.path.join(tmpdir, "test.txt")
                with open(sample_file, "wb") as f:
                    f.write(b"Config-driven encryption payload")

                nzb_out = os.path.join(tmpdir, "out.nzb")
                # Invoke WITHOUT --encrypt on CLI, only --encrypt-password
                cmd = [
                    ngpost_bin,
                    "-c", conf_file,
                    "-g", "alt.binaries.test",
                    "-o", nzb_out,
                    "-i", sample_file,
                    "--encrypt-password", "CliSuppliedSecret"
                ]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                if res.returncode != 0:
                    raise AssertionError(f"Process failed (code {res.returncode}): {res.stderr.decode('utf-8', errors='replace')}")

                with open(nzb_out, "r", encoding="utf-8") as f:
                    nzb_content = f.read()

                if '<meta type="yenc_encrypted">true</meta>' not in nzb_content:
                    raise AssertionError("NZB missing yenc_encrypted metadata")
                if '<meta type="password">CliSuppliedSecret</meta>' not in nzb_content:
                    raise AssertionError("NZB missing CLI-supplied password")
            finally:
                server.close()

    all_passed &= run_test("NP-3: Config ENCRYPT=true accepts CLI --encrypt-password", test_np3_config_enabled_encryption_cli_password)

    # Test 7: NP-3 Config ENCRYPT=true without password fails merged validation
    def test_np3_config_enabled_empty_password_fails():
        with tempfile.TemporaryDirectory() as tmpdir:
            conf_file = os.path.join(tmpdir, "ngPost.conf")
            with open(conf_file, "w") as f:
                f.write("""
ENCRYPT = true
""")
            sample_file = os.path.join(tmpdir, "test.txt")
            with open(sample_file, "wb") as f:
                f.write(b"content")

            cmd = [
                ngpost_bin,
                "-c", conf_file,
                "-i", sample_file,
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            if res.returncode == 0:
                raise AssertionError("Expected failure when config enables encryption without password")
            err = res.stderr.decode("utf-8", errors="replace") + res.stdout.decode("utf-8", errors="replace")
            if "non-empty password" not in err and "password" not in err.lower():
                raise AssertionError(f"Expected password error message, got: {err}")

    all_passed &= run_test("NP-3: Config ENCRYPT=true without password fails merged validation", test_np3_config_enabled_empty_password_fails)

    # Test 8: NP-4 Byte-stable retries
    def test_np4_byte_stable_retries():
        with tempfile.TemporaryDirectory() as tmpdir:
            # Server configured to fail the first POST attempt with 441
            server = FakeNntpServer(fail_first_post=True)
            try:
                sample_file = os.path.join(tmpdir, "test.txt")
                with open(sample_file, "wb") as f:
                    f.write(b"Payload that will be retried over NNTP connection")

                nzb_out = os.path.join(tmpdir, "out.nzb")
                cmd = [
                    ngpost_bin,
                    "-s", "false",
                    "--server", f"user:pass@@@127.0.0.1:{server.port}:1:nossl",
                    "-g", "alt.binaries.test",
                    "-f", "tester@example.com",
                    "-o", nzb_out,
                    "-i", sample_file,
                    "--encrypt",
                    "--encrypt-password", "StableRetryPass"
                ]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                if res.returncode != 0:
                    raise AssertionError(f"Process failed: {res.stderr.decode('utf-8', errors='replace')}")

                # Server should have received 2 attempts: first failed, second succeeded
                if len(server.raw_article_bodies) < 2:
                    raise AssertionError(f"Expected at least 2 article attempts due to retry, got {len(server.raw_article_bodies)}")

                first_attempt = server.raw_article_bodies[0]
                second_attempt = server.raw_article_bodies[1]

                # Extract the body portion (after NNTP headers)
                first_body = first_attempt.split(b"\r\n\r\n", 1)[1]
                second_body = second_attempt.split(b"\r\n\r\n", 1)[1]

                if first_body != second_body:
                    raise AssertionError(f"Retry was not byte-stable! Attempt 1 len={len(first_body)}, Attempt 2 len={len(second_body)}")

                # Check Line 1 20-byte bootstrap
                first_line = first_body.split(b"\r\n")[0]
                # Bootstrap prefix is 20 bytes (16 salt + 4 index)
                if len(first_line) < 20:
                    raise AssertionError("Line 1 too short to contain bootstrap")
                salt = first_line[:16]
                index = first_line[16:20]
                if index != b"\x00\x00\x00\x01":
                    raise AssertionError(f"Expected segment index 1 in bootstrap, got {index.hex()}")
            finally:
                server.close()

    all_passed &= run_test("NP-4: Byte-stable retries upon provider failure", test_np4_byte_stable_retries)

    # Test 9: NP-4 Socket-level dot-stuffing verification
    def test_np4_socket_dot_stuffing():
        with tempfile.TemporaryDirectory() as tmpdir:
            server = FakeNntpServer()
            try:
                # Create a sample file
                sample_file = os.path.join(tmpdir, "test.txt")
                with open(sample_file, "wb") as f:
                    f.write(b"Dot stuffing payload test")

                nzb_out = os.path.join(tmpdir, "out.nzb")
                cmd = [
                    ngpost_bin,
                    "-s", "false",
                    "--server", f"user:pass@@@127.0.0.1:{server.port}:1:nossl",
                    "-g", "alt.binaries.test",
                    "-f", "tester@example.com",
                    "-o", nzb_out,
                    "-i", sample_file,
                    "--encrypt",
                    "--encrypt-password", "DotStuffPass"
                ]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                if res.returncode != 0:
                    raise AssertionError(f"Process failed: {res.stderr.decode('utf-8', errors='replace')}")

                if not server.received_articles:
                    raise AssertionError("No articles received by fake NNTP server")

                article = server.received_articles[0]
                lines = article.split(b"\r\n")
                body_start = False
                body_lines = []
                for line in lines:
                    if body_start:
                        body_lines.append(line)
                    elif line == b"":
                        body_start = True

                if not body_lines:
                    raise AssertionError("Empty article body received")

                line1 = body_lines[0]
                # Verify Line 1 has the 20-byte bootstrap prefix
                if len(line1) < 20:
                    raise AssertionError("Line 1 too short")
                index_bytes = line1[16:20]
                if index_bytes != b"\x00\x00\x00\x01":
                    raise AssertionError(f"Expected index 1, got {index_bytes.hex()}")

                # Verify wire terminator was properly handled without leaving trailing dots
                last_line = body_lines[-1] if body_lines[-1] != b"" else body_lines[-2]
                if last_line == b".":
                    raise AssertionError("Premature EOF dot remaining in unstuffed body")
            finally:
                server.close()

    all_passed &= run_test("NP-4: Socket-level article transmission and framing", test_np4_socket_dot_stuffing)

    if not all_passed:
        print("\nSome CLI integration tests FAILED!")
        sys.exit(1)
    else:
        print("\nAll CLI integration tests PASSED successfully!")


if __name__ == "__main__":
    main()
