import copy
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build import ROOT, build_arch, build_deb, digest, load_app, run, squashfs_offset, stage
from release import Signer, assemble, validate
import release as distribution


def png():
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\0\xff\0\0\xff")) + chunk(b"IEND", b""))


class KeySelection(unittest.TestCase):
    def test_only_lists_available_signing_keys_and_subkeys(self):
        def key(kind="sec", capabilities="s", validity="u", expiry="", secret="+"):
            fields = [kind, validity] + [""] * 13
            fields[6], fields[11], fields[14] = expiry, capabilities, secret
            return ":".join(fields)

        def identity(letter, name):
            return f"fpr:::::::::{letter * 40}:\nuid:u::::::::{name}:"

        listing = "\n".join([
            key(), identity("A", r"Signing\x3a \xe6\x97\xa5\xe6\x9c\xac <one@example.invalid>"),
            key(capabilities="cE"), identity("B", "Encryption only"), key("ssb", "e"),
            key(capabilities="cS", secret="#"), identity("C", "Offline primary"),
            key("ssb", "s"), "fpr:::::::::" + "4" * 40 + ":",
            key("ssb", "s"), "fpr:::::::::" + "5" * 40 + ":",
            key("ssb", "e"), "fpr:::::::::" + "6" * 40 + ":",
            key("ssb", "s", secret="#"), "fpr:::::::::" + "7" * 40 + ":",
            key(validity="r"), identity("D", "Revoked"),
            key("ssb", "s"), "fpr:::::::::" + "8" * 40 + ":",
            key(expiry="1"), identity("E", "Expired"),
            key(capabilities="sD"), identity("F", "Disabled"),
            key(secret="#"), identity("1", "Missing private key"),
            key(capabilities="cS"), identity("2", "Expired subkey"), key("ssb", "s", expiry="1"),
            key(secret="D27600012401"), identity("3", "Signing card"),
        ])
        response = subprocess.CompletedProcess([], 0, stdout=listing)

        with patch.object(distribution, "run", return_value=response):
            keys = distribution.signing_keys()

        self.assertEqual([item["fingerprint"] for item in keys], ["A" * 40, "4" * 40, "5" * 40, "3" * 40])
        self.assertEqual(keys[0]["name"], "Signing: 日本 <one@example.invalid>")
        self.assertTrue(keys[1]["subkey"])
        self.assertEqual(keys[1]["name"], "Offline primary")

    def test_selection_requires_a_valid_choice_in_a_terminal(self):
        keys = [{"name": "First", "fingerprint": "A" * 40},
                {"name": "Second", "fingerprint": "B" * 40}]
        with patch.object(sys.stdin, "isatty", return_value=True), \
                patch("builtins.input", side_effect=["0", "9", "invalid", "2"]), \
                patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(distribution.select_key(keys), "B" * 40 + "!")

        with patch.object(sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(ValueError, "--key"):
                distribution.select_key(keys)
        with self.assertRaisesRegex(ValueError, "No usable"):
            distribution.select_key([])

    def test_cancelling_leaves_existing_outputs_untouched(self):
        keys = [{"name": "Local", "fingerprint": "A" * 40}]
        with patch.object(sys, "argv", ["release.py", "--publish"]), \
                patch.object(sys.stdin, "isatty", return_value=True), \
                patch.object(distribution, "signing_keys", return_value=keys), \
                patch("builtins.input", return_value="q"), \
                patch("sys.stdout", new_callable=io.StringIO), \
                patch.object(distribution.shutil, "rmtree") as remove, \
                patch.object(distribution, "publish") as upload:
            distribution.main()

        remove.assert_not_called()
        upload.assert_not_called()

    def test_local_build_does_not_contact_github_or_request_a_token(self):
        with patch.object(sys, "argv", ["release.py", "--key", "A" * 40]), \
                patch.object(distribution, "Signer"), \
                patch.object(distribution.shutil, "rmtree"), \
                patch.object(distribution, "run") as build, \
                patch.object(distribution, "assemble") as assemble_local, \
                patch.object(distribution, "GitHub") as github, \
                patch.object(distribution, "restore") as restore, \
                patch.object(distribution.getpass, "getpass") as prompt:
            distribution.main()

        build.assert_called_once()
        assemble_local.assert_called_once()
        github.assert_not_called()
        restore.assert_not_called()
        prompt.assert_not_called()


class GitHubRequests(unittest.TestCase):
    def test_streams_uploads_and_keeps_credentials_off_download_redirects(self):
        github = distribution.GitHub("owner/repository", "test-token")
        requests = []
        bodies = []

        def respond(request, **kwargs):
            requests.append(request)
            bodies.append(request.data.read() if hasattr(request.data, "read") else request.data)
            return io.BytesIO(b'{"id": 2, "name": "Packages"}')

        with tempfile.TemporaryDirectory() as temporary, patch.object(distribution, "urlopen", respond):
            path = Path(temporary) / "Packages"
            path.write_bytes(b"package index\n")
            release = {"id": 1, "assets": [{"id": 7, "name": "Packages"}]}
            github.upload(release, path, replace=True)
            github.download(release, "Packages", Path(temporary))

        self.assertEqual(requests[0].method, "DELETE")
        self.assertEqual(requests[1].full_url,
                         "https://uploads.github.com/repos/owner/repository/releases/1/assets?name=Packages")
        self.assertEqual(bodies[1], b"package index\n")
        self.assertEqual(requests[1].get_header("Content-length"), "14")
        self.assertEqual(requests[2].get_header("Authorization"), "Bearer test-token")
        redirected = HTTPRedirectHandler().redirect_request(
            requests[2], None, 302, "Found", {}, "https://release-assets.githubusercontent.com/package")
        self.assertIsNone(redirected.get_header("Authorization"))

    def test_only_treats_a_missing_release_as_absent(self):
        github = distribution.GitHub("owner/repository", "test-token")
        for status in (404, 401, 403):
            error = HTTPError("url", status, "Error", {}, io.BytesIO())
            with patch.object(distribution, "urlopen", side_effect=error):
                if status == 404:
                    self.assertIsNone(github.release("apt"))
                else:
                    with self.assertRaises(HTTPError):
                        github.release("apt")


class Packaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = ("makepkg", "repo-add", "dpkg-deb", "mksquashfs", "unsquashfs", "gpg")
        missing = [tool for tool in required if not shutil.which(tool)]
        if missing:
            raise RuntimeError("Install packaging test tools: " + ", ".join(missing))
        cls.temporary = tempfile.TemporaryDirectory(prefix="yuzu-tests-")
        cls.folder = Path(cls.temporary.name)
        cls.config = json.loads((ROOT / "repository.json").read_text())
        cls.app = load_app(ROOT / "apps/eda.json")
        cls.app.update(name="sample-app", title="Sample App", version="1.2.3")
        cls.app["dependencies"] = {"arch": [], "deb": []}
        cls.source = cls.folder / "packages"
        cls.images = {}
        cls.roots = {}
        for architecture, machine in (("x86_64", 62), ("aarch64", 183)):
            base = cls.folder / architecture
            image = base / "image"
            payload = image / "usr/bin"
            (payload / "resources").mkdir(parents=True)
            header = bytearray(128)
            header[:6] = b"\x7fELF\x02\x01"
            header[8:11] = b"AI\x02"
            struct.pack_into("<H", header, 18, machine)
            struct.pack_into("<Q", header, 40, 64)
            struct.pack_into("<HH", header, 58, 64, 1)
            for name in ("eda", "chrome-sandbox", "UpdateNix"):
                (payload / name).write_bytes(header)
                (payload / name).chmod(0o755)
            (payload / "sq.version").write_text("AppImage updater marker")
            (payload / "resources/LICENSE").write_text("Test license\n")
            (payload / "resources/app-update.yml").write_text("not used by native packages")
            (image / "Eda.png").write_bytes(png())
            squash = base / "image.squashfs"
            run("mksquashfs", image, squash, "-noappend", "-no-progress", "-processors", "1",
                stdout=subprocess.DEVNULL)
            appimage = base / "sample.AppImage"
            appimage.write_bytes(header + squash.read_bytes())
            cls.app["assets"][architecture]["sha256"] = digest(appimage)
            cls.images[architecture] = appimage
            work = base / "work"
            work.mkdir()
            root = stage(cls.app, architecture, appimage, work)
            cls.roots[architecture] = root
            build_arch(cls.app, architecture, root, work, cls.source / f"arch-{architecture}", cls.config["maintainer"])
            build_deb(cls.app, architecture, root, cls.source / "apt", cls.config["maintainer"])
        home = cls.folder / "key"
        home.mkdir(mode=0o700)
        environment = {**os.environ, "GNUPGHOME": str(home)}
        run("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
            "--quick-generate-key", "Packaging tests <test@example.invalid>", "rsa2048", "sign", "1d",
            env=environment, capture_output=True)
        key = run("gpg", "--batch", "--with-colons", "--list-secret-keys",
                  env=environment, capture_output=True, text=True).stdout
        fingerprint = next(line.split(":")[9] for line in key.splitlines() if line.startswith("fpr:"))
        cls.signer = Signer(fingerprint, home)
        cls.repositories = cls.folder / "repositories"
        assemble(cls.source, cls.repositories, cls.config, [cls.app], cls.signer)

    @classmethod
    def tearDownClass(cls):
        run("gpgconf", "--kill", "gpg-agent", env=cls.signer.environment)
        cls.temporary.cleanup()

    def test_native_package_architectures_and_metadata(self):
        for architecture, debian in (("x86_64", "amd64"), ("aarch64", "arm64")):
            package = self.source / "apt" / f"sample-app_1.2.3-1_{debian}.deb"
            fields = run("dpkg-deb", "--field", package, "Package", "Architecture", "Version",
                         capture_output=True, text=True).stdout
            self.assertIn(f"Architecture: {debian}", fields)
            self.assertIn("Version: 1.2.3-1", fields)
            archive = self.source / f"arch-{architecture}" / f"sample-app-1.2.3-1-{architecture}.pkg.tar.zst"
            metadata = run("bsdtar", "-xOf", archive, ".PKGINFO", capture_output=True, text=True).stdout
            self.assertIn(f"arch = {architecture}", metadata)
            self.assertIn("pkgname = sample-app", metadata)

    def test_desktop_launcher_sandbox_and_package_manager_updates(self):
        for root in self.roots.values():
            payload = root / "opt/sample-app"
            self.assertFalse((payload / "sq.version").exists())
            self.assertFalse((payload / "UpdateNix").exists())
            self.assertEqual((payload / "chrome-sandbox").stat().st_mode & 0o7777, 0o4755)
            launcher = (root / "usr/bin/sample-app").read_text()
            self.assertIn('"$@"', launcher)
            self.assertNotIn("--no-sandbox", launcher)
            desktop = root / "usr/share/applications/sample-app.desktop"
            self.assertIn("x-scheme-handler/eda;", desktop.read_text())
            if shutil.which("desktop-file-validate"):
                run("desktop-file-validate", desktop)

    def test_package_archives_preserve_root_owned_sandbox(self):
        for kind in ("deb", "arch"):
            if kind == "deb":
                output = run("dpkg-deb", "--contents", self.source / "apt/sample-app_1.2.3-1_amd64.deb",
                             capture_output=True, text=True).stdout
            else:
                output = run("bsdtar", "-tvf", self.source / "arch-x86_64/sample-app-1.2.3-1-x86_64.pkg.tar.zst",
                             capture_output=True, text=True).stdout
            sandbox = next(line for line in output.splitlines() if line.endswith("opt/sample-app/chrome-sandbox"))
            self.assertTrue(sandbox.startswith("-rwsr-xr-x"), sandbox)
            self.assertIn("root", sandbox)

    def test_checksum_and_architecture_mismatches_fail(self):
        bad = copy.deepcopy(self.app)
        bad["assets"]["x86_64"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "checksum does not match"):
            stage(bad, "x86_64", self.images["x86_64"], self.folder / "bad")
        with self.assertRaisesRegex(ValueError, "architecture"):
            squashfs_offset(self.images["aarch64"], "x86_64")

    def test_signed_manifest_covers_every_published_file(self):
        for directory in self.repositories.iterdir():
            self.assertTrue(validate(directory, self.signer.fingerprint)["signed"])
        copied = self.folder / "tampered" / "apt"
        shutil.copytree(self.repositories / "apt", copied)
        (copied / "Packages").write_text("tampered\n")
        with self.assertRaisesRegex(ValueError, "changed after signing"):
            validate(copied, self.signer.fingerprint)

    def test_signs_with_the_existing_local_keyring(self):
        document = self.folder / "local-signing.txt"
        document.write_text("Local release signing\n")

        with patch.dict(os.environ, {"GNUPGHOME": self.signer.environment["GNUPGHOME"]}):
            keys = distribution.signing_keys()
            self.assertEqual([key["fingerprint"] for key in keys], [self.signer.fingerprint])
            with patch.object(sys.stdin, "isatty", return_value=True), \
                    patch("builtins.input", return_value="1"), \
                    patch("sys.stdout", new_callable=io.StringIO):
                signer = Signer(distribution.select_key(keys))
            signature = signer.sign(document)
            signer.verify(signature, document)

        self.assertTrue(signature.is_file())
        with self.assertRaisesRegex(ValueError, "selected signing key"):
            validate(self.repositories / "apt", "A" * 40)

    def test_unsigned_output_cannot_be_published(self):
        unsigned = self.folder / "unsigned"
        assemble(self.source, unsigned, self.config, [self.app], None)
        with self.assertRaisesRegex(ValueError, "unsigned"):
            validate(unsigned / "apt", self.signer.fingerprint)

    def test_selected_subkey_signs_and_exports_its_primary_identity(self):
        home = self.folder / "subkey-selection"
        home.mkdir(mode=0o700)
        environment = {**os.environ, "GNUPGHOME": str(home)}
        try:
            run("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-generate-key", "Subkey tests <subkey@example.invalid>", "ed25519", "cert", "1d",
                env=environment, capture_output=True)
            listing = run("gpg", "--batch", "--with-colons", "--list-keys",
                          env=environment, capture_output=True, text=True).stdout
            primary = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
            for _ in range(2):
                run("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                    "--quick-add-key", primary, "ed25519", "sign", "1d", env=environment, capture_output=True)

            with patch.dict(os.environ, environment):
                keys = distribution.signing_keys()
                self.assertEqual(len(keys), 2)
                self.assertTrue(all(key["subkey"] for key in keys))
                with patch.object(sys.stdin, "isatty", return_value=True), \
                        patch("builtins.input", return_value="1"), \
                        patch("sys.stdout", new_callable=io.StringIO) as output:
                    signer = Signer(distribution.select_key(keys))
                self.assertIn("Signing subkey", output.getvalue())
                document = self.folder / "subkey-signing.txt"
                document.write_text("Sign with the selected subkey.\n")
                signature = signer.sign(document)
                status = signer.gpg("--status-fd", "1", "--verify", signature, document).stdout.decode()
                self.assertIn("VALIDSIG " + keys[0]["fingerprint"], status)
                self.assertEqual(signer.fingerprint, primary)
                signer.export(home)
                self.assertEqual((home / "key.fingerprint").read_text().strip(), primary)
                verifier = Signer(primary, home / "verify")
                verifier.gpg("--import", home / "yuzu.asc")
                verifier.verify(signature, document)
        finally:
            run("gpgconf", "--kill", "gpg-agent", env=environment)

    def test_protected_local_key_uses_pinentry(self):
        home = self.folder / "protected-key"
        home.mkdir(mode=0o700)
        marker = self.folder / "pinentry-used"
        pinentry = self.folder / "pinentry"
        pinentry.write_text(
            f"#!{sys.executable}\n"
            "import sys\nfrom pathlib import Path\n"
            "print('OK', flush=True)\n"
            "for line in sys.stdin:\n"
            "    if line.startswith('GETPIN'):\n"
            f"        Path({str(marker)!r}).touch()\n"
            "        print('D local-test-passphrase', flush=True)\n"
            "    print('OK', flush=True)\n"
            "    if line.startswith('BYE'):\n"
            "        break\n"
        )
        pinentry.chmod(0o755)
        (home / "gpg-agent.conf").write_text(f"pinentry-program {pinentry}\n")
        environment = {**os.environ, "GNUPGHOME": str(home)}

        try:
            run("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                "--quick-generate-key", "Local signing <local@example.invalid>", "ed25519", "sign", "1d",
                input=b"local-test-passphrase\n", env=environment, capture_output=True)
            keys = run("gpg", "--batch", "--with-colons", "--list-secret-keys",
                       env=environment, capture_output=True, text=True).stdout
            fingerprint = next(line.split(":")[9] for line in keys.splitlines() if line.startswith("fpr:"))
            run("gpgconf", "--kill", "gpg-agent", env=environment)
            document = self.folder / "protected-signing.txt"
            document.write_text("Protected local release\n")

            with patch.dict(os.environ, {"GNUPGHOME": str(home)}):
                signer = Signer(fingerprint)
                signer.verify(signer.sign(document), document)

            self.assertTrue(marker.exists())
        finally:
            run("gpgconf", "--kill", "gpg-agent", env=environment)

    def test_restore_reuses_only_matching_signed_packages(self):
        github = Mock()
        github.release.side_effect = lambda channel: {"draft": False, "tag_name": channel, "assets": []}

        def download(release, name, destination):
            shutil.copyfile(self.repositories / release["tag_name"] / name, destination / name)

        github.download.side_effect = download

        root = self.folder / "restore"
        with patch.object(distribution, "ROOT", root):
            distribution.restore(self.config, [self.app], self.signer, github)
            self.assertEqual(digest(root / "dist/packages/apt/sample-app_1.2.3-1_amd64.deb"),
                             digest(self.repositories / "apt/sample-app_1.2.3-1_amd64.deb"))
            changed = copy.deepcopy(self.app)
            changed["description"] += " changed"
            with self.assertRaisesRegex(ValueError, "Increase the package revision"):
                distribution.restore(self.config, [changed], self.signer, github)

    def test_publisher_uploads_packages_before_indexes_and_refuses_replacement(self):
        github = Mock()
        release = {"id": 1, "draft": False, "assets": []}
        github.release.return_value = release
        directory = self.repositories / "apt"
        distribution.publish(directory, github, self.signer.fingerprint)
        uploads = github.upload.call_args_list
        self.assertTrue(uploads[0].args[1].name.endswith(".deb"))
        self.assertEqual(uploads[-1].args[1].name, "InRelease")
        self.assertNotIn("replace", uploads[0].kwargs)
        github.upload.reset_mock()
        release["assets"].append({"name": "sample-app_1.2.3-1_amd64.deb", "digest": "sha256:" + "0" * 64})
        with self.assertRaisesRegex(ValueError, "Increase the package revision"):
            distribution.publish(directory, github, self.signer.fingerprint)
        github.upload.assert_not_called()
        release["assets"].clear()
        release["draft"] = True
        distribution.publish(directory, github, self.signer.fingerprint)
        self.assertEqual([call.args[1].name for call in github.upload.call_args_list[:2]],
                         ["manifest.json", "manifest.json.sig"])
        github.request.assert_called_with("/1", method="PATCH", data={"draft": False, "make_latest": "false"})

        github.reset_mock()
        github.release.return_value = None
        github.request.return_value = {"id": 2, "draft": True, "assets": []}
        distribution.publish(directory, github, self.signer.fingerprint)
        creation = github.request.call_args_list[0].kwargs
        self.assertEqual(creation["method"], "POST")
        self.assertEqual(creation["data"]["tag_name"], "apt")
        self.assertTrue(creation["data"]["draft"])
        github.request.assert_called_with("/2", method="PATCH", data={"draft": False, "make_latest": "false"})

    def test_apt_release_hashes_and_flat_package_paths(self):
        directory = self.repositories / "apt"
        self.signer.verify(directory / "InRelease")
        self.signer.verify(directory / "Release.gpg", directory / "Release")
        release = (directory / "Release").read_text()
        self.assertIn("Architectures: amd64 arm64", release)
        self.assertIn("Valid-Until:", release)
        for name in ("Packages", "Packages.gz"):
            self.assertIn(digest(directory / name), release)
        packages = (directory / "Packages").read_text()
        for name in ("sample-app_1.2.3-1_amd64.deb", "sample-app_1.2.3-1_arm64.deb"):
            self.assertIn("Filename: " + name, packages)
            self.assertIn("SHA256: " + digest(directory / name), packages)

    @unittest.skipUnless(shutil.which("apt-get"), "APT client is installed in Ubuntu CI")
    def test_apt_client_update_and_download(self):
        directory = self.repositories / "apt"
        client = self.folder / "apt-client"
        for path in ("lists/partial", "cache/archives/partial", "downloads"):
            (client / path).mkdir(parents=True, exist_ok=True)
        (client / "status").touch()
        sources = client / "yuzu.sources"
        sources.write_text(f"Types: deb\nURIs: {directory.as_uri()}/\nSuites: ./\n"
                           f"Architectures: amd64\nSigned-By: {directory / 'yuzu.asc'}\n")
        options = ["-o", f"Dir::Etc::sourcelist={sources}", "-o", "Dir::Etc::sourceparts=-",
                   "-o", f"Dir::State::lists={client / 'lists'}", "-o", f"Dir::State::status={client / 'status'}",
                   "-o", f"Dir::Cache={client / 'cache'}", "-o", "APT::Architecture=amd64",
                   "-o", "APT::Sandbox::User=" + os.environ.get("USER", "runner")]
        run("apt-get", *options, "update", capture_output=True)
        run("apt-get", *options, "download", "sample-app:amd64", cwd=client / "downloads", capture_output=True)
        self.assertEqual(digest(client / "downloads/sample-app_1.2.3-1_amd64.deb"),
                         digest(directory / "sample-app_1.2.3-1_amd64.deb"))

    def test_pacman_reads_database_and_resolves_package_url(self):
        if not shutil.which("pacman"):
            self.skipTest("pacman client not installed")
        client = self.folder / "pacman-client"
        (client / "db/sync").mkdir(parents=True)
        directory = self.repositories / "arch-x86_64"
        shutil.copyfile(directory / "yuzu.db", client / "db/sync/yuzu.db")
        shutil.copyfile(directory / "yuzu.db.sig", client / "db/sync/yuzu.db.sig")
        config = client / "pacman.conf"
        config.write_text(f"[options]\nArchitecture = x86_64\nDBPath = {client / 'db'}\n"
                          f"GPGDir = {self.signer.environment['GNUPGHOME']}\n"
                          f"[yuzu]\nSigLevel = Required\nServer = {directory.as_uri()}\n")
        output = run("pacman", "--config", config, "-Sp", "--nodeps", "--print-format", "%l",
                     "sample-app", capture_output=True, text=True).stdout
        self.assertIn(directory.as_uri() + "/sample-app-1.2.3-1-x86_64.pkg.tar.zst", output)


if __name__ == "__main__":
    unittest.main()
