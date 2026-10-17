"""Normalisation rules of docs/PREREGISTRATION.md section 5 (as amended).

A record's install phase is reduced to four item sets: network, file_write, credential, process.
This module only transforms data handed to it. It performs no network access and never contacts
any address, domain or URL that appears in a record.

Interpretations of the written rules (also listed in docs/DEVIATIONS.md):
  * F3: the long-token rule (-> "X") is applied before the digit-run rule (-> "N"). In the
    written order the digit rule would leave no digits, and the token rule would never fire.
  * N1: a "hostname" that is itself an IP literal is classified with N3, so that no destination
    is ever an IP address (N5).
"""

import hashlib
import ipaddress
import posixpath
import re
import shlex

PSL_SHA256 = "13879fec7cb7f6c67991de0810874f511d67eca2d99af53e40db2a833b207cdc"
PSL_COMMIT = "2dbfce14c57bcea83fef2be3bdcb560667d7ef93"
PSL_PATH = "scratch/psl/public_suffix_list.dat"

CATEGORIES = ("network", "file_write", "credential", "process")

# ---------------------------------------------------------------------------------------------
# Public Suffix List (ICANN + private sections)


class PSL:
    def __init__(self, text):
        self.rules, self.wild, self.exc = set(), set(), set()
        for line in text.splitlines():
            line = line.strip().split()[0] if line.strip() else ""
            if not line or line.startswith("//"):
                continue
            line = _idna(line.lower())
            if line.startswith("!"):
                self.exc.add(line[1:])
            elif line.startswith("*."):
                self.wild.add(line[2:])
            else:
                self.rules.add(line)

    def public_suffix(self, host):
        labels = host.split(".")
        best = labels[-1:]  # default rule "*"
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in self.exc:  # exception rule: the suffix is the candidate minus its first label
                return ".".join(labels[i + 1:])
            if cand in self.rules and len(labels) - i > len(best):
                best = labels[i:]
            if i > 0 and ".".join(labels[i:]) in self.wild and len(labels) - i + 1 > len(best):
                best = labels[i - 1:]
        return ".".join(best)

    def registrable(self, host):
        """eTLD+1, or None if host is itself a public suffix."""
        ps = self.public_suffix(host)
        if host == ps:
            return None
        labels = host.split(".")
        n = len(ps.split("."))
        return ".".join(labels[-(n + 1):])


def _idna(label_string):
    try:
        prefix = "!" if label_string.startswith("!") else ("*." if label_string.startswith("*.") else "")
        body = label_string[len(prefix):]
        return prefix + body.encode("idna").decode("ascii")
    except Exception:
        return label_string


def load_psl(path=PSL_PATH, verify=True):
    with open(path, "rb") as fh:
        data = fh.read()
    if verify and hashlib.sha256(data).hexdigest() != PSL_SHA256:
        raise SystemExit(f"Public Suffix List hash mismatch for {path}")
    return PSL(data.decode("utf-8"))


# ---------------------------------------------------------------------------------------------
# 5.1 Network destinations

SELF_DOMAINS = {"npmjs.org", "npmjs.com", "yarnpkg.com", "pypi.org", "pythonhosted.org"}  # N4
METADATA_IPS = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")}
_HOST_OK = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")
_DROP_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "fc00::/7", "169.254.0.0/16", "fe80::/10")]


def classify_ip(addr):
    """N3: None (dropped), 'cloud-metadata' or 'ip-literal'."""
    try:
        ip = ipaddress.ip_address(str(addr).strip().strip("[]"))
    except ValueError:
        return None  # not an IP address: dropped
    if ip in METADATA_IPS:
        return "cloud-metadata"
    if ip.is_unspecified or ip.is_multicast or any(ip in n for n in _DROP_NETS):
        return None
    return "ip-literal"


def host_item(host, psl):
    """N1 (+N3 for IP literals). Returns an item or None."""
    h = str(host).strip().lower().rstrip(".")
    if not h:
        return None
    try:
        ipaddress.ip_address(h.strip("[]"))
        return classify_ip(h)
    except ValueError:
        pass
    if not _HOST_OK.match(h):
        return h  # cannot be parsed: kept as is
    reg = psl.registrable(h)
    return reg if reg is not None else h  # a public suffix itself: kept as is


def network_items(phase, psl):
    items = set()
    for s in phase.get("Sockets") or []:
        hosts = [h for h in (s.get("Hostnames") or []) if h]
        if hosts:  # N2
            items |= {host_item(h, psl) for h in hosts}
        else:  # N3
            items.add(classify_ip(s.get("Address", "")))
    for d in phase.get("DNS") or []:
        for q in d.get("Queries") or []:
            items.add(host_item(q.get("Hostname", ""), psl))
    items.discard(None)
    return items - SELF_DOMAINS  # N4 (N5: ports are never used)


# ---------------------------------------------------------------------------------------------
# 5.2 File writes

_HOME = re.compile(r"^(/root|/home/[^/]+)(?=/|$)")
DROP_UNDER = ("/tmp/", "/var/tmp/", "/dev/", "/proc/", "/sys/", "/run/",  # temporary
              "~/.npm/", "~/.cache/", "~/.node-gyp/", "~/.yarn/", "~/.bun/install/cache/",  # cache
              "/app/.pyenv/", "/usr/local/lib/node_modules/")  # install dirs
DROP_CONTAINS = ("/__pycache__/", "/node_modules/", "/site-packages/", "/dist-packages/")
DROP_EXACT = ("/app/package.json", "/app/package-lock.json")
_LONG = re.compile(r"[A-Za-z0-9_-]{16,}")
_DIGITS = re.compile(r"[0-9]+")


def f1(path):
    p = re.sub(r"/{2,}", "/", str(path))
    if p.startswith("/"):
        p = posixpath.normpath(p)
        if p.startswith("//"):
            p = p[1:]
    p = _HOME.sub("~", p, count=1)
    return p


def dropped(p):
    return (p.startswith(DROP_UNDER) or any(c in p for c in DROP_CONTAINS) or p.endswith(".pyc")
            or p in DROP_EXACT)


def f3(s):
    s = _LONG.sub(lambda m: "X" if re.search(r"[A-Za-z]", m[0]) and re.search(r"[0-9]", m[0]) else m[0], s)
    return _DIGITS.sub("N", s)


def write_items(phase):
    out = set()
    for f in phase.get("Files") or []:
        if f.get("Write"):
            p = f1(f.get("Path", ""))
            if p and not dropped(p):
                out.add(f3(p))
    return out


# ---------------------------------------------------------------------------------------------
# 5.3 Credential-file reads (item = the list entry)

CREDENTIAL_LIST = [
    ("~/.npmrc", re.compile(r"^~/\.npmrc$")),
    ("~/.pypirc", re.compile(r"^~/\.pypirc$")),
    ("~/.netrc", re.compile(r"^~/\.netrc$")),
    ("~/.git-credentials", re.compile(r"^~/\.git-credentials$")),
    ("~/.ssh/*", re.compile(r"^~/\.ssh/[^/]+$")),
    ("~/.aws/credentials", re.compile(r"^~/\.aws/credentials$")),
    ("~/.aws/config", re.compile(r"^~/\.aws/config$")),
    ("/proc/*/environ", re.compile(r"^/proc/[^/]+/environ$")),
    ("~/.config/gcloud/**", re.compile(r"^~/\.config/gcloud/.+")),
    ("~/.azure/**", re.compile(r"^~/\.azure/.+")),
    ("~/.kube/config", re.compile(r"^~/\.kube/config$")),
    ("~/.docker/config.json", re.compile(r"^~/\.docker/config\.json$")),
    ("~/.config/gh/hosts.yml", re.compile(r"^~/\.config/gh/hosts\.yml$")),
    ("~/.bash_history", re.compile(r"^~/\.bash_history$")),
    ("~/.zsh_history", re.compile(r"^~/\.zsh_history$")),
    ("/etc/shadow", re.compile(r"^/etc/shadow$")),
    (".env", re.compile(r"(^|/)\.env(\.[^/]*)?$")),
]


def credential_entry(path):
    p = f1(path)
    for name, rx in CREDENTIAL_LIST:
        if rx.search(p):
            return name
    return None


def credential_items(phase):
    out = set()
    for f in phase.get("Files") or []:
        if f.get("Read"):
            e = credential_entry(f.get("Path", ""))
            if e:
                out.add(e)
    return out


# ---------------------------------------------------------------------------------------------
# 5.4 Process spawns

SHELLS = {"sh", "bash", "dash", "zsh"}
TOOLS = {"npm", "npx", "yarn", "pnpm", "pip", "node", "python", "bun"}
INLINE_FLAGS = ("-e", "--eval", "-p", "--print", "-c")
_VERSION = re.compile(r"(?<=[a-z])[0-9][0-9.]*$")
_ENVVAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def p1(arg0):
    return _VERSION.sub("", posixpath.basename(str(arg0)).lower())


def _words(s):
    try:
        return shlex.split(s)
    except ValueError:
        return s.split()


def process_item(argv):
    argv = [str(a) for a in (argv or [])]
    if not argv:
        return None
    if p1(argv[0]) == "env":  # P2
        i = 1
        while i < len(argv) and _ENVVAR.match(argv[i]):
            i += 1
        argv = argv[i:]
        if not argv:
            return "env"
    exe = p1(argv[0])
    if exe in SHELLS and len(argv) >= 3 and argv[1] == "-c":  # P3, applied once
        argv = _words(argv[2])
        if not argv:
            return None
        exe = p1(argv[0])
    if exe in TOOLS:  # P4
        for a in argv[1:]:
            flag = a.split("=", 1)[0] if a.startswith("--") else a
            if flag in INLINE_FLAGS:
                return f3(f"{exe} {flag}")
            if a.startswith("-"):
                continue
            val = posixpath.basename(a.rstrip("/")) if "/" in a else a
            return f3(f"{exe} {val}")
        return f3(exe)
    return exe  # P5


def process_items(phase):
    out = {process_item(c.get("Command")) for c in phase.get("Commands") or []}
    out.discard(None)
    return out


# ---------------------------------------------------------------------------------------------
# Record level


def install_phase(record):
    """Return the install phase object, or None. Key names per the schema (section 2)."""
    a = record.get("Analysis") if isinstance(record, dict) else None
    if not isinstance(a, dict):
        return None
    ph = a.get("install")
    return ph if isinstance(ph, dict) else None


def evaluable(record):
    ph = install_phase(record)
    return ph is not None and ph.get("Status") == "completed"


def items(record, psl):
    ph = install_phase(record)
    return {"network": network_items(ph, psl), "file_write": write_items(ph),
            "credential": credential_items(ph), "process": process_items(ph)}


def new_items(older, newer):
    """5.5: per category, items in the newer record absent from the older one."""
    return {c: newer[c] - older[c] for c in CATEGORIES}
