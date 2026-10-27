"""VPN profile manager for SigmaOS-vpn-pia (pia-manager-inspired).

The engine manages region profiles (validated on load/save), plans OpenVPN
connections (config rendering + argv), parses connection status dumps and
plans kill-switch firewall rules via the stdlib ipaddress module. Bringing
the tunnel up or touching iptables is the thin execute layer -- self_test()
only exercises the pure plan/parse/validate layer (no subprocess, no root).
Principles: Defensive Programming, Fail-Fast, Separation of Concerns, KISS.
"""
import argparse, ipaddress, json, os, re, sys

ENGINE = {
    "name": "sigma-vpn",
    "summary": "Manage VPN profiles, connection plans, status and kill switch",
    "language": "python",
    "verbs": ["profiles", "connect-plan", "status", "killswitch-plan"],
    "principles": ["Defensive Programming", "Fail-Fast",
                   "Separation of Concerns", "KISS", "Deterministic Testing"],
}

cli_doc = """\
$ sigma-vpn profiles
AU  au.privateinternetaccess.com:1198/udp
$ sigma-vpn connect-plan US-East
remote us-east.privateinternetaccess.com 1198
$ sigma-vpn status status.txt
CONNECTED  in=1048576 out=262144
$ sigma-vpn killswitch-plan on --iface tun0 --vpn-net 10.8.0.0/24
iptables -I OUTPUT -o tun0 -j ACCEPT ...
"""


class VpnError(Exception):
    pass


DEFAULT_PROFILES = {
    "US-East": {"server": "us-east.privateinternetaccess.com", "port": 1198,
                "proto": "udp", "country": "US"},
    "US-West": {"server": "us-west.privateinternetaccess.com", "port": 1198,
                "proto": "udp", "country": "US"},
    "DE": {"server": "germany.privateinternetaccess.com", "port": 1198,
           "proto": "udp", "country": "DE"},
    "NL": {"server": "netherlands.privateinternetaccess.com", "port": 1198,
           "proto": "udp", "country": "NL"},
    "AU": {"server": "au.privateinternetaccess.com", "port": 1198,
           "proto": "udp", "country": "AU"},
}
_IFACE_RE = re.compile(r"^[a-z][a-z0-9._-]*$")
_SERVER_RE = re.compile(r"^[A-Za-z0-9.-]+$")


# --------------------------------------------------------------------------- #
#  PURE plan / parse layer
# --------------------------------------------------------------------------- #
def validate_profile(name, prof):
    """Validate one profile record; returns a normalised copy."""
    if not isinstance(prof, dict):
        raise VpnError(f"profile {name!r} must be an object")
    server = prof.get("server")
    if not isinstance(server, str) or not _SERVER_RE.match(server):
        raise VpnError(f"profile {name!r}: bad server {server!r}")
    port = prof.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        raise VpnError(f"profile {name!r}: bad port {port!r}")
    proto = prof.get("proto", "udp")
    if proto not in ("udp", "tcp"):
        raise VpnError(f"profile {name!r}: bad proto {proto!r}")
    return {"server": server, "port": port, "proto": proto,
            "country": str(prof.get("country", ""))}


def resolve_region(region, profiles=None):
    """Resolve a region name (case-insensitively) -> (name, profile)."""
    profiles = DEFAULT_PROFILES if profiles is None else profiles
    if not isinstance(profiles, dict) or not profiles:
        raise VpnError("no profiles available")
    if region in profiles:
        return region, validate_profile(region, profiles[region])
    lowered = {k.lower(): k for k in profiles}
    key = lowered.get((region or "").strip().lower())
    if key is None:
        raise VpnError(f"unknown region {region!r}; "
                       f"available: {', '.join(sorted(profiles))}")
    return key, validate_profile(key, profiles[key])


def load_profiles(path):
    """Load and validate a JSON profile store."""
    if not os.path.exists(path):
        raise VpnError(f"no profile store at {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        raise VpnError(f"bad profile store: {e}") from e
    if not isinstance(data, dict) or not data:
        raise VpnError("profile store must be a non-empty JSON object")
    for name in data:
        validate_profile(name, data[name])
    return data


def save_profiles(path, profiles):
    """Validate then atomically-ish write a JSON profile store."""
    if not isinstance(profiles, dict) or not profiles:
        raise VpnError("profile store must be a non-empty dict")
    for name, prof in profiles.items():
        validate_profile(name, prof)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(profiles, fh, indent=2, sort_keys=True)


def render_ovpn(profile):
    """Render an OpenVPN client config for a validated profile."""
    p = validate_profile("?", profile)
    return ("client\n"
            "dev tun\n"
            f"proto {p['proto']}\n"
            f"remote {p['server']} {p['port']}\n"
            "resolv-retry infinite\n"
            "nobind\n"
            "persist-key\n"
            "persist-tun\n"
            "remote-cert-tls server\n"
            "cipher AES-256-GCM\n"
            "verb 3\n")


def connect_plan(region, profiles=None, config_dir="/etc/openvpn"):
    """Plan an OpenVPN connection: config text + argv (pure)."""
    name, prof = resolve_region(region, profiles)
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    config_path = os.path.join(config_dir, f"{slug}.ovpn")
    argv = ["openvpn", "--config", config_path, "--auth-nocache",
            "--script-security", "2", "--askpass",
            os.path.join(config_dir, "auth.txt")]
    return {"region": name, "profile": prof, "config_path": config_path,
            "config": render_ovpn(prof), "argv": argv}


def parse_status(text):
    """Parse an OpenVPN-ish status dump into connection facts."""
    kv = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        kv[key.strip().upper().replace(" ", "_")] = value.strip()
    if "STATE" not in kv:
        raise VpnError("status dump has no STATE line")
    state = kv["STATE"].upper()

    def _num(key):
        try:
            return int(kv.get(key, "0").replace(",", "").replace(" ", ""))
        except ValueError:
            raise VpnError(f"status field {key} is not numeric")

    return {"state": state, "connected": state.startswith("CONNECTED"),
            "bytes_in": _num("BYTES_IN"), "bytes_out": _num("BYTES_OUT"),
            "remote": kv.get("REMOTE", "")}


def killswitch_plan(mode, iface="tun0", vpn_net="10.8.0.0/24"):
    """Plan iptables kill-switch rules (enable or disable)."""
    if mode not in ("on", "off"):
        raise VpnError(f"killswitch mode must be 'on' or 'off', got {mode!r}")
    if not isinstance(iface, str) or not _IFACE_RE.match(iface):
        raise VpnError(f"bad interface name: {iface!r}")
    try:
        net = str(ipaddress.ip_network(vpn_net, strict=False))
    except ValueError as e:
        raise VpnError(f"bad VPN network: {vpn_net!r}") from e
    accept_vpn = ["iptables", "-D" if mode == "off" else "-I", "OUTPUT",
                  "-d", net, "-j", "ACCEPT"]
    accept_iface = ["iptables", "-D" if mode == "off" else "-I", "OUTPUT",
                    "-o", iface, "-j", "ACCEPT"]
    block = (["iptables", "-D" if mode == "off" else "-A", "OUTPUT", "-j", "REJECT",
              "--reject-with", "icmp-port-unreachable"])
    if mode == "on":
        rules = [accept_iface, accept_vpn, block]      # allow VPN, drop rest
    else:
        rules = [block, accept_vpn, accept_iface]      # unwind in reverse
    return {"mode": mode, "iface": iface, "network": net, "rules": rules}


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=ENGINE["name"], description=ENGINE["summary"])
    p.add_argument("--store", default=os.path.expanduser(
        "~/.config/sigma-vpn/profiles.json"), help="profile store path")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("profiles", help="list region profiles")
    cp = sub.add_parser("connect-plan", help="plan an OpenVPN connection")
    cp.add_argument("region")
    cp.add_argument("--config-dir", default="/etc/openvpn")
    st = sub.add_parser("status", help="parse a status dump")
    st.add_argument("file")
    ks = sub.add_parser("killswitch-plan", help="plan kill-switch firewall rules")
    ks.add_argument("mode", choices=["on", "off"])
    ks.add_argument("--iface", default="tun0")
    ks.add_argument("--vpn-net", default="10.8.0.0/24")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "profiles":
            profiles = (load_profiles(args.store) if os.path.exists(args.store)
                        else DEFAULT_PROFILES)
            for name in sorted(profiles):
                p = validate_profile(name, profiles[name])
                print(f'{name:<10} {p["server"]}:{p["port"]}/{p["proto"]} '
                      f'({p["country"]})')
        elif args.cmd == "connect-plan":
            plan = connect_plan(args.region, None, args.config_dir)
            print(plan["config"], end="")
            print("# argv: " + " ".join(plan["argv"]))
        elif args.cmd == "status":
            with open(args.file, "r", encoding="utf-8") as fh:
                s = parse_status(fh.read())
            verb = "CONNECTED" if s["connected"] else s["state"]
            print(f'{verb}  in={s["bytes_in"]} out={s["bytes_out"]}'
                  + (f'  via {s["remote"]}' if s["remote"] else ""))
            return 0 if s["connected"] else 1
        elif args.cmd == "killswitch-plan":
            plan = killswitch_plan(args.mode, args.iface, args.vpn_net)
            for rule in plan["rules"]:
                print(" ".join(rule))
        return 0
    except (VpnError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


# --------------------------------------------------------------------------- #
#  Tests (pure plan/parse/validate layer; store I/O limited to tempfile)
# --------------------------------------------------------------------------- #
SAMPLE_STATUS = """\
# openvpn status dump
2026-10-24 09:15:02 OpenVPN 2.6.2 starting
STATE      : CONNECTED
REMOTE     : us-east.privateinternetaccess.com:1198/udp
BYTES IN   : 1,048,576
BYTES OUT  : 262144
"""


def self_test() -> None:
    assert len(DEFAULT_PROFILES) >= 4
    for name, prof in DEFAULT_PROFILES.items():
        validate_profile(name, prof)
        assert prof["port"] == 1198 and prof["proto"] == "udp"
    for bad in ({"server": "x.example.com", "port": 99999},
                {"server": "bad server!", "port": 1198},
                {"server": "x.example.com", "port": "1198"},
                {"server": "", "port": 1198},
                {"server": "x.example.com", "port": 1, "proto": "icmp"}):
        try:
            validate_profile("X", bad)
        except VpnError:
            pass
        else:
            raise AssertionError(f"bad profile not rejected: {bad!r}")

    name, prof = resolve_region("us-east")
    assert name == "US-East" and prof["server"].startswith("us-east.")
    name, _ = resolve_region("  de ")
    assert name == "DE"
    try:
        resolve_region("Atlantis")
    except VpnError as e:
        assert "available" in str(e)
    else:
        raise AssertionError("unknown region not rejected")

    plan = connect_plan("US-East")
    assert plan["config_path"] == "/etc/openvpn/us-east.ovpn"
    cfg = plan["config"]
    assert "remote us-east.privateinternetaccess.com 1198" in cfg, cfg
    assert "proto udp" in cfg and "dev tun" in cfg and cfg.endswith("\n")
    assert plan["argv"][:2] == ["openvpn", "--config"]
    assert plan["argv"][2] == "/etc/openvpn/us-east.ovpn"
    tcp = {"T1": {"server": "t1.example.com", "port": 443, "proto": "tcp"}}
    assert "proto tcp" in connect_plan("T1", tcp)["config"]
    assert connect_plan("T1", tcp, config_dir="/opt/vpn")["config_path"] == \
        "/opt/vpn/t1.ovpn"

    status = parse_status(SAMPLE_STATUS)
    assert status["connected"] is True and status["state"] == "CONNECTED"
    assert status["bytes_in"] == 1048576 and status["bytes_out"] == 262144
    assert status["remote"].startswith("us-east.")
    down = "STATE: RECONNECTING\nBYTES IN: 0\nBYTES OUT: 0\n"
    assert parse_status(down)["connected"] is False
    gone = "STATE: EXITING\nBYTES IN: 5\nBYTES OUT: 6\n"
    assert parse_status(gone)["connected"] is False
    for bad in ("", "no state here\n", "STATE: CONNECTED\nBYTES IN: x\n"):
        try:
            parse_status(bad)
        except VpnError:
            pass
        else:
            raise AssertionError(f"bad status dump not rejected: {bad!r}")

    on = killswitch_plan("on", "tun0", "10.8.0.0/24")
    assert on["network"] == "10.8.0.0/24"
    assert len(on["rules"]) == 3
    assert on["rules"][0] == ["iptables", "-I", "OUTPUT", "-o", "tun0", "-j", "ACCEPT"]
    assert on["rules"][1][4] == "10.8.0.0/24"
    assert on["rules"][2][:5] == ["iptables", "-A", "OUTPUT", "-j", "REJECT"]
    off = killswitch_plan("off", "tun0", "10.8.0.0/24")
    assert off["rules"][0][:4] == ["iptables", "-D", "OUTPUT", "-j"]
    assert off["rules"][0][-1] == "icmp-port-unreachable"
    assert off["rules"][2] == ["iptables", "-D", "OUTPUT", "-o", "tun0", "-j", "ACCEPT"]
    assert killswitch_plan("on", "wg0", "fd00::/8")["network"] == "fd00::/8"
    for bad in (("maybe", "tun0", "10.8.0.0/24"),
                ("on", "tun 0", "10.8.0.0/24"),
                ("on", "TUN0", "10.8.0.0/24"),
                ("on", "tun0", "not-a-net"),
                ("on", "", "10.8.0.0/24")):
        try:
            killswitch_plan(*bad)
        except VpnError:
            pass
        else:
            raise AssertionError(f"bad killswitch plan not rejected: {bad!r}")

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        store = os.path.join(d, "profiles.json")
        save_profiles(store, DEFAULT_PROFILES)
        loaded = load_profiles(store)
        assert loaded == DEFAULT_PROFILES
        assert resolve_region("AU", loaded)[0] == "AU"
        bad_store = os.path.join(d, "bad.json")
        with open(bad_store, "w", encoding="utf-8") as fh:
            fh.write('{"X": {"server": "x", "port": 70000}}')
        try:
            load_profiles(bad_store)
        except VpnError:
            pass
        else:
            raise AssertionError("bad profile store not rejected")
        with open(bad_store, "w", encoding="utf-8") as fh:
            fh.write("{}")
        try:
            load_profiles(bad_store)
        except VpnError:
            pass
        else:
            raise AssertionError("empty profile store not rejected")
        try:
            load_profiles(os.path.join(d, "missing.json"))
        except VpnError:
            pass
        else:
            raise AssertionError("missing store not rejected")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
