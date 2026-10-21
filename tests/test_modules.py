import ipaddress
import unittest

from privatetoolbox import actions as act
from privatetoolbox import netinfo
from privatetoolbox.context import Context, Options
from privatetoolbox.modules import BY_ID, PROFILES, select
from privatetoolbox.modules import abuse, dns, firewall, ssh
from tests.helpers import server


def ctx_for(system, **opts):
    return Context(system, Options(**opts))


def kinds(plan, cls):
    return [a for a in plan.actions if isinstance(a, cls)]


def commands(plan):
    return [a.cmd for a in plan.actions if isinstance(a, act.Run)]


class RegistryTests(unittest.TestCase):
    def test_profiles_only_name_real_modules(self):
        for name, ids in PROFILES.items():
            for module_id in ids:
                self.assertIn(module_id, BY_ID, (name, module_id))

    def test_select_keeps_the_safe_order(self):
        ids = [m.id for m in select(["firewall", "bbr", "ssh", "dns"])]
        self.assertEqual(ids, ["dns", "bbr", "ssh", "firewall"])

    def test_ssh_is_planned_before_the_firewall(self):
        order = [m.id for m in select(PROFILES["all"])]
        self.assertLess(order.index("ssh"), order.index("firewall"))


class BbrTests(unittest.TestCase):
    def test_enables_bbr_and_fq(self):
        s = server()
        plan = BY_ID["bbr"].plan(ctx_for(s))
        keys = {a.key: a.value for a in kinds(plan, act.Sysctl)}
        self.assertEqual(keys, {"net.core.default_qdisc": "fq",
                                "net.ipv4.tcp_congestion_control": "bbr"})

    def test_loads_the_module_when_bbr_is_not_listed(self):
        s = server()
        s.set_sysctl("net.ipv4.tcp_available_congestion_control", "reno cubic")
        plan = BY_ID["bbr"].plan(ctx_for(s))
        self.assertIn(["modprobe", "tcp_bbr"], commands(plan))

    def test_skips_when_the_kernel_cannot_do_bbr(self):
        s = server(responses=[(("modinfo",), (1, "not found"))])
        s.set_sysctl("net.ipv4.tcp_available_congestion_control", "reno cubic")
        self.assertEqual(BY_ID["bbr"].plan(ctx_for(s)).skip[0], "bbr_unsupported")

    def test_already_on(self):
        s = server()
        s.set_sysctl("net.ipv4.tcp_congestion_control", "bbr")
        s.set_sysctl("net.core.default_qdisc", "fq")
        self.assertEqual(BY_ID["bbr"].scan(ctx_for(s)).status, "ok")
        self.assertTrue(BY_ID["bbr"].plan(ctx_for(s)).empty)


class SysctlTests(unittest.TestCase):
    def test_only_keys_that_exist_are_touched(self):
        s = server()
        plan = BY_ID["sysctl"].plan(ctx_for(s))
        keys = {a.key for a in kinds(plan, act.Sysctl)}
        self.assertIn("net.ipv4.tcp_syncookies", keys)
        self.assertNotIn("kernel.dmesg_restrict", keys)       # not present on this fake kernel

    def test_rp_filter_is_loose_not_strict(self):
        plan = BY_ID["sysctl"].plan(ctx_for(server()))
        values = {a.key: a.value for a in kinds(plan, act.Sysctl)}
        self.assertEqual(values["net.ipv4.conf.all.rp_filter"], "2")


class FirewallTests(unittest.TestCase):
    def test_normalize_port(self):
        self.assertEqual(firewall.normalize_port("443"), "443")
        self.assertEqual(firewall.normalize_port("51820/udp"), "51820/udp")
        self.assertEqual(firewall.normalize_port("1000:2000"), "1000:2000/tcp")
        for bad in ("0", "70000", "abc", "22/icmp", "2000:1000", "22; reboot"):
            self.assertIsNone(firewall.normalize_port(bad), bad)

    def test_ssh_and_listening_ports_are_allowed(self):
        plan = BY_ID["firewall"].plan(ctx_for(server()))
        rules = [c[2] for c in commands(plan) if c[:2] == ["ufw", "allow"]]
        self.assertEqual(rules[0], "22/tcp")
        self.assertIn("443/tcp", rules)
        self.assertIn("51820/udp", rules)                      # 0xCA6C
        self.assertNotIn("5432/tcp", rules)
        self.assertNotIn("5400/tcp", rules)                    # loopback only (0x1538)

    def test_dhcp_client_port_is_not_opened(self):
        rules = [c[2] for c in commands(BY_ID["firewall"].plan(ctx_for(server()))) if c[:2] == ["ufw", "allow"]]
        self.assertNotIn("68/udp", rules)

    def test_ssh_is_allowed_before_the_firewall_is_enabled(self):
        cmds = commands(BY_ID["firewall"].plan(ctx_for(server())))
        self.assertLess(cmds.index(["ufw", "allow", "22/tcp", "comment", "privatetoolbox"]),
                        cmds.index(["ufw", "--force", "enable"]))

    def test_admin_session_port_is_always_allowed(self):
        s = server(env={"SSH_CONNECTION": "203.0.113.9 50000 10.0.0.5 2222"},
                   responses=[(("sshd", "-T"), (1, "denied"))])
        rules = [c[2] for c in commands(BY_ID["firewall"].plan(ctx_for(s))) if c[:2] == ["ufw", "allow"]]
        self.assertIn("2222/tcp", rules)

    def test_extra_exclude_and_invalid_ports(self):
        opts = dict(extra_ports=["8443", "bad"], exclude_ports=["443"])
        plan = BY_ID["firewall"].plan(ctx_for(server(), **opts))
        rules = [c[2] for c in commands(plan) if c[:2] == ["ufw", "allow"]]
        self.assertIn("8443", rules)
        self.assertNotIn("443/tcp", rules)
        self.assertEqual(plan.warnings[0][0], "fw_bad_port")

    def test_no_discover_keeps_only_ssh(self):
        plan = BY_ID["firewall"].plan(ctx_for(server(), discover=False))
        rules = [c[2] for c in commands(plan) if c[:2] == ["ufw", "allow"]]
        self.assertEqual(rules, ["22/tcp"])

    def test_forwarding_servers_get_an_accept_policy(self):
        s = server()
        s.set_sysctl("net.ipv4.ip_forward", "1")
        plan = BY_ID["firewall"].plan(ctx_for(s))
        writes = kinds(plan, act.WriteFile)
        self.assertIn('DEFAULT_FORWARD_POLICY="ACCEPT"', writes[0].content)

    def test_plain_servers_keep_the_forward_policy(self):
        self.assertEqual(kinds(BY_ID["firewall"].plan(ctx_for(server())), act.WriteFile), [])

    def test_installs_ufw_when_missing(self):
        s = server()
        s.bins.discard("ufw")
        self.assertTrue(kinds(BY_ID["firewall"].plan(ctx_for(s)), act.Install))

    def test_docker_warning(self):
        plan = BY_ID["firewall"].plan(ctx_for(server(bins=["docker"])))
        self.assertIn("fw_docker", [w[0] for w in plan.warnings])

    def test_undo_disables_ufw_if_it_was_off(self):
        plan = BY_ID["firewall"].plan(ctx_for(server()))
        self.assertEqual(kinds(plan, act.Snapshot)[0].undo_after, ["ufw", "--force", "disable"])

    def test_undo_reloads_ufw_if_it_was_on(self):
        s = server(responses=[(("ufw", "status"), (0, "Status: active\n"))])
        plan = BY_ID["firewall"].plan(ctx_for(s))
        self.assertEqual(kinds(plan, act.Snapshot)[0].undo_after, ["ufw", "reload"])

    def test_leaves_firewalld_alone(self):
        s = server(responses=[(("systemctl", "is-active", "firewalld"), (0, "active\n"))])
        self.assertEqual(BY_ID["firewall"].plan(ctx_for(s)).skip[0], "fw_firewalld")


class SshTests(unittest.TestCase):
    def test_dropin_validates_before_reloading(self):
        plan = BY_ID["ssh"].plan(ctx_for(server()))
        write = kinds(plan, act.WriteFile)[0]
        self.assertEqual(write.path, "/etc/ssh/sshd_config.d/00-privatetoolbox.conf")
        self.assertEqual(write.validate, ["sshd", "-t"])
        self.assertEqual(write.after, ["systemctl", "reload", "ssh"])
        self.assertIn("MaxAuthTries 3", write.content)

    def test_root_password_login_stays_without_any_key(self):
        s = server()
        s.remove("/root/.ssh/authorized_keys")
        plan = BY_ID["ssh"].plan(ctx_for(s))
        self.assertNotIn("PermitRootLogin", kinds(plan, act.WriteFile)[0].content)
        self.assertEqual(plan.warnings[0][0], "ssh_root_kept")

    def test_keys_only_needs_a_key_for_the_admin(self):
        s = server()
        s.remove("/root/.ssh/authorized_keys")
        plan = BY_ID["ssh"].plan(ctx_for(s, ssh_keys_only=True))
        self.assertNotIn("PasswordAuthentication no", kinds(plan, act.WriteFile)[0].content)
        self.assertIn("ssh_no_admin_key", [w[0] for w in plan.warnings])

    def test_keys_only_with_a_key(self):
        plan = BY_ID["ssh"].plan(ctx_for(server(), ssh_keys_only=True))
        content = kinds(plan, act.WriteFile)[0].content
        self.assertIn("PasswordAuthentication no", content)
        self.assertIn("KbdInteractiveAuthentication no", content)

    def test_old_openssh_uses_the_old_directive(self):
        s = server(responses=[(("ssh", "-V"), (0, "OpenSSH_7.4p1\n"))])
        content = kinds(BY_ID["ssh"].plan(ctx_for(s, ssh_keys_only=True)), act.WriteFile)[0].content
        self.assertIn("ChallengeResponseAuthentication no", content)

    def test_new_port_keeps_the_old_one_listening(self):
        content = kinds(BY_ID["ssh"].plan(ctx_for(server(), ssh_port=2200)), act.WriteFile)[0].content
        self.assertIn("Port 22\n", content)
        self.assertIn("Port 2200\n", content)

    def test_skips_without_dropin_support(self):
        s = server(files={"/etc/ssh/sshd_config": "Port 22\n"})
        self.assertEqual(BY_ID["ssh"].plan(ctx_for(s)).skip[0], "ssh_no_dropin")

    def test_scan_flags_weak_settings(self):
        finding = BY_ID["ssh"].scan(ctx_for(server()))
        self.assertEqual(finding.status, "todo")
        self.assertIn("root", finding.params["weak"])

    def test_parsers(self):
        self.assertEqual(ssh.openssh_version("OpenSSH_9.2p1 Debian"), (9, 2))
        self.assertEqual(ssh.parse_sshd_t("port 22\nport 2200\nmaxauthtries 3")["port"], "22")
        self.assertTrue(ssh.has_key("# c\nssh-ed25519 AAA x"))
        self.assertFalse(ssh.has_key("# only a comment\n\n"))


class Fail2banAndUpdatesTests(unittest.TestCase):
    def test_admin_ip_is_never_banned(self):
        plan = BY_ID["fail2ban"].plan(ctx_for(server()))
        content = kinds(plan, act.WriteFile)[0].content
        self.assertIn("203.0.113.9", content)
        self.assertIn("[sshd]", content)

    def test_installs_when_missing(self):
        s = server()
        s.bins.discard("fail2ban-client")
        self.assertTrue(kinds(BY_ID["fail2ban"].plan(ctx_for(s)), act.Install))

    def test_unattended_upgrades(self):
        plan = BY_ID["updates"].plan(ctx_for(server()))
        self.assertIn('Unattended-Upgrade "1"', kinds(plan, act.WriteFile)[0].content)


class AbuseTests(unittest.TestCase):
    def nets(self, profile="minimal", protect=()):
        return abuse.blocked_networks(profile, protect)

    def covers(self, nets, address):
        ip = ipaddress.ip_address(address)
        return any(ip in n for n in nets)

    def test_private_ranges_are_blocked(self):
        nets = self.nets()
        for address in ("10.5.5.5", "172.20.0.1", "192.168.1.1"):
            self.assertTrue(self.covers(nets, address), address)

    def test_public_addresses_are_not(self):
        self.assertFalse(self.covers(self.nets("aggressive"), "8.8.8.8"))

    def test_own_subnet_gateway_and_dns_are_carved_out(self):
        nets = self.nets(protect=["10.0.0.5", "10.0.0.1", "10.0.0.2"])
        for address in ("10.0.0.5", "10.0.0.1", "10.0.0.2", "10.0.0.77"):
            self.assertFalse(self.covers(nets, address), address)
        self.assertTrue(self.covers(nets, "10.9.9.9"))

    def test_cloud_metadata_address_stays_reachable(self):
        self.assertFalse(self.covers(self.nets(), "169.254.169.254"))
        self.assertTrue(self.covers(self.nets(), "169.254.10.10"))

    def test_aggressive_adds_ranges(self):
        self.assertTrue(self.covers(self.nets("aggressive"), "100.64.1.1"))
        self.assertFalse(self.covers(self.nets("minimal"), "100.64.1.1"))

    def test_replies_to_inbound_connections_are_never_dropped(self):
        text = abuse.render_nft("t", self.nets(), False)
        self.assertLess(text.index("ct state established,related accept"), text.index("drop"))

    def test_smtp_block_is_opt_in(self):
        self.assertNotIn("dport", abuse.render_nft("t", self.nets(), False))
        self.assertIn("25, 465, 587", abuse.render_nft("t", self.nets(), True))

    def test_plan_writes_conf_unit_and_enables_service(self):
        plan = BY_ID["abuse"].plan(ctx_for(server()))
        paths = [a.path for a in kinds(plan, act.WriteFile)]
        self.assertIn("/etc/privatetoolbox/abuse.nft", paths)
        self.assertIn("/etc/systemd/system/privatetoolbox-abuse.service", paths)
        self.assertEqual(kinds(plan, act.Service)[0].name, "privatetoolbox-abuse")


class DnsTests(unittest.TestCase):
    def fake_bench(self, results):
        return lambda: results

    def results(self):
        return [{"id": "cloudflare", "ips": ["1.1.1.1", "1.0.0.1"], "median_ms": 8.0, "fail": 0, "total": 10},
                {"id": "google", "ips": ["8.8.8.8", "8.8.4.4"], "median_ms": 14.0, "fail": 0, "total": 10},
                {"id": "quad9", "ips": ["9.9.9.9", "149.112.112.112"], "median_ms": None, "fail": 10, "total": 10}]

    def make(self, system, choice="auto"):
        return Context(system, Options(dns=choice), dns_benchmark=self.fake_bench(self.results()))

    def test_picks_the_fastest_and_writes_resolved_conf(self):
        s = server(files={"/lib/systemd/system/systemd-resolved.service": ""})
        plan = BY_ID["dns"].plan(self.make(s))
        content = kinds(plan, act.WriteFile)[0].content
        self.assertIn("DNS=1.1.1.1 1.0.0.1", content)
        self.assertIn("FallbackDNS=8.8.8.8 8.8.4.4", content)

    def test_explicit_choice(self):
        s = server(files={"/lib/systemd/system/systemd-resolved.service": ""})
        plan = BY_ID["dns"].plan(self.make(s, "google"))
        self.assertIn("DNS=8.8.8.8 8.8.4.4", kinds(plan, act.WriteFile)[0].content)

    def test_unreachable_choice_is_refused(self):
        s = server(files={"/lib/systemd/system/systemd-resolved.service": ""})
        self.assertEqual(BY_ID["dns"].plan(self.make(s, "quad9")).skip[0], "dns_unreachable")

    def test_keep(self):
        self.assertEqual(BY_ID["dns"].plan(self.make(server(), "keep")).skip[0], "dns_keep")

    def test_plain_resolv_conf(self):
        plan = BY_ID["dns"].plan(self.make(server()))
        self.assertEqual(kinds(plan, act.WriteFile)[0].path, "/etc/resolv.conf")

    def test_managed_resolv_conf_is_left_alone(self):
        s = server()
        s.links.add("/etc/resolv.conf")
        self.assertEqual(BY_ID["dns"].plan(self.make(s)).skip[0], "dns_managed")

    def test_nothing_usable(self):
        ctx = Context(server(), Options(), dns_benchmark=lambda: [
            {"id": "x", "ips": ["1.1.1.1"], "median_ms": None, "fail": 10, "total": 10}])
        self.assertEqual(BY_ID["dns"].plan(ctx).skip[0], "dns_none_usable")

    def test_benchmark_ranks_by_failures_then_speed(self):
        table = {"1.1.1.1": [5, 6], "8.8.8.8": [3, 4], "9.9.9.9": [None, 2]}

        def query(server_ip, name):
            return table[server_ip][0 if name == "a.test" else 1]
        ranked = dns.benchmark({"cf": ("1.1.1.1",), "gg": ("8.8.8.8",), "q9": ("9.9.9.9",)},
                               names=("a.test", "b.test"), rounds=1, query=query)
        self.assertEqual([r["id"] for r in ranked], ["gg", "cf", "q9"])
        self.assertEqual(ranked[2]["fail"], 1)

    def test_wire_format(self):
        query = dns.build_query("example.com", 0x1234)
        self.assertEqual(query[:2], b"\x12\x34")
        self.assertTrue(query.endswith(b"\x00\x00\x01\x00\x01"))
        reply = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        self.assertTrue(dns.answer_ok(reply, 0x1234))
        self.assertFalse(dns.answer_ok(reply, 0x9999))
        self.assertFalse(dns.answer_ok(b"\x12\x34\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00", 0x1234))


class TuningTests(unittest.TestCase):
    def test_ipv6_is_not_disabled_over_an_ipv6_session(self):
        s = server(env={"SSH_CONNECTION": "2001:db8::1 50000 2001:db8::2 22"})
        self.assertEqual(BY_ID["ipv6"].plan(ctx_for(s)).skip[0], "ipv6_ssh_session")

    def test_ipv6_off_over_ipv4(self):
        plan = BY_ID["ipv6"].plan(ctx_for(server()))
        self.assertEqual(len(kinds(plan, act.Sysctl)), 2)

    def test_swap_for_small_servers(self):
        plan = BY_ID["swap"].plan(ctx_for(server()))
        self.assertIn(["fallocate", "-l", "1024M", "/swapfile"], commands(plan))
        self.assertIn("/swapfile none swap sw 0 0", kinds(plan, act.WriteFile)[0].content)

    def test_no_swap_on_big_servers(self):
        s = server(files={"/proc/meminfo": "MemTotal: 16000000 kB\nSwapTotal: 0 kB\n"})
        self.assertTrue(BY_ID["swap"].plan(ctx_for(s)).empty)

    def test_swap_needs_disk_space(self):
        s = server()
        s.free_bytes = lambda path: 100 * 1024 * 1024
        self.assertEqual(BY_ID["swap"].plan(ctx_for(s)).skip[0], "swap_no_space")

    def test_time_sync_enables_timesyncd(self):
        s = server(files={"/lib/systemd/system/systemd-timesyncd.service": ""})
        plan = BY_ID["timesync"].plan(ctx_for(s))
        self.assertEqual(kinds(plan, act.Service)[0].name, "systemd-timesyncd")

    def test_mss_only_matters_for_routers(self):
        self.assertEqual(BY_ID["mss"].scan(ctx_for(server())).status, "na")
        s = server()
        s.set_sysctl("net.ipv4.ip_forward", "1")
        self.assertEqual(BY_ID["mss"].scan(ctx_for(s)).status, "todo")

    def test_journald_limit(self):
        plan = BY_ID["journald"].plan(ctx_for(server()))
        self.assertIn("SystemMaxUse=200M", kinds(plan, act.WriteFile)[0].content)


class NetinfoTests(unittest.TestCase):
    def test_public_listeners_ignore_loopback(self):
        found = netinfo.public_listeners(server())
        self.assertIn(("tcp", 22), found)
        self.assertNotIn(("tcp", 0x1538), found)

    def test_ssh_connection(self):
        self.assertEqual(netinfo.parse_ssh_connection("1.2.3.4 5555 10.0.0.5 22")["server_port"], 22)
        self.assertIsNone(netinfo.parse_ssh_connection("garbage"))

    def test_ss_fallback_finds_the_session(self):
        line = 'ESTAB 0 0 10.0.0.5:2222 198.51.100.4:41000 users:(("sshd",pid=900,fd=4))'
        found = netinfo.parse_ss_sessions(line, [900])
        self.assertEqual((found["client_ip"], found["server_port"]), ("198.51.100.4", 2222))
        self.assertIsNone(netinfo.parse_ss_sessions(line, [901]))

    def test_session_family(self):
        self.assertTrue(netinfo.session_is_ipv6({"client_ip": "2001:db8::1"}))
        self.assertFalse(netinfo.session_is_ipv6({"client_ip": "1.2.3.4"}))
        self.assertFalse(netinfo.session_is_ipv6(None))


if __name__ == "__main__":
    unittest.main()
