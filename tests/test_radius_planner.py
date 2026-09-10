"""Synthetic pure DAS planner tests against the real Runtime data structures."""
import copy
from dataclasses import FrozenInstanceError, replace
import itertools
import unittest
from unittest.mock import patch

from switchlab.engine import AccessSession, Runtime
from switchlab.models import Configuration, Endpoint, Port, Source, Switch, Vlan
from switchlab.radius import Authorization, NasIdentity, RadiusError, _DynamicRequest, verify_dynamic_request, dynamic_response, packet_attributes
from test_radius_codec import signed_request, SECRET
from switchlab.radius import plan_dynamic_request


MAC_A = "02:00:00:00:00:11"
MAC_B = "02:00:00:00:00:12"
MAC_C = "02:00:00:00:00:21"
MAC_D = "02:00:00:00:00:22"
MAC_X = "02:00:00:00:00:99"


def u32(value):
    return value.to_bytes(4, "big")


def vlan(vid=30, tag=0):
    return ((64, bytes([tag]) + bytes([0,0,13])),
            (65, bytes([tag]) + bytes([0,0,6])),
            (81, bytes([tag]) + str(vid).encode()))


def request(values, code=43):
    return verify_dynamic_request(signed_request(code, 7, (*values, (55, u32(1)))), SECRET)


def fixture():
    ports = {name: Port(id=name, bridge_port=n, if_index=100+n, name="Ethernet"+str(n),
                       mode="shared", shared_partner=True)
             for n,name in enumerate(("p1","p2","p3"), 1)}
    for port in ports.values():
        port.authentication.control = "auto"
        port.authentication.host_mode = "multi-auth"
    ports["p2"].authentication.host_mode = "multi-host"
    cfg = Configuration(switch=Switch(port_count=3, name="Current NAS"), ports=ports,
                        vlans={v:Vlan(vid=v,fdb_id=1000+v) for v in (1,20,30,40)})
    cfg.radius.nas_ip_address = "192.0.2.9"
    endpoint = Endpoint(id="ep", name="Synthetic", sources=[Source(mac=MAC_C),Source(mac=MAC_D)])
    cfg.endpoints[endpoint.id] = endpoint
    cfg.attachments[endpoint.id] = "p2"
    runtime = Runtime(cfg, epoch="synthetic-epoch", boot_start=0, sim_ms=100_000)
    for name,pid,address in (("a","p1",MAC_A),("b","p1",MAC_B),("c","p2",MAC_C),("d","p3",MAC_A)):
        policy = Authorization(20,"radius",session_timeout=90,idle_timeout=70,
                               classes=(b"class-first",b"class-second"),state=b"prior-state",
                               interim_seconds=120,accounting_warning=None,username=b"accepted-name")
        session = AccessSession(name,pid,address,"tls",policy,started_ms=1_000,last_activity_ms=40_000,
                                grant_generation="grant-"+name,observation_generation="observation-"+name,
                                last_auth_ms=30_000,idle_origin_ms=1_000,lease_deadline_ms=120_000,
                                user_name=b"same-user", accounting_interval=120,accounting_next_ms=121_000,
                                nas_identity=NasIdentity(b"Captured NAS",bytes([192,0,2,9])))
        runtime.radius_sessions[(pid,address)] = session
    runtime.fdb[(1020, MAC_D)] = dict(port_id="p2",mac=MAC_D,vid=20,last_seen_ms=90_000,expires_at_ms=390_000)
    return runtime


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.runtime = fixture()

    def plan(self, values, code=43):
        old = copy.deepcopy(self.runtime)
        req = request(values, code)
        plan = plan_dynamic_request(req, self.runtime)
        self.assertEqual(self.runtime, old, "planner mutated Runtime")
        self.assertEqual(req, request(values,code), "planner mutated verified request")
        return plan

    def nak(self, expected, values, code=43):
        plan = self.plan(values,code)
        self.assertEqual(plan.error_cause, expected)
        self.assertEqual(plan.sessions, ())
        return plan

    def keys(self, plan):
        self.assertIsNone(plan.error_cause)
        return tuple(proposal.key for proposal in plan.sessions)

    def test_mac_only_selects_all_independent_matching_services(self):
        plan = self.plan(((31,MAC_A.encode()),))
        self.assertEqual(self.keys(plan), (("p1",MAC_A),("p3",MAC_A)))
        self.assertEqual(tuple(p.session_id for p in plan.sessions), ("a","d"))

    def test_all_selectors_conjoin(self):
        values = ((31,MAC_A.encode()),(5,u32(1)),(87,b"Ethernet1"),(44,b"a"),(1,b"same-user"),
                  (4,bytes([192,0,2,9])),(32,b"Captured NAS"))
        self.assertEqual(self.keys(self.plan(values)), (("p1",MAC_A),))
        for kind,wrong in ((31,MAC_B.encode()),(5,u32(3)),(87,b"Ethernet3"),(44,b"d"),(1,b"other")):
            with self.subTest(kind=kind):
                self.nak(503, tuple((k,wrong if k == kind else value) for k,value in values))

    def test_old_session_id_never_dropped_to_match_current_mac(self):
        self.nak(503,((31,MAC_A.encode()),(44,b"old-a")))

    def test_session_id_exact_and_not_casefolded(self):
        self.nak(503,((44,b"A"),))
        self.assertEqual(self.keys(self.plan(((44,b"a"),))),(("p1",MAC_A),))

    def test_username_exact_captured_session_not_policy_or_profile(self):
        self.nak(503,((1,b"accepted-name"),))
        self.nak(503,((1,b"SAME-USER"),))
        self.assertEqual(len(self.keys(self.plan(((1,b"same-user"),)))),4)
        self.runtime.radius_sessions[("p1",MAC_A)].user_name = None
        self.assertNotIn(("p1",MAC_A),self.keys(self.plan(((1,b"same-user"),))))

    def test_nas_port_is_bridge_number_not_ifindex(self):
        self.assertEqual(len(self.keys(self.plan(((5,u32(1)),)))),2)
        self.nak(503,((5,u32(101)),))

    def test_port_name_uses_current_interface_name(self):
        self.runtime.cfg.ports["p1"].name = "Renamed"
        self.nak(503,((87,b"Ethernet1"),))
        self.assertEqual(len(self.keys(self.plan(((87,b"Renamed"),)))),2)

    def test_documented_mac_formats(self):
        for value in ("020000000011","02:00:00:00:00:11","02-00-00-00-00-11","0200.0000.0011"):
            with self.subTest(format=value):
                self.assertEqual(len(self.keys(self.plan(((31,value.encode()),)))),2)
        self.runtime.radius_sessions[("p1",MAC_A)].mac = "02:ab:cd:ef:00:11"
        moved = self.runtime.radius_sessions.pop(("p1",MAC_A))
        self.runtime.radius_sessions[("p1",moved.mac)] = moved
        self.assertEqual(self.keys(self.plan(((31,b"02-AB-CD-EF-00-11"),))),(("p1",moved.mac),))

    def test_bad_mac_formats_values(self):
        for value in (b"",b" 020000000011",b"020000000011 ",b"02:00-00:00:00:11",
                      b"02:0:0:0:0:11",b"0200_0000_0011",b"030000000011",b"000000000000",b"\xff"):
            with self.subTest(value_length=len(value)):
                self.nak(407,((31,value),))

    def test_selectors_are_required_but_nas_selector_is_not(self):
        self.nak(402,())
        self.nak(402,((32,b"Captured NAS"),))
        self.nak(402,((33,b"proxy"),))
        self.nak(402,(*vlan(),(24,b"state")))
        self.assertEqual(self.keys(self.plan(((44,b"a"),))),(("p1",MAC_A),))

    def test_nas_matches_capture_not_current_configuration(self):
        self.runtime.cfg.radius.nas_identifier = "Override"
        self.runtime.cfg.radius.nas_ip_address = "192.0.2.10"
        self.runtime.cfg.switch.name = "Renamed"
        self.assertEqual(self.keys(self.plan(((44,b"a"),(32,b"Captured NAS"),(4,bytes([192,0,2,9]))))),
                         (("p1",MAC_A),))
        for name in (b"Override",b"Renamed",b"Current NAS"):
            self.nak(403,((44,b"a"),(32,name)))
        self.nak(403,((44,b"a"),(4,bytes([192,0,2,10]))))
        self.runtime.cfg.radius.nas_ip_address = None
        self.assertEqual(self.keys(self.plan(((44,b"a"),(4,bytes([192,0,2,9]))))),(("p1",MAC_A),))

    def test_nas_filter_selects_only_matching_identity_subset(self):
        self.runtime.radius_sessions[("p3",MAC_A)].nas_identity = NasIdentity(b"Other NAS",bytes([192,0,2,10]))
        self.assertEqual(self.keys(self.plan(((31,MAC_A.encode()),(32,b"Captured NAS")))),(("p1",MAC_A),))
        self.assertEqual(self.keys(self.plan(((31,MAC_A.encode()),(32,b"Other NAS")))),(("p3",MAC_A),))
        self.assertEqual(self.keys(self.plan(((31,MAC_A.encode()),(4,bytes([192,0,2,10]))))),(("p3",MAC_A),))
        # Both fields must belong to one captured identity, not separate sessions.
        self.nak(403,((31,MAC_A.encode()),(32,b"Other NAS"),(4,bytes([192,0,2,9]))))
        self.nak(503,((44,b"a"),(32,b"Other NAS")))
        self.nak(403,((44,b"missing"),(32,b"Absent NAS")))

    def test_missing_capture_or_ipv4_never_uses_config_fallback(self):
        session = self.runtime.radius_sessions[("p1",MAC_A)]
        session.nas_identity = None
        self.nak(503,((44,b"a"),(32,b"Captured NAS")))
        self.assertEqual(self.keys(self.plan(((44,b"a"),))),(("p1",MAC_A),))
        self.runtime.radius_sessions = {("p1",MAC_A):session}
        self.nak(403,((44,b"a"),(32,b"Current NAS")))
        self.nak(403,((44,b"a"),(4,bytes([192,0,2,9]))))
        session.nas_identity = NasIdentity(b"Captured NAS",None)
        self.nak(403,((44,b"a"),(4,bytes([192,0,2,9]))))
        self.assertEqual(self.keys(self.plan(((44,b"a"),(32,b"Captured NAS")))),(("p1",MAC_A),))

    def test_empty_current_sessions_returns_503_with_any_valid_nas(self):
        self.runtime.radius_sessions.clear()
        for attrs in ((),((32,b"Captured NAS"),),((32,b"Absent NAS"),),((4,bytes([192,0,2,10])),)):
            self.nak(503,((44,b"a"),*attrs))

    def test_nas_opaque_exact_identity_no_string_normalization(self):
        self.runtime.radius_sessions[("p1",MAC_A)].nas_identity = NasIdentity(b"\x00private\xff",bytes([192,0,2,9]))
        self.assertEqual(self.keys(self.plan(((44,b"a"),(32,b"\x00private\xff")))),(("p1",MAC_A),))
        for name in (b"captured nas",b"Captured NAS ",b"PRIVATE"):
            self.nak(403,((44,b"a"),(32,name)))

    def test_repeated_any_supported_selector_is_404_before_normalization(self):
        valid = {1:b"same-user",4:bytes([192,0,2,9]),5:u32(1),31:MAC_A.encode(),
                 32:b"Captured NAS",44:b"a",87:b"Ethernet1"}
        for code in (40,43):
            for kind,value in valid.items():
                for duplicate in (value,b"",b"different"):
                    self.nak(404,((kind,value),(kind,duplicate)),code)
        self.nak(404,((31,MAC_A.encode()),(31,b"020000000011")))
        self.nak(404,((31,b"bad"),(31,b"bad")))
        self.nak(404,((32,b"Captured NAS"),(32,b"Captured NAS")))

    def test_repeated_proxy_state_preserved_order_and_not_a_selector(self):
        proxy = ((33,b"second\x00"),(33,b"first\xff"),(33,b"second\x00"))
        self.nak(402,proxy)
        for code,ack in ((40,41),(43,44)):
            values = ((44,b"a"),*proxy)
            plan = self.plan(values,code)
            self.assertEqual(self.keys(plan),(("p1",MAC_A),))
            _, echoed = packet_attributes(dynamic_response(request(values,code),ack,SECRET))
            self.assertEqual(tuple((k,v) for k,v in echoed if k == 33),proxy)

    def test_invalid_selector_lengths_and_empty_strings(self):
        for kind,value in ((4,b"abc"),(4,b"abcde"),(5,b"abc"),(5,b"abcde"),
                           (1,b""),(32,b""),(44,b""),(87,b"")):
            with self.subTest(kind=kind):
                self.nak(407,((31,MAC_A.encode()),(kind,value)))

    def test_unknown_context_does_not_select_pending_attempt(self):
        self.runtime.radius_attempts[("p1",MAC_X)] = object()
        # Object identity equality is unsuitable for the snapshot helper.
        self.runtime.radius_attempts[("p1",MAC_X)] = "synthetic-pending"
        self.nak(503,((31,MAC_X.encode()),))

    def test_vlan_plan_all_matches_atomic_and_immutable(self):
        plan = self.plan(((1,b"same-user"),*vlan(30)))
        self.assertEqual(len(self.keys(plan)),4)
        self.assertTrue(all(p.policy.vid == 30 and p.policy.source == "radius" for p in plan.sessions))
        self.assertTrue(all(s.policy.vid == 20 for s in self.runtime.radius_sessions.values()))
        with self.assertRaises(FrozenInstanceError):
            plan.error_cause = 401
        with self.assertRaises(FrozenInstanceError):
            plan.sessions[0].session_id = "changed"
        with self.assertRaises(FrozenInstanceError):
            plan.sessions[0].policy.vid = 1

    def test_one_forbidden_match_returns_no_partial_proposals(self):
        self.runtime.cfg.ports["p3"].forbidden = [30]
        plan = self.nak(501,((31,MAC_A.encode()),*vlan(30)))
        self.assertEqual(plan.sessions,())
        self.assertEqual(self.runtime.radius_sessions[("p1",MAC_A)].policy.vid,20)

    def test_forbidden_unmatched_port_does_not_block_other_service(self):
        self.runtime.cfg.ports["p3"].forbidden = [30]
        self.assertEqual(self.keys(self.plan(((44,b"a"),*vlan(30)))),(("p1",MAC_A),))

    def test_vlan_only_preserves_other_policy_and_deadlines(self):
        old = self.runtime.radius_sessions[("p1",MAC_A)]
        proposal = self.plan(((44,b"a"),*vlan(30))).sessions[0]
        self.assertEqual(proposal.policy,replace(old.policy,vid=30,source="radius"))
        self.assertEqual(proposal.lease_deadline_ms,120_000)
        self.assertEqual(proposal.idle_deadline_ms,110_000)
        self.assertEqual(proposal.grant_generation,"grant-a")
        self.assertEqual(proposal.session_id,"a")

    def test_inherited_vlan_switches_only_on_explicit_tunnel(self):
        old = self.runtime.radius_sessions[("p1",MAC_A)]
        old.policy = replace(old.policy,source="port-default",vid=1)
        self.runtime.cfg.ports["p1"].pvid = 20
        plain = self.plan(((44,b"a"),(27,u32(10)))).sessions[0]
        self.assertEqual((plain.policy.vid,plain.policy.source),(1,"port-default"))
        explicit = self.plan(((44,b"a"),*vlan(20))).sessions[0]
        self.assertEqual((explicit.policy.vid,explicit.policy.source),(20,"radius"))

    def test_supported_vlan_tags_and_untagged_string(self):
        for tag in (0,1,31):
            with self.subTest(tag=tag):
                self.assertEqual(self.plan(((44,b"a"),*vlan(30,tag))).sessions[0].policy.vid,30)
        self.assertEqual(self.plan(((44,b"a"),(64,u32(13)),(65,u32(6)),(81,b"30"))).sessions[0].policy.vid,30)

    def test_vlan_decimal_by_value_full_attribute_budget_raw_unchanged(self):
        self.runtime.cfg.vlans[4094] = Vlan(vid=4094,fdb_id=5094)
        for tag in (0,1,31):
            for group,expected in ((b"00030",30),(b"0"*250+b"30",30),
                                   (b"0"*248+b"4094",4094),(b"0"*251+b"1",1)):
                attrs = ((44,b"a"),(64,bytes([tag,0,0,13])),(65,bytes([tag,0,0,6])),
                         (81,bytes([tag])+group))
                req = request(attrs)
                original = req.packet
                plan = self.plan(attrs)
                self.assertEqual(plan.sessions[0].policy.vid,expected)
                self.assertEqual(req.packet,original)
                self.assertIn((81,bytes([tag])+group),req.attributes)
        for group,expected in ((b"0"*251+b"30",30),(b"0"*249+b"4094",4094)):
            plan = self.plan(((44,b"a"),(64,u32(13)),(65,u32(6)),(81,group)))
            self.assertEqual(plan.sessions[0].policy.vid,expected)
        for group in (b"0"*253,b"9"*253,b"\xb2",b"30 ","٣٠".encode("utf-8")):
            self.nak(407,((44,b"a"),(64,u32(13)),(65,u32(6)),(81,group)))

    def test_missing_vlan_triple_members_never_fill_from_old_policy(self):
        triple = vlan()
        for n in (1,2):
            for subset in itertools.combinations(triple,n):
                self.nak(402,((44,b"a"),*subset))

    def test_invalid_vlan_values_and_grouping(self):
        bad = (
            ((64,u32(12)),(65,u32(6)),(81,b"30")),
            ((64,u32(13)),(65,u32(5)),(81,b"30")),
            ((64,b"abc"),(65,u32(6)),(81,b"30")),
            ((64,u32(13)),(65,b"abcde"),(81,b"30")),
            ((64,bytes([32,0,0,13])),(65,u32(6)),(81,b"30")),
            ((64,bytes([1,0,0,13])),(65,u32(6)),(81,b"\x0130")),
            ((64,bytes([1,0,0,13])),(65,bytes([1,0,0,6])),(81,b"30")),
        )
        for triple in bad:
            with self.subTest(case=bad.index(triple)):
                self.nak(407,((44,b"a"),*triple))
        for group in (b"",b"\x00",b"0",b"4095",b"VLAN30",b"+30",b" 30",b"30\x00",b"999",b"\xff30"):
            with self.subTest(group_length=len(group)):
                self.nak(407,((44,b"a"),(64,u32(13)),(65,u32(6)),(81,group)))

    def test_duplicate_vlan_members_rejected(self):
        for attribute in vlan():
            self.nak(407,((44,b"a"),*vlan(),attribute))
        self.nak(407,((44,b"a"),*vlan(30,1),*vlan(40,2)))

    def test_session_timeout_starts_at_commit_simulation_time(self):
        proposal = self.plan(((44,b"a"),(27,u32(15)))).sessions[0]
        self.assertEqual(proposal.policy.session_timeout,15)
        self.assertEqual(proposal.lease_deadline_ms,115_000)
        self.assertEqual(proposal.idle_deadline_ms,110_000)
        self.runtime.sim_ms = 200_000
        self.assertEqual(self.plan(((44,b"a"),(27,u32(15)))).sessions[0].lease_deadline_ms,215_000)

    def test_idle_timeout_uses_true_last_activity_or_idle_origin(self):
        proposal = self.plan(((44,b"a"),(28,u32(5)))).sessions[0]
        self.assertEqual(proposal.policy.idle_timeout,5)
        self.assertEqual(proposal.idle_deadline_ms,45_000)
        self.assertEqual(proposal.lease_deadline_ms,120_000)
        session = self.runtime.radius_sessions[("p1",MAC_A)]
        session.last_activity_ms = None
        self.assertEqual(self.plan(((44,b"a"),(28,u32(5)))).sessions[0].idle_deadline_ms,6_000)
        session.last_activity_ms = 0
        self.assertEqual(self.plan(((44,b"a"),(28,u32(5)))).sessions[0].idle_deadline_ms,5_000)

    def test_zero_limits_are_not_disabled_and_do_not_execute(self):
        for action in (0,1):
            with self.subTest(action=action):
                proposal = self.plan(((44,b"a"),(27,u32(0)),(28,u32(0)),(29,u32(action)))).sessions[0]
                self.assertEqual(proposal.lease_deadline_ms,100_000)
                self.assertEqual(proposal.idle_deadline_ms,40_000)
                self.assertEqual(proposal.policy.termination_action,action)
                self.assertIn(("p1",MAC_A),self.runtime.radius_sessions)
                self.assertEqual(self.runtime.radius_attempts,{})

    def test_termination_action_only_does_not_renew_lease(self):
        session = self.runtime.radius_sessions[("p1",MAC_A)]
        proposal = self.plan(((44,b"a"),(29,u32(1)))).sessions[0]
        self.assertEqual(proposal.lease_deadline_ms,session.lease_deadline_ms)
        self.assertEqual(proposal.policy.session_timeout,session.policy.session_timeout)
        session.lease_deadline_ms = None
        self.assertIsNone(self.plan(((44,b"a"),(29,u32(1)))).sessions[0].lease_deadline_ms)

    def test_missing_controls_keep_local_deadline_policy(self):
        session = self.runtime.radius_sessions[("p1",MAC_A)]
        session.policy = replace(session.policy,idle_timeout=None,session_timeout=None)
        session.lease_deadline_ms = None
        self.runtime.cfg.radius.inactivity_seconds = 50
        self.runtime.cfg.radius.reauthentication_seconds = 70
        proposal = self.plan(((44,b"a"),*vlan())).sessions[0]
        self.assertEqual(proposal.idle_deadline_ms,90_000)
        self.assertIsNone(proposal.lease_deadline_ms)
        self.assertIsNone(proposal.policy.session_timeout)
        self.assertIsNone(proposal.policy.idle_timeout)

    def test_control_uint32_boundaries(self):
        proposal = self.plan(((44,b"a"),(27,u32(0xffffffff)),(28,u32(0xffffffff)))).sessions[0]
        self.assertEqual(proposal.lease_deadline_ms,100_000+0xffffffff*1000)
        self.assertEqual(proposal.idle_deadline_ms,40_000+0xffffffff*1000)

    def test_duplicate_controls_are_invalid_request(self):
        for kind in (27,28,29):
            self.nak(404,((44,b"a"),(kind,u32(1)),(kind,u32(1))))

    def test_invalid_control_lengths_and_termination_action(self):
        for kind in (27,28,29):
            for value in (b"",b"abc",b"abcde"):
                self.nak(407,((44,b"a"),(kind,value)))
        for value in (2,0xffffffff):
            self.nak(407,((44,b"a"),(29,u32(value))))

    def test_valid_state_is_opaque_and_omission_preserves_old(self):
        first = self.plan(((44,b"a"),(24,b"\x00new-state\xff"),(29,u32(1)))).sessions[0]
        self.assertEqual(first.policy.state,b"\x00new-state\xff")
        self.assertEqual(self.plan(((44,b"a"),(29,u32(0)))).sessions[0].policy.state,b"prior-state")
        self.assertNotIn("new-state",repr(first))
        self.assertNotIn("prior-state",repr(first.policy))

    def test_malformed_state_normalizes_only_its_nak(self):
        for attrs in (((24,b""),),((24,b"a"),(24,b"b")),((24,b"a"),(24,b"a"))):
            values = ((44,b"a"),(33,b"proxy"),*attrs)
            plan = self.nak(404,values)
            self.assertTrue(plan.omit_state_echo)
            response = dynamic_response(request(values),45,SECRET,error_cause=plan.error_cause)
            _, echoed = packet_attributes(response)
            self.assertNotIn(24,[kind for kind,_ in echoed])
            self.assertIn((33,b"proxy"),echoed)

    def test_valid_state_echoes_on_unrelated_nak(self):
        values = ((44,b"a"),(24,b"single"),(11,b"unsupported"))
        plan = self.nak(401,values)
        self.assertFalse(plan.omit_state_echo)
        _, echoed = packet_attributes(dynamic_response(request(values),45,SECRET,error_cause=plan.error_cause))
        self.assertIn((24,b"single"),echoed)

    def test_disconnect_has_only_identity_proposals(self):
        plan = self.plan(((31,MAC_A.encode()),),40)
        self.assertEqual(self.keys(plan),(("p1",MAC_A),("p3",MAC_A)))
        self.assertEqual(tuple(p.session_id for p in plan.sessions),("a","d"))
        self.assertTrue(all(p.policy is None and p.lease_deadline_ms is None for p in plan.sessions))

    def test_unknown_attributes_and_unsupported_semantics(self):
        for code in (40,43):
            for kind in (0,2,3,8,11,18,25,26,30,50,61,79,85,95,101,255):
                with self.subTest(code=code,kind=kind):
                    self.nak(401,((44,b"a"),(kind,b"opaque")),code)

    def test_disconnect_rejects_controls_state_service(self):
        for kind in (6,24,27,28,29,64,65,81):
            self.nak(401,((44,b"a"),(kind,u32(1))),40)
        self.nak(401,((44,b"a"),(24,b"")),40)

    def test_all_coa_service_types_unsupported(self):
        for value in (b"",b"abc",u32(0),u32(2),u32(17),u32(0xffffffff)):
            self.nak(405,((44,b"a"),(6,value)))
        self.nak(405,((44,b"a"),(6,u32(17)),(6,u32(17))))

    def test_precedence_independent_of_attribute_order(self):
        cases = (
            (404,((24,b""),(11,b"unsupported"),(6,u32(17)))),
            (401,((11,b"unsupported"),(6,u32(17)))),
            (405,((6,u32(17)),(27,u32(1)),(27,u32(2)))),
            (404,((27,u32(1)),(27,u32(2)),(64,u32(13)))),
            (402,((64,u32(13)),(28,b"bad"))),
            (407,((28,b"bad"),(32,b"wrong NAS"))),
            (403,((32,b"wrong NAS"),(44,b"missing"))),
        )
        for expected, attrs in cases:
            for permuted in itertools.permutations(attrs):
                self.nak(expected,((5,u32(1)),*permuted))

    def test_plan_order_independent_of_session_dictionary_insertion(self):
        values = ((1,b"same-user"),*vlan())
        before = self.plan(values)
        self.runtime.radius_sessions = dict(reversed(tuple(self.runtime.radius_sessions.items())))
        self.assertEqual(self.plan(values),before)

    def test_old_plan_captures_exact_ids_and_grant_generations(self):
        old = self.plan(((44,b"a"),*vlan()))
        session = self.runtime.radius_sessions[("p1",MAC_A)]
        session.id = "replacement"
        session.grant_generation = "replacement-grant"
        self.assertEqual(old.sessions[0].session_id,"a")
        self.assertEqual(old.sessions[0].grant_generation,"grant-a")
        self.nak(503,((44,b"a"),*vlan()))

    def test_multi_host_owner_selected_once_and_dependent_never_aliases(self):
        owner = self.plan(((31,MAC_C.encode()),))
        self.assertEqual(self.keys(owner),(("p2",MAC_C),))
        self.assertEqual(owner.sessions[0].session_id,"c")
        self.nak(503,((31,MAC_D.encode()),))
        self.nak(503,((44,b"c"),(31,MAC_D.encode())))

    def test_fdb_and_inventory_rows_do_not_create_selector_aliases(self):
        self.runtime.fdb[(1020,MAC_X)] = dict(port_id="p2",mac=MAC_X,vid=20,
                                            last_seen_ms=99_000,expires_at_ms=400_000)
        self.runtime.cfg.endpoints["ep"].sources.append(Source(mac=MAC_X))
        self.nak(503,((31,MAC_X.encode()),))
        self.nak(503,((44,b"c"),(31,MAC_X.encode())))

    def test_owner_selectable_after_fdb_aging_and_unannounced_departure(self):
        self.runtime.fdb.clear()
        self.runtime.cfg.endpoints["ep"].sources = []
        self.assertEqual(self.keys(self.plan(((31,MAC_C.encode()),))),(("p2",MAC_C),))
        self.assertEqual(self.keys(self.plan(((44,b"c"),(31,MAC_C.encode())))),(("p2",MAC_C),))

    def test_same_owner_mac_on_shared_and_independent_ports_selects_both(self):
        previous = self.runtime.radius_sessions.pop(("p2",MAC_C))
        previous.mac = MAC_A
        self.runtime.radius_sessions[("p2",MAC_A)] = previous
        plan = self.plan(((31,MAC_A.encode()),))
        self.assertEqual(self.keys(plan),(("p1",MAC_A),("p2",MAC_A),("p3",MAC_A)))

    def test_canonical_verified_request_class_and_padding(self):
        req = request(((44,b"a"),))
        self.assertIs(type(req),_DynamicRequest)
        padded = verify_dynamic_request(req.packet+b"\x00synthetic-padding",SECRET)
        self.assertEqual(padded,req)
        self.assertEqual(plan_dynamic_request(padded,self.runtime),plan_dynamic_request(req,self.runtime))

    def test_request_type_errors_are_fixed(self):
        for value in (None,b"raw-packet",object()):
            with self.assertRaisesRegex(RadiusError,"^invalid_dynamic_request$"):
                plan_dynamic_request(value,self.runtime)

    def test_no_clock_or_lifecycle_operations(self):
        def forbidden(*args,**kwargs):
            raise AssertionError("planner called an effect/clock/lifecycle owner")
        methods = ("event","queue_accounting","end_session","process_session_deadlines","reach_time",
                   "reserve_renewal","session","up","carrier","uptime","prepare_authentication")
        with patch.multiple(self.runtime,**{name:forbidden for name in methods}):
            plan = plan_dynamic_request(request(((44,b"a"),(27,u32(0)),(29,u32(1)))),self.runtime)
        self.assertIsNone(plan.error_cause)
        self.assertEqual(plan.sessions[0].lease_deadline_ms,100_000)
