"""Deterministic synthetic-only trust model tests. No OS, IPC, or privileged calls."""
from __future__ import annotations

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "tools" / "dragonfly_gate_a4_root_issuer_model.py"
spec = importlib.util.spec_from_file_location("a4_root_issuer_model_fixture", TARGET)
assert spec is not None and spec.loader is not None
model = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = model
spec.loader.exec_module(model)


def metadata(*, inode: int, kind="directory", mode=None, uid=0, gid=0,
             links=1, symlink=False, writable=False):
    if mode is None:
        mode = model.DIRECTORY_MODE if kind == "directory" else model.EXECUTABLE_MODE
    return model.FileMetadata(
        device=77, inode=inode, owner_uid=uid, group_gid=gid, mode=mode,
        link_count=links, kind=kind, symlink=symlink,
        writable_by_untrusted=writable,
    )


def observation(path, *, inode, kind="directory", mode=None, uid=0, gid=0,
                links=1, symlink=False, writable=False, sha="", blob="",
                after=None, path_after=None):
    before = metadata(inode=inode, kind=kind, mode=mode, uid=uid, gid=gid,
                      links=links, symlink=symlink, writable=writable)
    return model.ObjectObservation(
        path=path,
        descriptor_before=before,
        descriptor_after=before if after is None else after,
        path_after=before if path_after is None else path_after,
        sha256=sha,
        git_blob_sha1=blob,
    )


def valid_fixture():
    ancestors = tuple(
        observation(path, inode=index + 10)
        for index, path in enumerate(model.EXPECTED_ANCESTORS)
    )
    manifest = observation(
        model.SYNTHETIC_MANIFEST_PIN.path,
        inode=30,
        kind="regular",
        mode=model.MANIFEST_MODE,
        sha=model.SYNTHETIC_MANIFEST_PIN.sha256,
        blob=model.SYNTHETIC_MANIFEST_PIN.git_blob_sha1,
    )
    payloads = tuple(
        observation(
            pin.path,
            inode=40 + index,
            kind="regular",
            mode=model.EXECUTABLE_MODE,
            sha=pin.sha256,
            blob=pin.git_blob_sha1,
        )
        for index, pin in enumerate(model.SYNTHETIC_PIN_FIXTURE.values())
    )
    claims = tuple(
        model.ManifestClaim(path, pin.git_blob_sha1, pin.sha256)
        for path, pin in model.SYNTHETIC_PIN_FIXTURE.items()
    )
    package = model.PackageEvidence(ancestors, manifest, claims, payloads)
    channel = model.ChannelEvidence(
        launcher_created=True,
        created_after_privilege_boundary=True,
        receive_fd=51,
        send_fd=52,
        inherited_endpoint=False,
        preopened_endpoint=False,
        duplicate_endpoint=False,
        duplicate_peer_credentials=False,
        peer_credentials_measured=True,
        receiver_measured_executable=True,
        peer_uid=0,
        peer_gid=0,
        peer_pid=700,
        pidfd_opened=True,
        peer_starttime_before=901,
        peer_starttime_after=901,
        peer_namespaces_before=("user:[1]", "pid:[2]", "mnt:[3]"),
        peer_namespaces_after=("user:[1]", "pid:[2]", "mnt:[3]"),
        peer_executable=payloads[0],
        nonce_hex="a" * 64,
        issued_monotonic_ms=1000,
        expires_monotonic_ms=4000,
        receiver_monotonic_ms=1500,
        nonce_previously_consumed=False,
        duplicate_message=False,
        sequence_before=4,
        sequence_after=5,
        invocation_path=f"{model.FIXED_PACKAGE_ROOT}/launcher",
        invocation_arguments=(),
        invocation_environment=(),
        claims=(),
    )
    return package, channel


class RootIssuerModelTests(unittest.TestCase):
    def assert_data_only(self, result):
        self.assertEqual(result["classification"], "DATA_ONLY_NOT_AUTHORIZED")
        self.assertFalse(result["a4Pass"])
        self.assertFalse(result["privilegedChannelAuthenticated"])
        self.assertFalse(result["runtimeAuthority"])
        self.assertFalse(result["jitAdmissionAuthorized"])

    def assert_hold(self, package, channel, reason):
        result = model.evaluate_synthetic_evidence(package, channel)
        self.assertEqual(result["classification"], "HOLD")
        self.assertEqual(result["reasonCode"], reason)
        self.assertFalse(result["a4Pass"])
        self.assertFalse(result["privilegedChannelAuthenticated"])
        self.assertFalse(result["runtimeAuthority"])
        self.assertFalse(result["jitAdmissionAuthorized"])

    def test_all_matching_synthetic_evidence_is_data_only(self):
        self.assert_data_only(model.evaluate_synthetic_evidence(*valid_fixture()))

    def test_root_uid_alone_does_not_authenticate_unknown_executable(self):
        package, channel = valid_fixture()
        bad = replace(channel.peer_executable, path="/usr/bin/python3")
        self.assert_hold(package, replace(channel, peer_executable=bad),
                         "A4_ISSUER_PEER_EXECUTABLE_UNTRUSTED")

    def test_fixed_package_path_and_each_ancestor_are_required(self):
        package, channel = valid_fixture()
        ancestors = list(package.ancestors)
        ancestors[2] = replace(ancestors[2], path="/usr/local/libexec")
        self.assert_hold(replace(package, ancestors=tuple(ancestors)), channel,
                         "A4_ISSUER_ANCESTRY_INVALID")

    def test_symlink_ancestor_refused(self):
        package, channel = valid_fixture()
        ancestors = list(package.ancestors)
        bad_meta = replace(ancestors[2].descriptor_before, symlink=True, kind="symlink")
        ancestors[2] = replace(ancestors[2], descriptor_before=bad_meta,
                               descriptor_after=bad_meta, path_after=bad_meta)
        self.assert_hold(replace(package, ancestors=tuple(ancestors)), channel,
                         "A4_ISSUER_SYMLINK_REFUSED")

    def test_writable_parent_refused(self):
        package, channel = valid_fixture()
        ancestors = list(package.ancestors)
        bad_meta = replace(ancestors[1].descriptor_before, writable_by_untrusted=True)
        ancestors[1] = replace(ancestors[1], descriptor_before=bad_meta,
                               descriptor_after=bad_meta, path_after=bad_meta)
        self.assert_hold(replace(package, ancestors=tuple(ancestors)), channel,
                         "A4_ISSUER_MODE_OR_WRITABLE_PARENT_INVALID")

    def test_owner_and_group_are_independently_pinned(self):
        package, channel = valid_fixture()
        for field, value in (("owner_uid", 1000), ("group_gid", 1000)):
            ancestors = list(package.ancestors)
            meta = replace(ancestors[-1].descriptor_before, **{field: value})
            ancestors[-1] = replace(ancestors[-1], descriptor_before=meta,
                                    descriptor_after=meta, path_after=meta)
            with self.subTest(field=field):
                self.assert_hold(replace(package, ancestors=tuple(ancestors)), channel,
                                 "A4_ISSUER_OWNER_OR_GROUP_INVALID")

    def test_wrong_mode_and_link_count_refused(self):
        package, channel = valid_fixture()
        item = package.payloads[0]
        bad_mode = replace(item.descriptor_before, mode=0o755)
        bad = replace(item, descriptor_before=bad_mode, descriptor_after=bad_mode,
                      path_after=bad_mode)
        self.assert_hold(replace(package, payloads=(bad,) + package.payloads[1:]), channel,
                         "A4_ISSUER_MODE_OR_WRITABLE_PARENT_INVALID")
        hardlink_meta = replace(item.descriptor_before, link_count=2)
        hardlink = replace(item, descriptor_before=hardlink_meta,
                           descriptor_after=hardlink_meta, path_after=hardlink_meta)
        self.assert_hold(replace(package, payloads=(hardlink,) + package.payloads[1:]), channel,
                         "A4_ISSUER_HARDLINK_REFUSED")

    def test_open_and_path_inode_swap_refused(self):
        package, channel = valid_fixture()
        item = package.payloads[1]
        swapped = replace(item.descriptor_before, inode=item.descriptor_before.inode + 1)
        drift = replace(item, path_after=swapped)
        self.assert_hold(replace(package, payloads=(package.payloads[0], drift,
                                                     package.payloads[2])), channel,
                         "A4_ISSUER_TOCTOU_IDENTITY_DRIFT")

    def test_cross_device_package_mount_is_refused(self):
        package, channel = valid_fixture()
        item = package.payloads[-1]
        changed = replace(item.descriptor_before, device=88)
        payload = replace(item, descriptor_before=changed, descriptor_after=changed,
                          path_after=changed)
        self.assert_hold(replace(package, payloads=package.payloads[:-1] + (payload,)), channel,
                         "A4_ISSUER_DEVICE_BOUNDARY_CHANGED")

    def test_independent_git_blob_and_sha256_pins_both_must_match(self):
        package, channel = valid_fixture()
        item = package.payloads[0]
        for changed in (replace(item, sha256="f" * 64),
                        replace(item, git_blob_sha1="f" * 40)):
            payloads = (changed,) + package.payloads[1:]
            self.assert_hold(replace(package, payloads=payloads), channel,
                             "A4_ISSUER_IMMUTABLE_PIN_MISMATCH")

    def test_mutable_manifest_cannot_replace_source_pins(self):
        package, channel = valid_fixture()
        claim = package.manifest_claims[0]
        changed = replace(claim, sha256="e" * 64)
        claims = (changed,) + package.manifest_claims[1:]
        self.assert_hold(replace(package, manifest_claims=claims), channel,
                         "A4_ISSUER_MANIFEST_CANNOT_OVERRIDE_SOURCE_PINS")

    def test_manifest_duplicate_path_refused(self):
        package, channel = valid_fixture()
        claims = package.manifest_claims + (package.manifest_claims[0],)
        self.assert_hold(replace(package, manifest_claims=claims), channel,
                         "A4_ISSUER_MANIFEST_CLAIMS_INVALID")

    def test_peer_starttime_and_pidfd_drift_refused(self):
        package, channel = valid_fixture()
        self.assert_hold(package, replace(channel, peer_starttime_after=902),
                         "A4_ISSUER_PEER_STARTTIME_DRIFT")
        self.assert_hold(package, replace(channel, pidfd_opened=False),
                         "A4_ISSUER_PIDFD_UNVERIFIED")

    def test_unmeasured_executable_provenance_refused(self):
        package, channel = valid_fixture()
        self.assert_hold(package, replace(channel, receiver_measured_executable=False),
                         "A4_ISSUER_PEER_EXECUTABLE_UNTRUSTED")

    def test_peer_namespace_mismatch_or_partial_readback_refused(self):
        package, channel = valid_fixture()
        self.assert_hold(package, replace(channel,
                         peer_namespaces_after=("user:[1]", "pid:[2]", "mnt:[4]")),
                         "A4_ISSUER_PEER_NAMESPACE_DRIFT")
        self.assert_hold(package, replace(channel,
                         peer_namespaces_before=("user:[1]", "", "mnt:[3]")),
                         "A4_ISSUER_PEER_NAMESPACE_DRIFT")

    def test_preopened_inherited_and_duplicate_endpoints_refused(self):
        package, channel = valid_fixture()
        for field in ("preopened_endpoint", "inherited_endpoint", "duplicate_endpoint"):
            with self.subTest(field=field):
                self.assert_hold(package, replace(channel, **{field: True}),
                                 "A4_ISSUER_ENDPOINT_REUSE_REFUSED")
        self.assert_hold(package, replace(channel, send_fd=channel.receive_fd),
                         "A4_ISSUER_ENDPOINT_IDENTITY_INVALID")
        self.assert_hold(package, replace(channel, duplicate_peer_credentials=True),
                         "A4_ISSUER_DUPLICATE_PEER_REFUSED")

    def test_nonce_ttl_replay_duplicate_and_sequence_refused(self):
        package, channel = valid_fixture()
        self.assert_hold(package, replace(channel, nonce_previously_consumed=True),
                         "A4_ISSUER_NONCE_REPLAY_REFUSED")
        self.assert_hold(package, replace(channel, duplicate_message=True),
                         "A4_ISSUER_NONCE_REPLAY_REFUSED")
        self.assert_hold(package, replace(channel, receiver_monotonic_ms=4000),
                         "A4_ISSUER_NONCE_TTL_INVALID")
        self.assert_hold(package, replace(channel, expires_monotonic_ms=9000),
                         "A4_ISSUER_NONCE_TTL_INVALID")
        self.assert_hold(package, replace(channel, sequence_after=4),
                         "A4_ISSUER_CHANNEL_SEQUENCE_INVALID")

    def test_no_caller_program_arguments_or_environment(self):
        package, channel = valid_fixture()
        self.assert_hold(package, replace(channel, invocation_path="/bin/sh"),
                         "A4_ISSUER_CALLER_SELECTED_PROGRAM_REFUSED")
        self.assert_hold(package, replace(channel, invocation_arguments=("-c", "id")),
                         "A4_ISSUER_CALLER_ARGUMENT_OR_ENV_REFUSED")
        self.assert_hold(package, replace(channel, invocation_environment=(("PATH", "/tmp"),)),
                         "A4_ISSUER_CALLER_ARGUMENT_OR_ENV_REFUSED")

    def test_self_asserted_root_signature_or_auth_claim_refused(self):
        package, channel = valid_fixture()
        for claim in (("root", True), ("signature", True),
                      ("privilegedChannelAuthenticated", True)):
            with self.subTest(claim=claim):
                self.assert_hold(package, replace(channel, claims=(claim,)),
                                 "A4_ISSUER_SELF_ASSERTED_AUTH_REFUSED")

    def test_source_module_has_no_privileged_or_transport_entrypoints(self):
        source = TARGET.read_text(encoding="utf-8")
        for forbidden in (
            "if __name__ ==", "subprocess.", "os.exec", "os.system(",
            "socket.socket(", "setcap ", "sudo -n", "os.setuid(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
