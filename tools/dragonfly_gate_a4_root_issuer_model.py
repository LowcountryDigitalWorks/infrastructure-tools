"""Synthetic REDRIX Gate A4 root-issuer trust model; data only, never an issuer.

No import-time activity, filesystem access, sockets, subprocesses, privilege changes,
/proc reads, network, or execution entrypoint. All input is immutable synthetic evidence.
Even a fully coherent model result is DATA_ONLY_NOT_AUTHORIZED.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Mapping

MARKER = "REDRIX_A4_ROOT_ISSUER_MODEL_V1"
FIXED_PACKAGE_ROOT = "/usr/libexec/ldw-redrix-a4"
EXPECTED_ANCESTORS = (
    "/",
    "/usr",
    "/usr/libexec",
    FIXED_PACKAGE_ROOT,
)
EXPECTED_PAYLOADS = (
    f"{FIXED_PACKAGE_ROOT}/launcher",
    f"{FIXED_PACKAGE_ROOT}/inspector",
    f"{FIXED_PACKAGE_ROOT}/uid1000-verifier",
)
ROOT_UID = 0
ROOT_GID = 0
DIRECTORY_MODE = 0o755
EXECUTABLE_MODE = 0o555
MANIFEST_MODE = 0o444
MAX_NONCE_TTL_MS = 5000


@dataclass(frozen=True)
class PinnedBytes:
    path: str
    git_blob_sha1: str
    sha256: str


# These are deliberately synthetic source constants used only by unit fixtures. They
# are not hashes of deployed binaries and are not accepted physical package pins.
SYNTHETIC_PIN_FIXTURE: Mapping[str, PinnedBytes] = MappingProxyType({
    EXPECTED_PAYLOADS[0]: PinnedBytes(EXPECTED_PAYLOADS[0], "1" * 40, "a" * 64),
    EXPECTED_PAYLOADS[1]: PinnedBytes(EXPECTED_PAYLOADS[1], "2" * 40, "b" * 64),
    EXPECTED_PAYLOADS[2]: PinnedBytes(EXPECTED_PAYLOADS[2], "3" * 40, "c" * 64),
})
SYNTHETIC_MANIFEST_PIN = PinnedBytes(
    f"{FIXED_PACKAGE_ROOT}/manifest.json", "4" * 40, "d" * 64
)


@dataclass(frozen=True)
class FileMetadata:
    device: int
    inode: int
    owner_uid: int
    group_gid: int
    mode: int
    link_count: int
    kind: str = "regular"
    symlink: bool = False
    writable_by_untrusted: bool = False


@dataclass(frozen=True)
class ObjectObservation:
    path: str
    descriptor_before: FileMetadata
    descriptor_after: FileMetadata
    path_after: FileMetadata
    sha256: str = ""
    git_blob_sha1: str = ""


@dataclass(frozen=True)
class ManifestClaim:
    path: str
    git_blob_sha1: str
    sha256: str


@dataclass(frozen=True)
class PackageEvidence:
    ancestors: tuple[ObjectObservation, ...]
    manifest: ObjectObservation
    manifest_claims: tuple[ManifestClaim, ...]
    payloads: tuple[ObjectObservation, ...]


@dataclass(frozen=True)
class ChannelEvidence:
    launcher_created: bool
    created_after_privilege_boundary: bool
    receive_fd: int
    send_fd: int
    inherited_endpoint: bool
    preopened_endpoint: bool
    duplicate_endpoint: bool
    duplicate_peer_credentials: bool
    peer_credentials_measured: bool
    receiver_measured_executable: bool
    peer_uid: int
    peer_gid: int
    peer_pid: int
    pidfd_opened: bool
    peer_starttime_before: int
    peer_starttime_after: int
    peer_namespaces_before: tuple[str, str, str]
    peer_namespaces_after: tuple[str, str, str]
    peer_executable: ObjectObservation
    nonce_hex: str
    issued_monotonic_ms: int
    expires_monotonic_ms: int
    receiver_monotonic_ms: int
    nonce_previously_consumed: bool
    duplicate_message: bool
    sequence_before: int
    sequence_after: int
    invocation_path: str
    invocation_arguments: tuple[str, ...]
    invocation_environment: tuple[tuple[str, str], ...]
    claims: tuple[tuple[str, object], ...]


def _hold(reason: str) -> dict[str, object]:
    return {
        "schema": 1,
        "marker": MARKER,
        "classification": "HOLD",
        "reasonCode": reason,
        "a4Pass": False,
        "privilegedChannelAuthenticated": False,
        "runtimeAuthority": False,
        "jitAdmissionAuthorized": False,
    }


def _data_only() -> dict[str, object]:
    return {
        "schema": 1,
        "marker": MARKER,
        "classification": "DATA_ONLY_NOT_AUTHORIZED",
        "reasonCode": "SYNTHETIC_TRUST_MODEL_ONLY",
        "a4Pass": False,
        "privilegedChannelAuthenticated": False,
        "runtimeAuthority": False,
        "jitAdmissionAuthorized": False,
    }


def _same_identity(left: FileMetadata, right: FileMetadata) -> bool:
    return left == right


def _check_metadata(
    observed: FileMetadata,
    *,
    owner: int,
    group: int,
    mode: int,
    kind: str,
    single_link: bool,
) -> str | None:
    numeric = (
        observed.device,
        observed.inode,
        observed.owner_uid,
        observed.group_gid,
        observed.mode,
        observed.link_count,
    )
    if any(type(value) is not int for value in numeric):
        return "A4_ISSUER_IDENTITY_INVALID"
    if observed.device <= 0 or observed.inode <= 0 or observed.link_count <= 0:
        return "A4_ISSUER_IDENTITY_INVALID"
    if observed.symlink:
        return "A4_ISSUER_SYMLINK_REFUSED"
    if observed.kind != kind:
        return "A4_ISSUER_OBJECT_TYPE_INVALID"
    if observed.owner_uid != owner or observed.group_gid != group:
        return "A4_ISSUER_OWNER_OR_GROUP_INVALID"
    if observed.mode != mode or observed.writable_by_untrusted:
        return "A4_ISSUER_MODE_OR_WRITABLE_PARENT_INVALID"
    if single_link and observed.link_count != 1:
        return "A4_ISSUER_HARDLINK_REFUSED"
    return None


def _validate_stable_object(
    evidence: ObjectObservation,
    *,
    expected_path: str,
    owner: int,
    group: int,
    mode: int,
    kind: str,
    single_link: bool,
    pin: PinnedBytes | None = None,
) -> str | None:
    if evidence.path != expected_path:
        return "A4_ISSUER_PATH_MISMATCH"
    for observed in (
        evidence.descriptor_before,
        evidence.descriptor_after,
        evidence.path_after,
    ):
        reason = _check_metadata(
            observed,
            owner=owner,
            group=group,
            mode=mode,
            kind=kind,
            single_link=single_link,
        )
        if reason:
            return reason
    if not (
        _same_identity(evidence.descriptor_before, evidence.descriptor_after)
        and _same_identity(evidence.descriptor_after, evidence.path_after)
    ):
        return "A4_ISSUER_TOCTOU_IDENTITY_DRIFT"
    if pin is not None and (
        evidence.sha256 != pin.sha256
        or evidence.git_blob_sha1 != pin.git_blob_sha1
    ):
        return "A4_ISSUER_IMMUTABLE_PIN_MISMATCH"
    return None


def _validate_package(evidence: PackageEvidence) -> str | None:
    if not isinstance(evidence, PackageEvidence):
        return "A4_ISSUER_EVIDENCE_TYPE_INVALID"
    if tuple(item.path for item in evidence.ancestors) != EXPECTED_ANCESTORS:
        return "A4_ISSUER_ANCESTRY_INVALID"
    for item in evidence.ancestors:
        reason = _validate_stable_object(
            item,
            expected_path=item.path,
            owner=ROOT_UID,
            group=ROOT_GID,
            mode=DIRECTORY_MODE,
            kind="directory",
            single_link=False,
        )
        if reason:
            return reason
    reason = _validate_stable_object(
        evidence.manifest,
        expected_path=SYNTHETIC_MANIFEST_PIN.path,
        owner=ROOT_UID,
        group=ROOT_GID,
        mode=MANIFEST_MODE,
        kind="regular",
        single_link=True,
        pin=SYNTHETIC_MANIFEST_PIN,
    )
    if reason:
        return reason
    if tuple(item.path for item in evidence.payloads) != EXPECTED_PAYLOADS:
        return "A4_ISSUER_PAYLOAD_SET_INVALID"
    claims = {claim.path: claim for claim in evidence.manifest_claims}
    if len(claims) != len(evidence.manifest_claims) or set(claims) != set(EXPECTED_PAYLOADS):
        return "A4_ISSUER_MANIFEST_CLAIMS_INVALID"
    for item in evidence.payloads:
        pin = SYNTHETIC_PIN_FIXTURE[item.path]
        reason = _validate_stable_object(
            item,
            expected_path=pin.path,
            owner=ROOT_UID,
            group=ROOT_GID,
            mode=EXECUTABLE_MODE,
            kind="regular",
            single_link=True,
            pin=pin,
        )
        if reason:
            return reason
        claim = claims[item.path]
        if (claim.path, claim.git_blob_sha1, claim.sha256) != (
            pin.path, pin.git_blob_sha1, pin.sha256
        ):
            return "A4_ISSUER_MANIFEST_CANNOT_OVERRIDE_SOURCE_PINS"
    all_objects = evidence.ancestors + (evidence.manifest,) + evidence.payloads
    identities = [item.descriptor_before for item in all_objects]
    if len({item.device for item in identities}) != 1:
        return "A4_ISSUER_DEVICE_BOUNDARY_CHANGED"
    if len({item.inode for item in identities}) != len(identities):
        return "A4_ISSUER_INODE_COLLISION"
    return None


def _validate_channel(evidence: ChannelEvidence, package: PackageEvidence) -> str | None:
    if not isinstance(evidence, ChannelEvidence):
        return "A4_ISSUER_CHANNEL_EVIDENCE_TYPE_INVALID"
    if not evidence.launcher_created or not evidence.created_after_privilege_boundary:
        return "A4_ISSUER_CHANNEL_CREATION_ORDER_INVALID"
    if evidence.inherited_endpoint or evidence.preopened_endpoint or evidence.duplicate_endpoint:
        return "A4_ISSUER_ENDPOINT_REUSE_REFUSED"
    if evidence.duplicate_peer_credentials:
        return "A4_ISSUER_DUPLICATE_PEER_REFUSED"
    if evidence.receive_fd <= 0 or evidence.send_fd <= 0 or evidence.receive_fd == evidence.send_fd:
        return "A4_ISSUER_ENDPOINT_IDENTITY_INVALID"
    if not evidence.peer_credentials_measured:
        return "A4_ISSUER_PEER_CREDENTIALS_UNVERIFIED"
    if not evidence.receiver_measured_executable:
        return "A4_ISSUER_PEER_EXECUTABLE_UNTRUSTED"
    if evidence.peer_uid != ROOT_UID or evidence.peer_gid != ROOT_GID:
        return "A4_ISSUER_PEER_IDENTITY_INVALID"
    if evidence.peer_pid <= 1 or not evidence.pidfd_opened:
        return "A4_ISSUER_PIDFD_UNVERIFIED"
    if evidence.peer_starttime_before <= 0 or evidence.peer_starttime_before != evidence.peer_starttime_after:
        return "A4_ISSUER_PEER_STARTTIME_DRIFT"
    if (
        len(evidence.peer_namespaces_before) != 3
        or evidence.peer_namespaces_before != evidence.peer_namespaces_after
        or any(not isinstance(value, str) or not value for value in evidence.peer_namespaces_before)
    ):
        return "A4_ISSUER_PEER_NAMESPACE_DRIFT"
    if evidence.peer_executable.path not in EXPECTED_PAYLOADS[:2]:
        return "A4_ISSUER_PEER_EXECUTABLE_UNTRUSTED"
    package_file = next(item for item in package.payloads if item.path == evidence.peer_executable.path)
    if evidence.peer_executable != package_file:
        return "A4_ISSUER_PEER_EXECUTABLE_UNTRUSTED"
    if not re.fullmatch(r"[0-9a-f]{64}", evidence.nonce_hex):
        return "A4_ISSUER_NONCE_INVALID"
    if (
        evidence.expires_monotonic_ms <= evidence.issued_monotonic_ms
        or evidence.expires_monotonic_ms - evidence.issued_monotonic_ms > MAX_NONCE_TTL_MS
        or not evidence.issued_monotonic_ms <= evidence.receiver_monotonic_ms < evidence.expires_monotonic_ms
    ):
        return "A4_ISSUER_NONCE_TTL_INVALID"
    if evidence.nonce_previously_consumed or evidence.duplicate_message:
        return "A4_ISSUER_NONCE_REPLAY_REFUSED"
    if evidence.sequence_before <= 0 or evidence.sequence_after != evidence.sequence_before + 1:
        return "A4_ISSUER_CHANNEL_SEQUENCE_INVALID"
    if evidence.invocation_path != f"{FIXED_PACKAGE_ROOT}/launcher":
        return "A4_ISSUER_CALLER_SELECTED_PROGRAM_REFUSED"
    if evidence.invocation_arguments or evidence.invocation_environment:
        return "A4_ISSUER_CALLER_ARGUMENT_OR_ENV_REFUSED"
    claim_fields = dict(evidence.claims)
    if len(claim_fields) != len(evidence.claims):
        return "A4_ISSUER_DUPLICATE_AUTH_CLAIM_REFUSED"
    if any(claim_fields.get(key) is not None and claim_fields.get(key) is not False for key in (
        "root", "signature", "privilegedChannelAuthenticated", "a4Pass", "runtimeAuthority"
    )):
        return "A4_ISSUER_SELF_ASSERTED_AUTH_REFUSED"
    return None


def evaluate_synthetic_evidence(
    package: PackageEvidence, channel: ChannelEvidence
) -> dict[str, object]:
    """Validate injected frozen evidence; never authenticates or grants authority."""
    try:
        package_error = _validate_package(package)
        if package_error:
            return _hold(package_error)
        channel_error = _validate_channel(channel, package)
        if channel_error:
            return _hold(channel_error)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return _hold("A4_ISSUER_EVIDENCE_MALFORMED")
    return _data_only()
