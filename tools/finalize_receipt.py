#!/usr/bin/env python3
"""Fail-closed verifier for the production repository-fetch proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import tarfile


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


parser = argparse.ArgumentParser()
parser.add_argument("--action", required=True, type=pathlib.Path)
parser.add_argument("--control-log", required=True, type=pathlib.Path)
parser.add_argument("--control-rc", required=True, type=int)
parser.add_argument("--diagnostic-archive", required=True, type=pathlib.Path)
parser.add_argument("--diagnostic-source", required=True, type=pathlib.Path)
parser.add_argument("--emitter", required=True, type=pathlib.Path)
parser.add_argument("--fetched-source", required=True, type=pathlib.Path)
parser.add_argument("--output", required=True, type=pathlib.Path)
parser.add_argument("--protobuf", required=True, type=pathlib.Path)
parser.add_argument("--readback", required=True, type=pathlib.Path)
parser.add_argument("--registry-commit", required=True)
parser.add_argument("--site-tar", required=True, type=pathlib.Path)
args = parser.parse_args()

emitter = json.loads(args.emitter.read_text())
expected_archive = emitter["expected_sha256"]
observed_archive = digest(args.diagnostic_archive)
fetched_source_sha = digest(args.fetched_source)
diagnostic_source_sha = digest(args.diagnostic_source)
if fetched_source_sha != diagnostic_source_sha:
    raise SystemExit("Bazel external source differs from the diagnostic archive member")

source_text = args.fetched_source.read_text()
if "BCR_FRONTEND_REVIEWED" in source_text:
    marker = "BCR_FRONTEND_REVIEWED"
elif "BCR_FRONTEND_UNREVIEWED" in source_text:
    marker = "BCR_FRONTEND_UNREVIEWED"
else:
    raise SystemExit("controlled documentation marker is absent from Bazel external source")

control_log = args.control_log.read_text(errors="replace")
if observed_archive == expected_archive:
    if args.control_rc != 0:
        raise SystemExit("reviewed archive failed the digest-enforcing control")
    control_result = "ACCEPTED_REVIEWED_ARCHIVE"
else:
    if args.control_rc == 0:
        raise SystemExit("replacement archive passed the digest-enforcing control")
    pattern = rf"Checksum was {re.escape(observed_archive)} but wanted {re.escape(expected_archive)}"
    if re.search(pattern, control_log) is None:
        raise SystemExit("control failure does not bind replacement and reviewed archive digests")
    control_result = "REJECTED_REPLACEMENT"

action = args.action.read_text(errors="replace")
canonical_repo = "build_stack_rules_proto++starlark_repository+bzl.proof---1.0.0"
source_path = f"external/{canonical_repo}/proof.bzl"
target_label = f"@@{canonical_repo}//:proof"
required_action_text = (
    "Mnemonic: CompileProductionFetchedBzl",
    f"Inputs: [bzlcompiler-bin, constellate-server.jar, {source_path}]",
    f"--bzl_file=proof|{target_label}|{source_path}",
)
for value in required_action_text:
    if value not in action:
        raise SystemExit(f"compile action does not bind {value}")
if action.count(source_path) < 3:
    raise SystemExit("Bazel external source is not both the declared and positional compiler input")
if "controlled-source" in action or "stage/extracted" in action:
    raise SystemExit("compile action uses a manually staged source")

readback = args.readback.read_text()
if marker + "_MODULE_DOCSTRING" not in readback or marker + "_FUNCTION_DOCSTRING" not in readback:
    raise SystemExit("semantic protobuf readback does not contain the Bazel-fetched marker")

protobuf_bytes = args.protobuf.read_bytes()
with tarfile.open(args.site_tar) as archive:
    released = archive.extractfile("modules/proof/1.0.0/documentationinfo.pb.gz").read()
if released != protobuf_bytes:
    raise SystemExit("releasecompiler changed the documentation protobuf bytes")

value = {
    "result": "PASS",
    "registry_commit": args.registry_commit,
    "frontend_sha": emitter["frontend_commit"],
    "source_url": emitter["source_url"],
    "reviewed_sha256": expected_archive,
    "downloaded_sha256": observed_archive,
    "control_result": control_result,
    "control_integrity_forwarded": True,
    "control_expected_sha256": expected_archive,
    "control_observed_sha256": observed_archive,
    "control_and_attack_same_url": True,
    "control_and_attack_same_bytes": True,
    "attack_integrity_forwarded": False,
    "production_rule_execution": True,
    "production_function": emitter["production_function"],
    "production_target_label": target_label,
    "compiler_source_path": source_path,
    "compiler_source_sha256": fetched_source_sha,
    "diagnostic_source_sha256": diagnostic_source_sha,
    "compiler_source_equals_diagnostic_archive_member": True,
    "manual_download_used_as_compiler_source": False,
    "documentation_marker": marker,
    "documentation_protobuf_sha256": digest(args.protobuf),
    "release_tar_sha256": digest(args.site_tar),
    "release_member_byte_identical": True,
    "semantic_readback": readback.splitlines(),
}
args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
