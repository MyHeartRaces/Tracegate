from __future__ import annotations

import argparse
from pathlib import Path

from tracegate.services.runtime_preflight import (
    LinkCryptoEnv,
    LinkCryptoState,
    ObfuscationEnvContract,
    FrontingEnvContract,
    FrontingRuntimeState,
    MTProtoEnvContract,
    MTProtoGatewayState,
    MTProtoPublicProfile,
    ObfuscationRuntimeEnv,
    ObfuscationRuntimeState,
    PrivateProfileEnv,
    PrivateProfileState,
    RuntimePreflightFinding,
    RuntimePreflightError,
    SystemdUnitContract,
    load_private_profile_env,
    load_private_profile_state,
    load_obfuscation_env_contract,
    load_fronting_env_contract,
    load_fronting_runtime_state,
    load_link_crypto_env,
    load_link_crypto_state,
    load_mtproto_env_contract,
    load_mtproto_gateway_state,
    load_mtproto_public_profile,
    load_obfuscation_runtime_env,
    load_obfuscation_runtime_state,
    load_runtime_contract,
    load_systemd_unit_contract,
    load_zapret_profile,
    validate_private_helper_unit_contract,
    validate_obfuscation_env_contract,
    validate_obfuscation_runtime_env,
    validate_fronting_env_contract,
    validate_fronting_runtime_state,
    validate_link_crypto_env,
    validate_link_crypto_state,
    validate_mtproto_env_contract,
    validate_mtproto_gateway_state,
    validate_obfuscation_runtime_state,
    validate_private_profile_env,
    validate_private_profile_state,
    validate_runtime_contract_pair,
    validate_runtime_contract_single,
    validate_zapret_profile,
    validate_zapret_profile_collection,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracegate-validate-runtime-contracts",
        description="Validate Entry/Transit runtime-contract.json files before promoting a runtime to production.",
    )
    parser.add_argument(
        "--entry",
        default="/var/lib/tracegate/agent-entry/runtime/runtime-contract.json",
        help="Path to Entry runtime-contract.json",
    )
    parser.add_argument(
        "--transit",
        default="/var/lib/tracegate/agent-transit/runtime/runtime-contract.json",
        help="Path to Transit runtime-contract.json",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on warnings as well as errors",
    )
    parser.add_argument(
        "--mode",
        choices=("pair", "entry", "transit"),
        default="pair",
        help="Validation topology: pair for Entry+Transit, or a single-role preflight for entry/transit-only testbeds",
    )
    parser.add_argument(
        "--zapret-root",
        default="",
        help="Directory with private zapret profile metadata (entry-lite.env, transit-lite.env, entry-transit-stealth.env, optional mtproto-extra.env)",
    )
    parser.add_argument("--zapret-entry", default="", help="Path to Entry zapret profile metadata")
    parser.add_argument("--zapret-transit", default="", help="Path to Transit zapret profile metadata")
    parser.add_argument("--zapret-interconnect", default="", help="Path to Entry-Transit interconnect zapret profile metadata")
    parser.add_argument("--zapret-mtproto", default="", help="Path to MTProto zapret profile metadata")
    parser.add_argument("--obfuscation-env", default="", help="Path to host-local private obfuscation.env")
    parser.add_argument("--obfuscation-unit", default="", help="Path to tracegate-obfuscation@.service")
    parser.add_argument("--entry-runtime-state", default="", help="Path to Entry obfuscation runtime-state.json")
    parser.add_argument("--transit-runtime-state", default="", help="Path to Transit obfuscation runtime-state.json")
    parser.add_argument("--entry-runtime-env", default="", help="Path to Entry obfuscation runtime-state.env")
    parser.add_argument("--transit-runtime-env", default="", help="Path to Transit obfuscation runtime-state.env")
    parser.add_argument("--entry-profile-state", default="", help="Path to Entry private profile desired-state.json")
    parser.add_argument("--transit-profile-state", default="", help="Path to Transit private profile desired-state.json")
    parser.add_argument("--entry-profile-env", default="", help="Path to Entry private profile desired-state.env")
    parser.add_argument("--transit-profile-env", default="", help="Path to Transit private profile desired-state.env")
    parser.add_argument("--profiles-unit", default="", help="Path to tracegate-profiles@.service")
    parser.add_argument("--entry-link-crypto-state", default="", help="Path to Entry link-crypto desired-state.json")
    parser.add_argument("--transit-link-crypto-state", default="", help="Path to Transit link-crypto desired-state.json")
    parser.add_argument("--entry-link-crypto-env", default="", help="Path to Entry link-crypto desired-state.env")
    parser.add_argument("--transit-link-crypto-env", default="", help="Path to Transit link-crypto desired-state.env")
    parser.add_argument("--link-crypto-unit", default="", help="Path to tracegate-link-crypto@.service")
    parser.add_argument("--fronting-state", default="", help="Path to Transit fronting last-action.json")
    parser.add_argument("--fronting-env", default="", help="Path to Transit fronting.env")
    parser.add_argument("--fronting-unit", default="", help="Path to tracegate-fronting@.service")
    parser.add_argument("--mtproto-state", default="", help="Path to Transit MTProto last-action.json")
    parser.add_argument("--mtproto-env", default="", help="Path to Transit mtproto.env")
    parser.add_argument("--mtproto-unit", default="", help="Path to tracegate-mtproto@.service")
    parser.add_argument("--mtproto-public-profile", default="", help="Path to Transit MTProto public-profile.json")
    return parser


def _resolve_zapret_paths(args: argparse.Namespace) -> tuple[Path | None, Path | None, Path | None, Path | None]:
    root_raw = str(args.zapret_root or "").strip()
    root = Path(root_raw) if root_raw else None

    entry = Path(args.zapret_entry) if str(args.zapret_entry or "").strip() else None
    transit = Path(args.zapret_transit) if str(args.zapret_transit or "").strip() else None
    interconnect = Path(args.zapret_interconnect) if str(args.zapret_interconnect or "").strip() else None
    mtproto = Path(args.zapret_mtproto) if str(args.zapret_mtproto or "").strip() else None

    if root is not None:
        entry = entry or (root / "entry-lite.env")
        transit = transit or (root / "transit-lite.env")
        interconnect = interconnect or (root / "entry-transit-stealth.env")
        inferred_mtproto = root / "mtproto-extra.env"
        if mtproto is None and inferred_mtproto.exists():
            mtproto = inferred_mtproto

    return entry, transit, interconnect, mtproto


def _print_findings(findings: list[RuntimePreflightFinding]) -> None:
    for finding in findings:
        print(f"{finding.severity.upper()} [{finding.code}] {finding.message}")


def _load_runtime_state_pair(args: argparse.Namespace) -> tuple[ObfuscationRuntimeState | None, ObfuscationRuntimeState | None]:
    entry_path_raw = str(args.entry_runtime_state or "").strip()
    transit_path_raw = str(args.transit_runtime_state or "").strip()
    if not entry_path_raw and not transit_path_raw:
        return None, None
    if not entry_path_raw or not transit_path_raw:
        raise SystemExit("runtime-state validation requires both --entry-runtime-state and --transit-runtime-state")
    try:
        return load_obfuscation_runtime_state(Path(entry_path_raw)), load_obfuscation_runtime_state(Path(transit_path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_runtime_env_pair(args: argparse.Namespace) -> tuple[ObfuscationRuntimeEnv | None, ObfuscationRuntimeEnv | None]:
    entry_path_raw = str(args.entry_runtime_env or "").strip()
    transit_path_raw = str(args.transit_runtime_env or "").strip()
    if not entry_path_raw and not transit_path_raw:
        return None, None
    if not entry_path_raw or not transit_path_raw:
        raise SystemExit("runtime-state env validation requires both --entry-runtime-env and --transit-runtime-env")
    try:
        return load_obfuscation_runtime_env(Path(entry_path_raw)), load_obfuscation_runtime_env(Path(transit_path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_private_profile_state_pair(args: argparse.Namespace) -> tuple[PrivateProfileState | None, PrivateProfileState | None]:
    entry_path_raw = str(args.entry_profile_state or "").strip()
    transit_path_raw = str(args.transit_profile_state or "").strip()
    if not entry_path_raw and not transit_path_raw:
        return None, None
    if not entry_path_raw or not transit_path_raw:
        raise SystemExit("private profile validation requires both --entry-profile-state and --transit-profile-state")
    try:
        return load_private_profile_state(Path(entry_path_raw)), load_private_profile_state(Path(transit_path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_private_profile_env_pair(args: argparse.Namespace) -> tuple[PrivateProfileEnv | None, PrivateProfileEnv | None]:
    entry_path_raw = str(args.entry_profile_env or "").strip()
    transit_path_raw = str(args.transit_profile_env or "").strip()
    if not entry_path_raw and not transit_path_raw:
        return None, None
    if not entry_path_raw or not transit_path_raw:
        raise SystemExit("private profile env validation requires both --entry-profile-env and --transit-profile-env")
    try:
        return load_private_profile_env(Path(entry_path_raw)), load_private_profile_env(Path(transit_path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_link_crypto_state_pair(args: argparse.Namespace) -> tuple[LinkCryptoState | None, LinkCryptoState | None]:
    entry_path_raw = str(args.entry_link_crypto_state or "").strip()
    transit_path_raw = str(args.transit_link_crypto_state or "").strip()
    if not entry_path_raw and not transit_path_raw:
        return None, None
    if not entry_path_raw or not transit_path_raw:
        raise SystemExit("link-crypto validation requires both --entry-link-crypto-state and --transit-link-crypto-state")
    try:
        return load_link_crypto_state(Path(entry_path_raw)), load_link_crypto_state(Path(transit_path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_link_crypto_env_pair(args: argparse.Namespace) -> tuple[LinkCryptoEnv | None, LinkCryptoEnv | None]:
    entry_path_raw = str(args.entry_link_crypto_env or "").strip()
    transit_path_raw = str(args.transit_link_crypto_env or "").strip()
    if not entry_path_raw and not transit_path_raw:
        return None, None
    if not entry_path_raw or not transit_path_raw:
        raise SystemExit("link-crypto env validation requires both --entry-link-crypto-env and --transit-link-crypto-env")
    try:
        return load_link_crypto_env(Path(entry_path_raw)), load_link_crypto_env(Path(transit_path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_runtime_state_single(args: argparse.Namespace, *, role: str) -> ObfuscationRuntimeState | None:
    attr_name = "entry_runtime_state" if role.upper() == "ENTRY" else "transit_runtime_state"
    path_raw = str(getattr(args, attr_name, "") or "").strip()
    if not path_raw:
        return None
    try:
        return load_obfuscation_runtime_state(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_runtime_env_single(args: argparse.Namespace, *, role: str) -> ObfuscationRuntimeEnv | None:
    attr_name = "entry_runtime_env" if role.upper() == "ENTRY" else "transit_runtime_env"
    path_raw = str(getattr(args, attr_name, "") or "").strip()
    if not path_raw:
        return None
    try:
        return load_obfuscation_runtime_env(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_private_profile_state_single(args: argparse.Namespace, *, role: str) -> PrivateProfileState | None:
    attr_name = "entry_profile_state" if role.upper() == "ENTRY" else "transit_profile_state"
    path_raw = str(getattr(args, attr_name, "") or "").strip()
    if not path_raw:
        return None
    try:
        return load_private_profile_state(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_private_profile_env_single(args: argparse.Namespace, *, role: str) -> PrivateProfileEnv | None:
    attr_name = "entry_profile_env" if role.upper() == "ENTRY" else "transit_profile_env"
    path_raw = str(getattr(args, attr_name, "") or "").strip()
    if not path_raw:
        return None
    try:
        return load_private_profile_env(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_link_crypto_state_single(args: argparse.Namespace, *, role: str) -> LinkCryptoState | None:
    attr_name = "entry_link_crypto_state" if role.upper() == "ENTRY" else "transit_link_crypto_state"
    path_raw = str(getattr(args, attr_name, "") or "").strip()
    if not path_raw:
        return None
    try:
        return load_link_crypto_state(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_link_crypto_env_single(args: argparse.Namespace, *, role: str) -> LinkCryptoEnv | None:
    attr_name = "entry_link_crypto_env" if role.upper() == "ENTRY" else "transit_link_crypto_env"
    path_raw = str(getattr(args, attr_name, "") or "").strip()
    if not path_raw:
        return None
    try:
        return load_link_crypto_env(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_obfuscation_env(args: argparse.Namespace) -> ObfuscationEnvContract | None:
    path_raw = str(args.obfuscation_env or "").strip()
    if not path_raw:
        return None
    try:
        return load_obfuscation_env_contract(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_systemd_unit(args: argparse.Namespace, arg_name: str) -> SystemdUnitContract | None:
    path_raw = str(getattr(args, arg_name, "") or "").strip()
    if not path_raw:
        return None
    try:
        return load_systemd_unit_contract(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_fronting_state(args: argparse.Namespace) -> FrontingRuntimeState | None:
    path_raw = str(args.fronting_state or "").strip()
    if not path_raw:
        return None
    try:
        return load_fronting_runtime_state(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_fronting_env(args: argparse.Namespace) -> FrontingEnvContract | None:
    path_raw = str(args.fronting_env or "").strip()
    if not path_raw:
        return None
    try:
        return load_fronting_env_contract(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_mtproto_state(args: argparse.Namespace) -> MTProtoGatewayState | None:
    path_raw = str(args.mtproto_state or "").strip()
    if not path_raw:
        return None
    try:
        return load_mtproto_gateway_state(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_mtproto_env(args: argparse.Namespace) -> MTProtoEnvContract | None:
    path_raw = str(args.mtproto_env or "").strip()
    if not path_raw:
        return None
    try:
        return load_mtproto_env_contract(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_mtproto_public_profile(args: argparse.Namespace) -> MTProtoPublicProfile | None:
    path_raw = str(args.mtproto_public_profile or "").strip()
    if not path_raw:
        return None
    try:
        return load_mtproto_public_profile(Path(path_raw))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc


def _load_contract(path: str, *, label: str) -> dict:
    try:
        return load_runtime_contract(Path(path))
    except RuntimePreflightError as exc:
        raise SystemExit(f"{label}: {exc}") from exc


def _print_single_role_report(
    *,
    args: argparse.Namespace,
    role: str,
    findings: list[RuntimePreflightFinding],
    obfuscation_env: ObfuscationEnvContract | None,
    obfuscation_unit: SystemdUnitContract | None,
    runtime_state: ObfuscationRuntimeState | None,
    runtime_env: ObfuscationRuntimeEnv | None,
    private_profile_state: PrivateProfileState | None,
    private_profile_env: PrivateProfileEnv | None,
    profiles_unit: SystemdUnitContract | None,
    link_crypto_state: LinkCryptoState | None,
    link_crypto_env: LinkCryptoEnv | None,
    link_crypto_unit: SystemdUnitContract | None,
    fronting_state: FrontingRuntimeState | None,
    fronting_env: FrontingEnvContract | None,
    fronting_unit: SystemdUnitContract | None,
    mtproto_state: MTProtoGatewayState | None,
    mtproto_env: MTProtoEnvContract | None,
    mtproto_unit: SystemdUnitContract | None,
    mtproto_public_profile: MTProtoPublicProfile | None,
    zapret_entry_path: Path | None,
    zapret_transit_path: Path | None,
    zapret_interconnect_path: Path | None,
    zapret_mtproto_path: Path | None,
    zapret_enabled: bool,
) -> None:
    role_upper = role.upper()
    role_lower = role.lower()

    print(f"mode={role_lower}")
    if role_upper == "ENTRY":
        print(f"entry={args.entry}")
    else:
        print(f"transit={args.transit}")
    if obfuscation_env is not None:
        print(f"obfuscation_env={args.obfuscation_env}")
    if obfuscation_unit is not None:
        print(f"obfuscation_unit={args.obfuscation_unit}")
    if runtime_state is not None:
        label = "entry_runtime_state" if role_upper == "ENTRY" else "transit_runtime_state"
        value = args.entry_runtime_state if role_upper == "ENTRY" else args.transit_runtime_state
        print(f"{label}={value}")
    if runtime_env is not None:
        label = "entry_runtime_env" if role_upper == "ENTRY" else "transit_runtime_env"
        value = args.entry_runtime_env if role_upper == "ENTRY" else args.transit_runtime_env
        print(f"{label}={value}")
    if private_profile_state is not None:
        label = "entry_profile_state" if role_upper == "ENTRY" else "transit_profile_state"
        value = args.entry_profile_state if role_upper == "ENTRY" else args.transit_profile_state
        print(f"{label}={value}")
    if private_profile_env is not None:
        label = "entry_profile_env" if role_upper == "ENTRY" else "transit_profile_env"
        value = args.entry_profile_env if role_upper == "ENTRY" else args.transit_profile_env
        print(f"{label}={value}")
    if profiles_unit is not None:
        print(f"profiles_unit={args.profiles_unit}")
    if link_crypto_state is not None:
        label = "entry_link_crypto_state" if role_upper == "ENTRY" else "transit_link_crypto_state"
        value = args.entry_link_crypto_state if role_upper == "ENTRY" else args.transit_link_crypto_state
        print(f"{label}={value}")
    if link_crypto_env is not None:
        label = "entry_link_crypto_env" if role_upper == "ENTRY" else "transit_link_crypto_env"
        value = args.entry_link_crypto_env if role_upper == "ENTRY" else args.transit_link_crypto_env
        print(f"{label}={value}")
    if link_crypto_unit is not None:
        print(f"link_crypto_unit={args.link_crypto_unit}")
    if fronting_state is not None:
        print(f"fronting_state={args.fronting_state}")
    if fronting_env is not None:
        print(f"fronting_env={args.fronting_env}")
    if fronting_unit is not None:
        print(f"fronting_unit={args.fronting_unit}")
    if mtproto_state is not None:
        print(f"mtproto_state={args.mtproto_state}")
    if mtproto_env is not None:
        print(f"mtproto_env={args.mtproto_env}")
    if mtproto_unit is not None:
        print(f"mtproto_unit={args.mtproto_unit}")
    if mtproto_public_profile is not None:
        print(f"mtproto_public_profile={args.mtproto_public_profile}")
    if zapret_entry_path is not None:
        print(f"zapret_entry={zapret_entry_path}")
    if zapret_transit_path is not None:
        print(f"zapret_transit={zapret_transit_path}")
    if zapret_interconnect_path is not None:
        print(f"zapret_interconnect={zapret_interconnect_path}")
    if zapret_mtproto_path is not None:
        print(f"zapret_mtproto={zapret_mtproto_path}")

    errors = [finding for finding in findings if finding.severity == "error"]
    warnings = [finding for finding in findings if finding.severity == "warning"]

    if findings:
        _print_findings(findings)
    else:
        has_private_runtime_chain = any(
            item is not None
            for item in (
                obfuscation_env,
                obfuscation_unit,
                runtime_state,
                private_profile_state,
                profiles_unit,
                link_crypto_state,
                link_crypto_unit,
                fronting_state,
                fronting_unit,
                mtproto_state,
                mtproto_unit,
                mtproto_public_profile,
            )
        )
        has_private_env_chain = any(
            item is not None
            for item in (
                obfuscation_env,
                obfuscation_unit,
                runtime_env,
                private_profile_env,
                profiles_unit,
                link_crypto_env,
                link_crypto_unit,
                fronting_env,
                fronting_unit,
                mtproto_env,
                mtproto_unit,
            )
        )
        if zapret_enabled and (has_private_runtime_chain or has_private_env_chain):
            print(f"OK {role_lower} runtime contract, zapret profiles and private handoffs are internally consistent")
        elif zapret_enabled:
            print(f"OK {role_lower} runtime contract and zapret profiles are internally consistent")
        elif has_private_runtime_chain and has_private_env_chain:
            print(f"OK {role_lower} runtime contract and private runtime/env handoffs are internally consistent")
        elif has_private_env_chain:
            print(f"OK {role_lower} runtime contract and private env contracts are internally consistent")
        elif has_private_runtime_chain:
            print(f"OK {role_lower} runtime contract and private runtime-state handoffs are internally consistent")
        else:
            print(f"OK {role_lower} runtime contract is internally consistent")

    if errors:
        raise SystemExit(1)
    if warnings and args.strict:
        raise SystemExit(2)


def _run_single_role_mode(args: argparse.Namespace) -> None:
    role_upper = str(args.mode or "").strip().upper()
    if role_upper not in {"ENTRY", "TRANSIT"}:
        raise SystemExit(f"unsupported single-role mode: {args.mode}")

    contract_path = args.entry if role_upper == "ENTRY" else args.transit
    contract = _load_contract(contract_path, label=f"{role_upper.lower()} runtime-contract")
    findings = validate_runtime_contract_single(contract, expected_role=role_upper)

    obfuscation_env = _load_obfuscation_env(args)
    obfuscation_unit = _load_systemd_unit(args, "obfuscation_unit")
    runtime_state = _load_runtime_state_single(args, role=role_upper)
    runtime_env = _load_runtime_env_single(args, role=role_upper)
    private_profile_state = _load_private_profile_state_single(args, role=role_upper)
    private_profile_env = _load_private_profile_env_single(args, role=role_upper)
    profiles_unit = _load_systemd_unit(args, "profiles_unit")
    link_crypto_state = _load_link_crypto_state_single(args, role=role_upper)
    link_crypto_env = _load_link_crypto_env_single(args, role=role_upper)
    link_crypto_unit = _load_systemd_unit(args, "link_crypto_unit")
    fronting_state = _load_fronting_state(args) if role_upper == "TRANSIT" else None
    fronting_env = _load_fronting_env(args) if role_upper == "TRANSIT" else None
    fronting_unit = _load_systemd_unit(args, "fronting_unit") if role_upper == "TRANSIT" else None
    mtproto_state = _load_mtproto_state(args) if role_upper == "TRANSIT" else None
    mtproto_env = _load_mtproto_env(args) if role_upper == "TRANSIT" else None
    mtproto_unit = _load_systemd_unit(args, "mtproto_unit") if role_upper == "TRANSIT" else None
    mtproto_public_profile = _load_mtproto_public_profile(args) if role_upper == "TRANSIT" else None

    zapret_entry_path, zapret_transit_path, zapret_interconnect_path, zapret_mtproto_path = _resolve_zapret_paths(args)
    zapret_enabled = any(path is not None for path in (zapret_entry_path, zapret_transit_path, zapret_interconnect_path, zapret_mtproto_path))

    entry_profile = None
    transit_profile = None
    interconnect_profile = None
    mtproto_profile = None

    if zapret_enabled:
        try:
            if role_upper == "ENTRY":
                if zapret_entry_path is None or zapret_interconnect_path is None:
                    raise SystemExit("entry-only zapret validation requires entry and interconnect profile paths")
                entry_profile = load_zapret_profile(zapret_entry_path)
                interconnect_profile = load_zapret_profile(zapret_interconnect_path)
                findings.extend(validate_zapret_profile(entry_profile, profile_kind="entry"))
                findings.extend(validate_zapret_profile(interconnect_profile, profile_kind="interconnect"))
            else:
                if zapret_transit_path is None:
                    raise SystemExit("transit-only zapret validation requires transit profile path")
                transit_profile = load_zapret_profile(zapret_transit_path)
                interconnect_profile = load_zapret_profile(zapret_interconnect_path) if zapret_interconnect_path is not None else None
                mtproto_profile = load_zapret_profile(zapret_mtproto_path) if zapret_mtproto_path is not None else None
                findings.extend(validate_zapret_profile(transit_profile, profile_kind="transit"))
                if interconnect_profile is not None:
                    findings.extend(validate_zapret_profile(interconnect_profile, profile_kind="interconnect"))
                if mtproto_profile is not None:
                    findings.extend(validate_zapret_profile(mtproto_profile, profile_kind="mtproto"))

                fronting_block = contract.get("fronting")
                transit_mtproto_domain = str(fronting_block.get("mtprotoDomain") or "").strip() if isinstance(fronting_block, dict) else ""
                if mtproto_profile is not None and not transit_mtproto_domain:
                    findings.append(
                        RuntimePreflightFinding(
                            severity="warning",
                            code="zapret-mtproto-no-domain",
                            message="MTProto zapret profile is present but Transit runtime-contract does not advertise an MTProto domain",
                        )
                    )
                if mtproto_profile is None and transit_mtproto_domain:
                    findings.append(
                        RuntimePreflightFinding(
                            severity="warning",
                            code="zapret-mtproto-missing-profile",
                            message="Transit runtime-contract advertises an MTProto domain but no MTProto zapret profile was validated",
                        )
                    )
        except RuntimePreflightError as exc:
            raise SystemExit(str(exc)) from exc

    if obfuscation_env is not None:
        findings.extend(
            validate_obfuscation_env_contract(
                env=obfuscation_env,
                entry_contract_path=args.entry if role_upper == "ENTRY" else None,
                transit_contract_path=args.transit if role_upper == "TRANSIT" else None,
                entry_profile=entry_profile,
                transit_profile=transit_profile,
                interconnect_profile=interconnect_profile,
                mtproto_profile=mtproto_profile,
                entry_runtime_state=runtime_state if role_upper == "ENTRY" else None,
                transit_runtime_state=runtime_state if role_upper == "TRANSIT" else None,
                entry_runtime_env=runtime_env if role_upper == "ENTRY" else None,
                transit_runtime_env=runtime_env if role_upper == "TRANSIT" else None,
                fronting_env=fronting_env,
                mtproto_env=mtproto_env,
            )
        )
    if obfuscation_unit is not None:
        findings.extend(
            validate_private_helper_unit_contract(
                unit=obfuscation_unit,
                unit_kind="obfuscation",
                expected_runner_path="/etc/tracegate/private/systemd/run-obfuscation.sh",
                expected_env_path=str(args.obfuscation_env or "/etc/tracegate/private/systemd/obfuscation.env"),
                expected_description_fragment="private obfuscation helper",
            )
        )

    if runtime_state is not None:
        findings.extend(
            validate_obfuscation_runtime_state(
                state=runtime_state,
                contract=contract,
                expected_role=role_upper,
                contract_path=contract_path,
                zapret_profile=entry_profile if role_upper == "ENTRY" else transit_profile,
                zapret_interconnect_profile=interconnect_profile,
                zapret_mtproto_profile=mtproto_profile if role_upper == "TRANSIT" else None,
            )
        )
    if runtime_env is not None:
        findings.extend(
            validate_obfuscation_runtime_env(
                env=runtime_env,
                contract=contract,
                expected_role=role_upper,
                runtime_state=runtime_state,
                contract_path=contract_path,
                zapret_profile=entry_profile if role_upper == "ENTRY" else transit_profile,
                zapret_interconnect_profile=interconnect_profile,
                zapret_mtproto_profile=mtproto_profile if role_upper == "TRANSIT" else None,
            )
        )
    if private_profile_state is not None:
        findings.extend(
            validate_private_profile_state(
                state=private_profile_state,
                contract=contract,
                expected_role=role_upper,
                contract_path=contract_path,
            )
        )
    if private_profile_env is not None:
        findings.extend(
            validate_private_profile_env(
                env=private_profile_env,
                expected_role=role_upper,
                contract=contract,
                state=private_profile_state,
            )
        )
    if profiles_unit is not None:
        findings.extend(
            validate_private_helper_unit_contract(
                unit=profiles_unit,
                unit_kind="profiles",
                expected_runner_path="/etc/tracegate/private/profiles/run-profiles.sh",
                expected_env_path="/etc/tracegate/private/profiles/profiles.env",
                expected_description_fragment="private profile adapter helper",
            )
        )
    if link_crypto_state is not None:
        findings.extend(
            validate_link_crypto_state(
                state=link_crypto_state,
                contract=contract,
                expected_role=role_upper,
                contract_path=contract_path,
            )
        )
    if link_crypto_env is not None:
        findings.extend(
            validate_link_crypto_env(
                env=link_crypto_env,
                expected_role=role_upper,
                contract=contract,
                state=link_crypto_state,
            )
        )
    if profiles_unit is not None:
        findings.extend(
            validate_private_helper_unit_contract(
                unit=profiles_unit,
                unit_kind="profiles",
                expected_runner_path="/etc/tracegate/private/profiles/run-profiles.sh",
                expected_env_path="/etc/tracegate/private/profiles/profiles.env",
                expected_description_fragment="private profile adapter helper",
            )
        )

    if link_crypto_unit is not None:
        findings.extend(
            validate_private_helper_unit_contract(
                unit=link_crypto_unit,
                unit_kind="link-crypto",
                expected_runner_path="/etc/tracegate/private/link-crypto/run-link-crypto.sh",
                expected_env_path="/etc/tracegate/private/link-crypto/link-crypto.env",
                expected_description_fragment="private link-crypto helper",
            )
        )

    if role_upper == "TRANSIT":
        if fronting_state is not None:
            findings.extend(
                validate_fronting_runtime_state(
                    state=fronting_state,
                    transit_contract=contract,
                    transit_runtime_state=runtime_state,
                    mtproto_profile=mtproto_profile,
                )
            )
        if fronting_env is not None:
            findings.extend(
                validate_fronting_env_contract(
                    env=fronting_env,
                    transit_contract=contract,
                    transit_runtime_state=runtime_state,
                    mtproto_profile=mtproto_profile,
                    fronting_state=fronting_state,
                )
            )
        if fronting_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=fronting_unit,
                    unit_kind="fronting",
                    expected_runner_path="/etc/tracegate/private/fronting/run-fronting.sh",
                    expected_env_path=str(args.fronting_env or "/etc/tracegate/private/fronting/fronting.env"),
                    expected_description_fragment="private TCP/443 fronting helper",
                )
            )
        if mtproto_state is not None:
            findings.extend(
                validate_mtproto_gateway_state(
                    state=mtproto_state,
                    transit_contract=contract,
                    transit_runtime_state=runtime_state,
                    mtproto_profile=mtproto_profile,
                    public_profile=mtproto_public_profile,
                )
            )
        if mtproto_env is not None:
            findings.extend(
                validate_mtproto_env_contract(
                    env=mtproto_env,
                    transit_contract=contract,
                    transit_runtime_state=runtime_state,
                    mtproto_profile=mtproto_profile,
                    fronting_env=fronting_env,
                    fronting_state=fronting_state,
                    gateway_state=mtproto_state,
                    public_profile=mtproto_public_profile,
                )
            )
        if mtproto_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=mtproto_unit,
                    unit_kind="mtproto",
                    expected_runner_path="/etc/tracegate/private/mtproto/run-mtproto.sh",
                    expected_env_path=str(args.mtproto_env or "/etc/tracegate/private/mtproto/mtproto.env"),
                    expected_description_fragment="private MTProto gateway",
                )
            )

    _print_single_role_report(
        args=args,
        role=role_upper,
        findings=findings,
        obfuscation_env=obfuscation_env,
        obfuscation_unit=obfuscation_unit,
        runtime_state=runtime_state,
        runtime_env=runtime_env,
        private_profile_state=private_profile_state,
        private_profile_env=private_profile_env,
        profiles_unit=profiles_unit,
        link_crypto_state=link_crypto_state,
        link_crypto_env=link_crypto_env,
        link_crypto_unit=link_crypto_unit,
        fronting_state=fronting_state,
        fronting_env=fronting_env,
        fronting_unit=fronting_unit,
        mtproto_state=mtproto_state,
        mtproto_env=mtproto_env,
        mtproto_unit=mtproto_unit,
        mtproto_public_profile=mtproto_public_profile,
        zapret_entry_path=zapret_entry_path,
        zapret_transit_path=zapret_transit_path,
        zapret_interconnect_path=zapret_interconnect_path,
        zapret_mtproto_path=zapret_mtproto_path,
        zapret_enabled=zapret_enabled,
    )


def main() -> None:
    args = _parser().parse_args()

    if args.mode != "pair":
        _run_single_role_mode(args)
        return

    try:
        entry_contract = load_runtime_contract(Path(args.entry))
        transit_contract = load_runtime_contract(Path(args.transit))
    except RuntimePreflightError as exc:
        raise SystemExit(str(exc)) from exc

    findings = validate_runtime_contract_pair(entry_contract, transit_contract)
    obfuscation_env = _load_obfuscation_env(args)
    obfuscation_unit = _load_systemd_unit(args, "obfuscation_unit")
    entry_runtime_state, transit_runtime_state = _load_runtime_state_pair(args)
    entry_runtime_env, transit_runtime_env = _load_runtime_env_pair(args)
    entry_private_profile_state, transit_private_profile_state = _load_private_profile_state_pair(args)
    entry_private_profile_env, transit_private_profile_env = _load_private_profile_env_pair(args)
    profiles_unit = _load_systemd_unit(args, "profiles_unit")
    entry_link_crypto_state, transit_link_crypto_state = _load_link_crypto_state_pair(args)
    entry_link_crypto_env, transit_link_crypto_env = _load_link_crypto_env_pair(args)
    link_crypto_unit = _load_systemd_unit(args, "link_crypto_unit")
    fronting_state = _load_fronting_state(args)
    fronting_env = _load_fronting_env(args)
    fronting_unit = _load_systemd_unit(args, "fronting_unit")
    mtproto_state = _load_mtproto_state(args)
    mtproto_env = _load_mtproto_env(args)
    mtproto_unit = _load_systemd_unit(args, "mtproto_unit")
    mtproto_public_profile = _load_mtproto_public_profile(args)
    zapret_entry_path, zapret_transit_path, zapret_interconnect_path, zapret_mtproto_path = _resolve_zapret_paths(args)
    zapret_enabled = any(path is not None for path in (zapret_entry_path, zapret_transit_path, zapret_interconnect_path, zapret_mtproto_path))

    if zapret_enabled:
        if zapret_entry_path is None or zapret_transit_path is None or zapret_interconnect_path is None:
            raise SystemExit("zapret validation requires entry, transit and interconnect profile paths")
        try:
            entry_profile = load_zapret_profile(zapret_entry_path)
            transit_profile = load_zapret_profile(zapret_transit_path)
            interconnect_profile = load_zapret_profile(zapret_interconnect_path)
            mtproto_profile = load_zapret_profile(zapret_mtproto_path) if zapret_mtproto_path is not None else None
        except RuntimePreflightError as exc:
            raise SystemExit(str(exc)) from exc

        findings.extend(
            validate_zapret_profile_collection(
                entry_profile=entry_profile,
                transit_profile=transit_profile,
                interconnect_profile=interconnect_profile,
                mtproto_profile=mtproto_profile,
                transit_contract=transit_contract,
            )
        )

        if obfuscation_env is not None:
            findings.extend(
                validate_obfuscation_env_contract(
                    env=obfuscation_env,
                    entry_contract_path=args.entry,
                    transit_contract_path=args.transit,
                    entry_profile=entry_profile,
                    transit_profile=transit_profile,
                    interconnect_profile=interconnect_profile,
                    mtproto_profile=mtproto_profile,
                    entry_runtime_state=entry_runtime_state,
                    transit_runtime_state=transit_runtime_state,
                    entry_runtime_env=entry_runtime_env,
                    transit_runtime_env=transit_runtime_env,
                    fronting_env=fronting_env,
                    mtproto_env=mtproto_env,
                )
            )
        if obfuscation_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=obfuscation_unit,
                    unit_kind="obfuscation",
                    expected_runner_path="/etc/tracegate/private/systemd/run-obfuscation.sh",
                    expected_env_path=str(args.obfuscation_env or "/etc/tracegate/private/systemd/obfuscation.env"),
                    expected_description_fragment="private obfuscation helper",
                )
            )

        if entry_runtime_state is not None and transit_runtime_state is not None:
            findings.extend(
                validate_obfuscation_runtime_state(
                    state=entry_runtime_state,
                    contract=entry_contract,
                    expected_role="ENTRY",
                    contract_path=args.entry,
                    zapret_profile=entry_profile,
                    zapret_interconnect_profile=interconnect_profile,
                )
            )
            findings.extend(
                validate_obfuscation_runtime_state(
                    state=transit_runtime_state,
                    contract=transit_contract,
                    expected_role="TRANSIT",
                    contract_path=args.transit,
                    zapret_profile=transit_profile,
                    zapret_interconnect_profile=interconnect_profile,
                    zapret_mtproto_profile=mtproto_profile,
                )
            )
        if entry_runtime_env is not None and transit_runtime_env is not None:
            findings.extend(
                validate_obfuscation_runtime_env(
                    env=entry_runtime_env,
                    contract=entry_contract,
                    expected_role="ENTRY",
                    runtime_state=entry_runtime_state,
                    contract_path=args.entry,
                    zapret_profile=entry_profile,
                    zapret_interconnect_profile=interconnect_profile,
                )
            )
            findings.extend(
                validate_obfuscation_runtime_env(
                    env=transit_runtime_env,
                    contract=transit_contract,
                    expected_role="TRANSIT",
                    runtime_state=transit_runtime_state,
                    contract_path=args.transit,
                    zapret_profile=transit_profile,
                    zapret_interconnect_profile=interconnect_profile,
                    zapret_mtproto_profile=mtproto_profile,
                )
            )
        if fronting_state is not None:
            findings.extend(
                validate_fronting_runtime_state(
                    state=fronting_state,
                    transit_contract=transit_contract,
                    transit_runtime_state=transit_runtime_state,
                    mtproto_profile=mtproto_profile,
                )
            )
        if fronting_env is not None:
            findings.extend(
                validate_fronting_env_contract(
                    env=fronting_env,
                    transit_contract=transit_contract,
                    transit_runtime_state=transit_runtime_state,
                    mtproto_profile=mtproto_profile,
                    fronting_state=fronting_state,
                )
            )
        if fronting_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=fronting_unit,
                    unit_kind="fronting",
                    expected_runner_path="/etc/tracegate/private/fronting/run-fronting.sh",
                    expected_env_path=str(args.fronting_env or "/etc/tracegate/private/fronting/fronting.env"),
                    expected_description_fragment="private TCP/443 fronting helper",
                )
            )
        if mtproto_state is not None:
            findings.extend(
                validate_mtproto_gateway_state(
                    state=mtproto_state,
                    transit_contract=transit_contract,
                    transit_runtime_state=transit_runtime_state,
                    mtproto_profile=mtproto_profile,
                    public_profile=mtproto_public_profile,
                )
            )
        if mtproto_env is not None:
            findings.extend(
                validate_mtproto_env_contract(
                    env=mtproto_env,
                    transit_contract=transit_contract,
                    transit_runtime_state=transit_runtime_state,
                    mtproto_profile=mtproto_profile,
                    fronting_env=fronting_env,
                    fronting_state=fronting_state,
                    gateway_state=mtproto_state,
                    public_profile=mtproto_public_profile,
                )
            )
        if mtproto_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=mtproto_unit,
                    unit_kind="mtproto",
                    expected_runner_path="/etc/tracegate/private/mtproto/run-mtproto.sh",
                    expected_env_path=str(args.mtproto_env or "/etc/tracegate/private/mtproto/mtproto.env"),
                    expected_description_fragment="private MTProto gateway",
                )
            )
    elif entry_runtime_state is not None and transit_runtime_state is not None:
        findings.extend(
            validate_obfuscation_runtime_state(
                state=entry_runtime_state,
                contract=entry_contract,
                expected_role="ENTRY",
                contract_path=args.entry,
            )
        )
        findings.extend(
            validate_obfuscation_runtime_state(
                state=transit_runtime_state,
                contract=transit_contract,
                expected_role="TRANSIT",
                contract_path=args.transit,
            )
        )
        if entry_runtime_env is not None and transit_runtime_env is not None:
            findings.extend(
                validate_obfuscation_runtime_env(
                    env=entry_runtime_env,
                    contract=entry_contract,
                    expected_role="ENTRY",
                    runtime_state=entry_runtime_state,
                    contract_path=args.entry,
                )
            )
            findings.extend(
                validate_obfuscation_runtime_env(
                    env=transit_runtime_env,
                    contract=transit_contract,
                    expected_role="TRANSIT",
                    runtime_state=transit_runtime_state,
                    contract_path=args.transit,
                )
            )
        if obfuscation_env is not None:
            findings.extend(
                validate_obfuscation_env_contract(
                    env=obfuscation_env,
                    entry_contract_path=args.entry,
                    transit_contract_path=args.transit,
                    entry_runtime_state=entry_runtime_state,
                    transit_runtime_state=transit_runtime_state,
                    entry_runtime_env=entry_runtime_env,
                    transit_runtime_env=transit_runtime_env,
                    fronting_env=fronting_env,
                    mtproto_env=mtproto_env,
                )
            )
        if obfuscation_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=obfuscation_unit,
                    unit_kind="obfuscation",
                    expected_runner_path="/etc/tracegate/private/systemd/run-obfuscation.sh",
                    expected_env_path=str(args.obfuscation_env or "/etc/tracegate/private/systemd/obfuscation.env"),
                    expected_description_fragment="private obfuscation helper",
                )
            )
        if fronting_state is not None:
            findings.extend(
                validate_fronting_runtime_state(
                    state=fronting_state,
                    transit_contract=transit_contract,
                    transit_runtime_state=transit_runtime_state,
                )
            )
        if fronting_env is not None:
            findings.extend(
                validate_fronting_env_contract(
                    env=fronting_env,
                    transit_contract=transit_contract,
                    transit_runtime_state=transit_runtime_state,
                    fronting_state=fronting_state,
                )
            )
        if fronting_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=fronting_unit,
                    unit_kind="fronting",
                    expected_runner_path="/etc/tracegate/private/fronting/run-fronting.sh",
                    expected_env_path=str(args.fronting_env or "/etc/tracegate/private/fronting/fronting.env"),
                    expected_description_fragment="private TCP/443 fronting helper",
                )
            )
        if mtproto_state is not None:
            findings.extend(
                validate_mtproto_gateway_state(
                    state=mtproto_state,
                    transit_contract=transit_contract,
                    transit_runtime_state=transit_runtime_state,
                    public_profile=mtproto_public_profile,
                )
            )
        if mtproto_env is not None:
            findings.extend(
                validate_mtproto_env_contract(
                    env=mtproto_env,
                    transit_contract=transit_contract,
                    transit_runtime_state=transit_runtime_state,
                    fronting_env=fronting_env,
                    fronting_state=fronting_state,
                    gateway_state=mtproto_state,
                    public_profile=mtproto_public_profile,
                )
            )
        if mtproto_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=mtproto_unit,
                    unit_kind="mtproto",
                    expected_runner_path="/etc/tracegate/private/mtproto/run-mtproto.sh",
                    expected_env_path=str(args.mtproto_env or "/etc/tracegate/private/mtproto/mtproto.env"),
                    expected_description_fragment="private MTProto gateway",
                )
            )
    elif entry_runtime_env is not None and transit_runtime_env is not None:
        findings.extend(
            validate_obfuscation_runtime_env(
                env=entry_runtime_env,
                contract=entry_contract,
                expected_role="ENTRY",
                contract_path=args.entry,
            )
        )
        findings.extend(
            validate_obfuscation_runtime_env(
                env=transit_runtime_env,
                contract=transit_contract,
                expected_role="TRANSIT",
                contract_path=args.transit,
            )
        )
        if obfuscation_env is not None:
            findings.extend(
                validate_obfuscation_env_contract(
                    env=obfuscation_env,
                    entry_contract_path=args.entry,
                    transit_contract_path=args.transit,
                    entry_runtime_env=entry_runtime_env,
                    transit_runtime_env=transit_runtime_env,
                    fronting_env=fronting_env,
                    mtproto_env=mtproto_env,
                )
            )
        if obfuscation_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=obfuscation_unit,
                    unit_kind="obfuscation",
                    expected_runner_path="/etc/tracegate/private/systemd/run-obfuscation.sh",
                    expected_env_path=str(args.obfuscation_env or "/etc/tracegate/private/systemd/obfuscation.env"),
                    expected_description_fragment="private obfuscation helper",
                )
            )
        if fronting_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=fronting_unit,
                    unit_kind="fronting",
                    expected_runner_path="/etc/tracegate/private/fronting/run-fronting.sh",
                    expected_env_path=str(args.fronting_env or "/etc/tracegate/private/fronting/fronting.env"),
                    expected_description_fragment="private TCP/443 fronting helper",
                )
            )
        if mtproto_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=mtproto_unit,
                    unit_kind="mtproto",
                    expected_runner_path="/etc/tracegate/private/mtproto/run-mtproto.sh",
                    expected_env_path=str(args.mtproto_env or "/etc/tracegate/private/mtproto/mtproto.env"),
                    expected_description_fragment="private MTProto gateway",
                )
            )
    else:
        if obfuscation_env is not None:
            findings.extend(
                validate_obfuscation_env_contract(
                    env=obfuscation_env,
                    entry_contract_path=args.entry,
                    transit_contract_path=args.transit,
                    fronting_env=fronting_env,
                    mtproto_env=mtproto_env,
                )
            )
        if obfuscation_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=obfuscation_unit,
                    unit_kind="obfuscation",
                    expected_runner_path="/etc/tracegate/private/systemd/run-obfuscation.sh",
                    expected_env_path=str(args.obfuscation_env or "/etc/tracegate/private/systemd/obfuscation.env"),
                    expected_description_fragment="private obfuscation helper",
                )
            )
        if fronting_state is not None:
            findings.extend(validate_fronting_runtime_state(state=fronting_state, transit_contract=transit_contract))
        if fronting_env is not None:
            findings.extend(validate_fronting_env_contract(env=fronting_env, transit_contract=transit_contract, fronting_state=fronting_state))
        if fronting_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=fronting_unit,
                    unit_kind="fronting",
                    expected_runner_path="/etc/tracegate/private/fronting/run-fronting.sh",
                    expected_env_path=str(args.fronting_env or "/etc/tracegate/private/fronting/fronting.env"),
                    expected_description_fragment="private TCP/443 fronting helper",
                )
            )
        if mtproto_state is not None:
            findings.extend(
                validate_mtproto_gateway_state(
                    state=mtproto_state,
                    transit_contract=transit_contract,
                    public_profile=mtproto_public_profile,
                )
            )
        if mtproto_env is not None:
            findings.extend(
                validate_mtproto_env_contract(
                    env=mtproto_env,
                    transit_contract=transit_contract,
                    fronting_env=fronting_env,
                    fronting_state=fronting_state,
                    gateway_state=mtproto_state,
                    public_profile=mtproto_public_profile,
                )
            )
        if mtproto_unit is not None:
            findings.extend(
                validate_private_helper_unit_contract(
                    unit=mtproto_unit,
                    unit_kind="mtproto",
                    expected_runner_path="/etc/tracegate/private/mtproto/run-mtproto.sh",
                    expected_env_path=str(args.mtproto_env or "/etc/tracegate/private/mtproto/mtproto.env"),
                    expected_description_fragment="private MTProto gateway",
                )
            )

    if link_crypto_unit is not None:
        findings.extend(
            validate_private_helper_unit_contract(
                unit=link_crypto_unit,
                unit_kind="link-crypto",
                expected_runner_path="/etc/tracegate/private/link-crypto/run-link-crypto.sh",
                expected_env_path="/etc/tracegate/private/link-crypto/link-crypto.env",
                expected_description_fragment="private link-crypto helper",
            )
        )

    if entry_private_profile_state is not None and transit_private_profile_state is not None:
        findings.extend(
            validate_private_profile_state(
                state=entry_private_profile_state,
                contract=entry_contract,
                expected_role="ENTRY",
                contract_path=args.entry,
            )
        )
        findings.extend(
            validate_private_profile_state(
                state=transit_private_profile_state,
                contract=transit_contract,
                expected_role="TRANSIT",
                contract_path=args.transit,
            )
        )
    if entry_private_profile_env is not None and transit_private_profile_env is not None:
        findings.extend(
            validate_private_profile_env(
                env=entry_private_profile_env,
                expected_role="ENTRY",
                contract=entry_contract,
                state=entry_private_profile_state,
            )
        )
        findings.extend(
            validate_private_profile_env(
                env=transit_private_profile_env,
                expected_role="TRANSIT",
                contract=transit_contract,
                state=transit_private_profile_state,
            )
        )
    if entry_link_crypto_state is not None and transit_link_crypto_state is not None:
        findings.extend(
            validate_link_crypto_state(
                state=entry_link_crypto_state,
                contract=entry_contract,
                expected_role="ENTRY",
                contract_path=args.entry,
            )
        )
        findings.extend(
            validate_link_crypto_state(
                state=transit_link_crypto_state,
                contract=transit_contract,
                expected_role="TRANSIT",
                contract_path=args.transit,
            )
        )
    if entry_link_crypto_env is not None and transit_link_crypto_env is not None:
        findings.extend(
            validate_link_crypto_env(
                env=entry_link_crypto_env,
                expected_role="ENTRY",
                contract=entry_contract,
                state=entry_link_crypto_state,
            )
        )
        findings.extend(
            validate_link_crypto_env(
                env=transit_link_crypto_env,
                expected_role="TRANSIT",
                contract=transit_contract,
                state=transit_link_crypto_state,
            )
        )

    errors = [finding for finding in findings if finding.severity == "error"]
    warnings = [finding for finding in findings if finding.severity == "warning"]

    print(f"entry={args.entry}")
    print(f"transit={args.transit}")
    if obfuscation_env is not None:
        print(f"obfuscation_env={args.obfuscation_env}")
    if obfuscation_unit is not None:
        print(f"obfuscation_unit={args.obfuscation_unit}")
    if entry_runtime_state is not None:
        print(f"entry_runtime_state={args.entry_runtime_state}")
    if transit_runtime_state is not None:
        print(f"transit_runtime_state={args.transit_runtime_state}")
    if entry_runtime_env is not None:
        print(f"entry_runtime_env={args.entry_runtime_env}")
    if transit_runtime_env is not None:
        print(f"transit_runtime_env={args.transit_runtime_env}")
    if entry_private_profile_state is not None:
        print(f"entry_profile_state={args.entry_profile_state}")
    if transit_private_profile_state is not None:
        print(f"transit_profile_state={args.transit_profile_state}")
    if entry_private_profile_env is not None:
        print(f"entry_profile_env={args.entry_profile_env}")
    if transit_private_profile_env is not None:
        print(f"transit_profile_env={args.transit_profile_env}")
    if profiles_unit is not None:
        print(f"profiles_unit={args.profiles_unit}")
    if entry_link_crypto_state is not None:
        print(f"entry_link_crypto_state={args.entry_link_crypto_state}")
    if transit_link_crypto_state is not None:
        print(f"transit_link_crypto_state={args.transit_link_crypto_state}")
    if entry_link_crypto_env is not None:
        print(f"entry_link_crypto_env={args.entry_link_crypto_env}")
    if transit_link_crypto_env is not None:
        print(f"transit_link_crypto_env={args.transit_link_crypto_env}")
    if link_crypto_unit is not None:
        print(f"link_crypto_unit={args.link_crypto_unit}")
    if fronting_state is not None:
        print(f"fronting_state={args.fronting_state}")
    if fronting_env is not None:
        print(f"fronting_env={args.fronting_env}")
    if fronting_unit is not None:
        print(f"fronting_unit={args.fronting_unit}")
    if mtproto_state is not None:
        print(f"mtproto_state={args.mtproto_state}")
    if mtproto_env is not None:
        print(f"mtproto_env={args.mtproto_env}")
    if mtproto_unit is not None:
        print(f"mtproto_unit={args.mtproto_unit}")
    if mtproto_public_profile is not None:
        print(f"mtproto_public_profile={args.mtproto_public_profile}")
    if zapret_entry_path is not None:
        print(f"zapret_entry={zapret_entry_path}")
    if zapret_transit_path is not None:
        print(f"zapret_transit={zapret_transit_path}")
    if zapret_interconnect_path is not None:
        print(f"zapret_interconnect={zapret_interconnect_path}")
    if zapret_mtproto_path is not None:
        print(f"zapret_mtproto={zapret_mtproto_path}")
    if findings:
        _print_findings(findings)
    else:
        has_private_runtime_chain = any(
            item is not None
            for item in (
                obfuscation_env,
                obfuscation_unit,
                entry_runtime_state,
                transit_runtime_state,
                entry_runtime_env,
                transit_runtime_env,
                entry_private_profile_state,
                transit_private_profile_state,
                entry_private_profile_env,
                transit_private_profile_env,
                profiles_unit,
                entry_link_crypto_state,
                transit_link_crypto_state,
                entry_link_crypto_env,
                transit_link_crypto_env,
                link_crypto_unit,
                fronting_state,
                fronting_unit,
                mtproto_state,
                mtproto_unit,
                mtproto_public_profile,
            )
        )
        has_private_env_chain = any(
            item is not None
            for item in (
                obfuscation_env,
                obfuscation_unit,
                entry_runtime_env,
                transit_runtime_env,
                entry_private_profile_env,
                transit_private_profile_env,
                profiles_unit,
                entry_link_crypto_env,
                transit_link_crypto_env,
                link_crypto_unit,
                fronting_env,
                fronting_unit,
                mtproto_env,
                mtproto_unit,
            )
        )
        if zapret_enabled and (has_private_runtime_chain or has_private_env_chain):
            print("OK runtime contracts, zapret profiles and private handoffs are internally consistent")
        elif zapret_enabled and entry_runtime_state is not None and transit_runtime_state is not None:
            print("OK runtime contracts, zapret profiles and obfuscation runtime-state are internally consistent")
        elif zapret_enabled:
            print("OK runtime contracts and zapret profiles are internally consistent")
        elif has_private_runtime_chain and has_private_env_chain:
            print("OK runtime contracts and private runtime/env handoffs are internally consistent")
        elif has_private_env_chain:
            print("OK runtime contracts and private env contracts are internally consistent")
        elif has_private_runtime_chain:
            print("OK runtime contracts and private runtime-state handoffs are internally consistent")
        elif entry_runtime_state is not None and transit_runtime_state is not None:
            print("OK runtime contracts and obfuscation runtime-state are internally consistent")
        else:
            print("OK runtime contracts are internally consistent")

    if errors:
        raise SystemExit(1)
    if warnings and args.strict:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
