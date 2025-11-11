import os
import re
import yaml
import json
import subprocess
import shutil
import pwd
import grp


# ==============================
# Helper functions
# ==============================

def run_command(command):
    """Run a shell command and return its output or error string."""
    if not command:
        return ""
    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT, text=True
        ).strip()
        return output
    except subprocess.CalledProcessError as e:
        return e.output.strip()
    except Exception as e:
        return f"Error: {e}"


def safe_run_command(command):
    """
    Run shell commands safely in minimal Kubernetes job environments.
    - Detects missing common binaries (ps, stat, find, grep) and uses fallbacks.
    - Handles permission errors gracefully.
    - Works with hostPID and /proc-based fallbacks.
    - Returns command output or descriptive error message.
    """
    if not command:
        return ""

    # --- Fallback 1: Replace missing /bin/ps with /proc-based scanning ---
    if "ps -ef" in command or "ps aux" in command:
        if not shutil.which("ps") and os.path.isdir("/proc"):
            try:
                processes = []
                for pid in os.listdir("/proc"):
                    if pid.isdigit():
                        cmdline_path = os.path.join("/proc", pid, "cmdline")
                        try:
                            with open(cmdline_path, "rb") as f:
                                cmdline = (
                                    f.read()
                                    .decode(errors="ignore")
                                    .replace("\x00", " ")
                                    .strip()
                                )
                                if "kube-apiserver" in cmdline:
                                    processes.append(cmdline)
                        except (FileNotFoundError, PermissionError):
                            continue
                if processes:
                    return "\n".join(processes)
                else:
                    return "No kube-apiserver process found in /proc"
            except Exception as e:
                return f"Error reading /proc fallback: {e}"

    # --- Fallback 2: Missing 'stat' command (use Python os.stat) ---
    if command.strip().startswith("stat "):
        tokens = command.split()
        for t in tokens:
            if os.path.exists(t):
                try:
                    st = os.stat(t)
                    mode = oct(st.st_mode & 0o777)
                    owner = pwd.getpwuid(st.st_uid).pw_name
                    group = grp.getgrgid(st.st_gid).gr_name
                    return f"permissions={mode} ownership={owner}:{group} file={t}"
                except Exception as e:
                    return f"Error inspecting {t}: {e}"
        return "No valid file found for stat fallback"

    # --- Normal case: try to run normally ---
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=20
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            if "Permission denied" in stderr:
                return f"Permission denied: {stderr or stdout}"
            elif "not found" in stderr:
                return f"Command not found: {stderr or stdout}"
            elif stdout:
                return stdout
            elif stderr:
                return stderr
            else:
                return f"Command failed with code {result.returncode}"
        else:
            return result.stdout.strip()

    except subprocess.TimeoutExpired:
        return "Command timed out"
    except FileNotFoundError:
        return f"Command not found: {command}"
    except Exception as e:
        return f"Unexpected error executing command: {e}"


# ==============================
# Test evaluation logic
# ==============================

def evaluate_test(audit_output, tests_def):
    """
    Evaluate audit output against CIS test definitions.
    Supports:
    - bin_op (and/or) across multiple test_items
    - flag/env presence with 'set' true/false
    - compare.op in: 'bitmask', 'eq', 'has', 'nothave', 'gte', 'valid_elements'
    - simple string matching
    """
    if not audit_output:
        return "WARN", "No output from audit command, the recommendation might be manual"

    audit_output = str(audit_output)

    # tests_def can be either a dict {"bin_op": ..., "test_items": [...]} or just a list
    if isinstance(tests_def, dict):
        test_items = tests_def.get("test_items", []) or []
        bin_op = (tests_def.get("bin_op") or "and").lower()
    else:
        test_items = tests_def or []
        bin_op = "and"

    results = []  # store individual PASS/FAIL/WARN entries

    for test in test_items:
        flag = test.get("flag")
        env = test.get("env")  # optional alternative match string
        compare = test.get("compare") or {}
        op = compare.get("op")
        expected_value = compare.get("value")

        # Build possible match targets (flag or env variable)
        match_targets = [t for t in (flag, env) if t]

        # --- Handle 'set' checks (presence/absence only) ---
        if "set" in test:
            should_exist = bool(test["set"])
            found_any = any(t in audit_output for t in match_targets)

            if should_exist and found_any:
                results.append(("PASS", f"{match_targets} present as expected"))
            elif should_exist and not found_any:
                results.append(("FAIL", f"{match_targets} missing"))
            elif not should_exist and found_any:
                results.append(("FAIL", f"{match_targets} should not be set"))
            else:
                results.append(("PASS", f"{match_targets} correctly unset"))
            continue

        # --- Compare block present ---
        if op:
            op = str(op).lower()

            if op == "bitmask":
                matched = False
                for token in audit_output.split():
                    if token.startswith("permissions="):
                        try:
                            actual_perm = int(token.split("=", 1)[1], 8)
                            expected_perm = int(expected_value or "600", 8)
                            if actual_perm <= expected_perm:
                                results.append(("PASS", f"Permissions {oct(actual_perm)} ≤ {oct(expected_perm)}"))
                            else:
                                results.append(("FAIL", f"Permissions {oct(actual_perm)} > expected {oct(expected_perm)}"))
                            matched = True
                            break
                        except ValueError:
                            continue
                if not matched:
                    results.append(("WARN", "Could not parse permissions"))

            elif op == "eq":
                matched = any(
                    t in audit_output and str(expected_value) in audit_output
                    for t in match_targets
                )
                if matched:
                    results.append(("PASS", f"{match_targets} == {expected_value}"))
                else:
                    results.append(("FAIL", f"{match_targets} != {expected_value}"))

            elif op == "has":
                # Flag/env should be present and its output should include expected_value
                matched = any(
                    t in audit_output and str(expected_value) in audit_output
                    for t in match_targets
                )
                if matched:
                    results.append(("PASS", f"{match_targets} contains {expected_value}"))
                else:
                    results.append(("FAIL", f"{match_targets} does not contain {expected_value}"))

            elif op in ("nothave", "not_have"):
                # Should not contain the forbidden value
                value_present = str(expected_value) in audit_output if expected_value is not None else False
                if value_present:
                    results.append(("FAIL", f"{match_targets} should not contain {expected_value}"))
                else:
                    results.append(("PASS", f"{match_targets} does not contain {expected_value}"))

            elif op == "gte":
                # Example: --audit-log-maxsize=100
                actual = None
                for t in match_targets:
                    if not t:
                        continue
                    m = re.search(rf"{re.escape(t)}[= ](\d+)", audit_output)
                    if m:
                        actual = int(m.group(1))
                        break

                try:
                    expected_num = int(expected_value)
                except Exception:
                    results.append(("WARN", f"Invalid expected numeric value {expected_value}"))
                    continue

                if actual is None:
                    results.append(("WARN", "Could not parse numeric value for comparison"))
                elif actual >= expected_num:
                    results.append(("PASS", f"{match_targets} >= {expected_num} (actual {actual})"))
                else:
                    results.append(("FAIL", f"{match_targets} < {expected_num} (actual {actual})"))

            elif op == "valid_elements":
                # Expected value is a comma-separated allow-list
                allowed = {s.strip() for s in str(expected_value).split(",") if s.strip()}
                actual_set = set()

                for t in match_targets:
                    if not t:
                        continue
                    m = re.search(rf"{re.escape(t)}=([A-Za-z0-9_@.\-+,]+)", audit_output)
                    if m:
                        actual_set.update(
                            s.strip() for s in m.group(1).split(",") if s.strip()
                        )

                if not actual_set:
                    results.append(("WARN", "Could not parse values for valid_elements"))
                else:
                    invalid = [c for c in actual_set if c not in allowed]
                    if invalid:
                        results.append(("FAIL", f"Found disallowed values: {', '.join(invalid)}"))
                    else:
                        results.append(("PASS", "All configured values are in the allowed list"))

            else:
                results.append(("WARN", f"Unknown compare op {op}"))

            continue  # done with this test item

        # --- Default simple presence match (no compare block) ---
        found_any = any(t in audit_output for t in match_targets)
        if found_any:
            results.append(("PASS", f"Found {match_targets}"))
        else:
            results.append(("FAIL", f"Did not find {match_targets}"))

    # Combine results based on bin_op
    statuses = [r[0] for r in results if r[0] != "WARN"]
    reasons = "; ".join([r[1] for r in results])

    if not statuses:
        return "WARN", reasons or "No valid test conditions"

    if bin_op == "and":
        final_status = "PASS" if all(s == "PASS" for s in statuses) else "FAIL"
    elif bin_op == "or":
        final_status = "PASS" if any(s == "PASS" for s in statuses) else "FAIL"
    else:
        final_status = "WARN"

    return final_status, reasons


# ==============================
# Main CIS processing logic
# ==============================

def process_cis_yaml(yaml_path):
    """Parse CIS controls YAML and evaluate all checks."""
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)

    if not data:
        raise ValueError("YAML file is empty or invalid")

    if "controls" in data and isinstance(data["controls"], dict) and data["controls"]:
        control = data["controls"]
    else:
        control = {
            "version": data.get("version"),
            "id": data.get("id"),
            "text": data.get("text"),
            "type": data.get("type"),
            "groups": data.get("groups", [])
        }

    groups = control.get("groups", [])
    results = []

    for group in groups:
        for check in group.get("checks", []):
            check_id = check.get("id")
            description = check.get("text")
            audit_cmd = check.get("audit")
            check_type = check.get("type")
            remediation = (check.get("remediation") or "").strip()
            tests = check.get("tests", {})  # pass full tests dict (bin_op + test_items)
            use_multiple = check.get("use_multiple_values", False)

            if check_type == "manual":
                results.append({
                    "check_id": check_id,
                    "description": description,
                    "status": "WARN",
                    "reason": "Manual Check, Please verify the recommendation and follow the remediation if needed",
                    "remediation": remediation
                })
                continue

            audit_output = safe_run_command(audit_cmd)

            if use_multiple:
                line_results = []
                all_pass = True
                any_fail = False

                lines = [line.strip() for line in audit_output.splitlines() if line.strip()]
                if not lines:
                    status, reason = "WARN", "No output lines found (possibly manual check)"
                else:
                    for line in lines:
                        try:
                            s, r = evaluate_test(line, tests)
                        except Exception as e:
                            s, r = "ERROR", f"Exception during evaluation: {e}"
                        line_results.append({"line": line, "status": s, "reason": r})
                        if s == "FAIL":
                            any_fail = True
                            all_pass = False
                        elif s != "PASS":
                            all_pass = False

                    if any_fail:
                        status, reason = "FAIL", "One or more lines failed"
                    elif all_pass:
                        status, reason = "PASS", "All lines passed"
                    else:
                        status, reason = "WARN", "No definitive PASS or FAIL"

                results.append({
                    "check_id": check_id,
                    "description": description,
                    "status": status,
                    "reason": reason,
                    "audit_command": audit_cmd,
                    "audit_output": audit_output,
                    "line_results": line_results,
                    "remediation": remediation
                })

            else:
                try:
                    status, reason = evaluate_test(audit_output, tests)
                except Exception as e:
                    status, reason = "ERROR", f"Exception during evaluation: {e}"

                results.append({
                    "check_id": check_id,
                    "description": description,
                    "status": status,
                    "reason": reason,
                    "audit_command": audit_cmd,
                    "audit_output": audit_output,
                    "remediation": remediation
                })

    return results


# ==============================
# Entry point
# ==============================

def main():
    MAIN_SOURCE = "cis-1.11"

    yamls_to_process = []
    if os.path.isdir(MAIN_SOURCE):
        for fn in sorted(os.listdir(MAIN_SOURCE)):
            if fn.lower().endswith((".yaml", ".yml")):
                yamls_to_process.append(os.path.join(MAIN_SOURCE, fn))
    elif os.path.isfile(MAIN_SOURCE):
        yamls_to_process.append(MAIN_SOURCE)
    else:
        print(f"Source '{MAIN_SOURCE}' not found (expected directory or file).")
        return

    all_results = []
    for yaml_path in yamls_to_process:
        try:
            res = process_cis_yaml(yaml_path)
            for r in res:
                r["_source_file"] = yaml_path
            all_results.extend(res)
        except Exception as e:
            all_results.append({
                "check_id": None,
                "description": None,
                "status": "ERROR",
                "reason": f"Failed to process {yaml_path}: {e}",
                "audit_command": None,
                "audit_output": None
            })

    os.makedirs("/output", exist_ok=True)
    output_file = "/output/results.json"

    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=4)
        f.write("\n")

    print(json.dumps(all_results, indent=4) + "\n")


if __name__ == "__main__":
    main()
