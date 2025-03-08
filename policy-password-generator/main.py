#!/usr/bin/env python3
import requests
import json
import argparse
import sys
import subprocess
import re

def normalize_name(name):
    """
    Normalize a string to be used as part of a Terraform resource name:
    - Convert to lowercase.
    - Replace non-alphanumeric characters with underscores.
    - Collapse multiple underscores into one.
    - Remove leading/trailing underscores.
    """
    name = name.lower()
    name = re.sub(r'[^a-z0-9]', '_', name)
    name = re.sub(r'_+', '_', name)
    return name.strip('_')

def build_okta_url(subdomain, domain, endpoint):
    """Construct the full Okta API URL."""
    return f"https://{subdomain}.{domain}{endpoint}"

def fetch_policies(subdomain, domain, api_token):
    """Fetch all PASSWORD policies."""
    url = build_okta_url(subdomain, domain, "/api/v1/policies")
    params = {"type": "PASSWORD"}
    headers = {"Authorization": f"SSWS {api_token}"}
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()

def fetch_policy_rules(subdomain, domain, api_token, policy_id):
    """Fetch rules for a given policy."""
    url = build_okta_url(subdomain, domain, f"/api/v1/policies/{policy_id}/rules")
    headers = {"Authorization": f"SSWS {api_token}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def tf_value(val, is_string=False):
    """
    Convert a Python value to a Terraform literal.
    - If val is None, return 'null'.
    - Booleans become 'true' or 'false'.
    - Numbers are left as is.
    - Strings are enclosed in quotes.
    """
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    return f'"{val}"'

def safe_get(d, keys):
    """Retrieve nested value from dict 'd' using a list of keys."""
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key)
        else:
            return None
        if d is None:
            return None
    return d

def generate_policy_block(policy, global_groups):
    """
    Generate the Terraform resource block for a password policy.
    Uses okta_policy_password_default if policy["system"] is true;
    otherwise, uses okta_policy_password.
    Returns the resource block string, resource type, and combined resource name in the format name_id.
    
    Also updates global_groups (a set) with any group IDs found in groups_included.
    """
    base_name = normalize_name(policy.get("name", policy["id"]))
    normalized_id = policy["id"].replace("-", "_")
    resource_name = f"{base_name}_{normalized_id}"
    resource_type = "okta_policy_password_default" if policy.get("system", False) else "okta_policy_password"

    lines = [f'resource "{resource_type}" "{resource_name}" {{']
    lines.append(f'  name        = {tf_value(policy.get("name"), True)}')
    lines.append(f'  description = {tf_value(policy.get("description"), True)}')
    lines.append(f'  status      = {tf_value(policy.get("status"), True)}')
    lines.append(f'  priority    = {tf_value(policy.get("priority"))}')

    # Process groups_included: Instead of raw IDs, reference data lookups.
    groups = safe_get(policy, ["conditions", "people", "groups", "include"])
    if groups and isinstance(groups, list):
        ref_list = []
        for group in groups:
            global_groups.add(group)
            ref_list.append(f"data.okta_group.group_{group}.id")
        groups_str = ", ".join(ref_list)
        lines.append(f'  groups_included = [{groups_str}]')
    else:
        lines.append(f'  groups_included = null')

    # For non-default policies, map additional settings.
    if resource_type == "okta_policy_password":
        settings = safe_get(policy, ["settings", "password"]) or {}
        age = settings.get("age", {})
        complexity = settings.get("complexity", {})
        lockout = settings.get("lockout", {})

        lines.append(f'  password_history_count = {tf_value(safe_get(age, ["historyCount"]))}')
        lines.append(f'  password_min_length = {tf_value(safe_get(complexity, ["minLength"]))}')
        lines.append(f'  password_min_lowercase = {tf_value(safe_get(complexity, ["minLowerCase"]))}')
        lines.append(f'  password_min_uppercase = {tf_value(safe_get(complexity, ["minUpperCase"]))}')
        lines.append(f'  password_min_number = {tf_value(safe_get(complexity, ["minNumber"]))}')
        lines.append(f'  password_min_symbol = {tf_value(safe_get(complexity, ["minSymbol"]))}')
        lines.append(f'  password_exclude_username = {tf_value(safe_get(complexity, ["excludeUsername"]))}')
        lines.append(f'  password_expire_warn_days = {tf_value(safe_get(age, ["expireWarnDays"]))}')
        lines.append(f'  password_min_age_minutes = {tf_value(safe_get(age, ["minAgeMinutes"]))}')
        lines.append(f'  password_max_age_days = {tf_value(safe_get(age, ["maxAgeDays"]))}')
        lines.append(f'  password_max_lockout_attempts = {tf_value(safe_get(lockout, ["maxAttempts"]))}')
        lines.append(f'  password_auto_unlock_minutes = {tf_value(safe_get(lockout, ["autoUnlockMinutes"]))}')
        lines.append(f'  password_show_lockout_failures = {tf_value(safe_get(lockout, ["showLockoutFailures"]))}')
        token = safe_get(policy, ["settings", "recovery", "factors", "okta_email", "properties", "recoveryToken", "tokenLifetimeMinutes"])
        lines.append(f'  recovery_email_token = {tf_value(token)}')
    lines.append("}")
    return "\n".join(lines), resource_type, resource_name

def generate_rule_block(rule, parent_resource_type, parent_resource_name):
    """
    Generate the Terraform resource block for a password policy rule
    using okta_policy_rule_password.
    The parent's ID is referenced via interpolation.
    The resource name is in the format name_id.
    """
    base_name = normalize_name(rule.get("name", rule["id"]))
    normalized_id = rule["id"].replace("-", "_")
    resource_name = f"{base_name}_{normalized_id}"
    lines = [f'resource "okta_policy_rule_password" "{resource_name}" {{']
    lines.append(f'  name      = {tf_value(rule.get("name"), True)}')
    lines.append(f'  policy_id = {parent_resource_type}.{parent_resource_name}.id')
    lines.append(f'  priority  = {tf_value(rule.get("priority"))}')
    lines.append(f'  status    = {tf_value(rule.get("status"), True)}')
    net_conn = safe_get(rule, ["conditions", "network", "connection"])
    lines.append(f'  network_connection = {tf_value(net_conn, True)}')
    password_change = safe_get(rule, ["actions", "passwordChange", "access"])
    password_reset = safe_get(rule, ["actions", "selfServicePasswordReset", "access"])
    password_unlock = safe_get(rule, ["actions", "selfServiceUnlock", "access"])
    lines.append(f'  password_change = {tf_value(password_change, True)}')
    lines.append(f'  password_reset  = {tf_value(password_reset, True)}')
    lines.append(f'  password_unlock = {tf_value(password_unlock, True)}')
    users_excluded = safe_get(rule, ["conditions", "people", "users", "exclude"])
    if users_excluded and isinstance(users_excluded, list) and users_excluded:
        users_str = ", ".join([tf_value(u, True) for u in users_excluded])
        lines.append(f'  users_excluded = [{users_str}]')
    else:
        lines.append(f'  users_excluded = null')
    lines.append("}")
    return "\n".join(lines)

def generate_import_block(resource_type, resource_name, resource_id):
    """
    Generate an import block in the format:
    
    import {
      to = resource_type.resource_name
      id = "resource_id"
    }
    Uses the combined resource name (name_id).
    """
    lines = [
        "import {",
        f"  to = {resource_type}.{resource_name}",
        f"  id = {tf_value(resource_id, True)}",
        "}"
    ]
    return "\n".join(lines)

def generate_data_block_for_group(group_id):
    """
    Generate a data block for an Okta group lookup.
    For example:
    data "okta_group" "group_00gq12s54WHn2SW3o4x6" {
      id = "00gq12s54WHn2SW3o4x6"
    }
    """
    resource_name = f"group_{group_id}"
    lines = [
        f'data "okta_group" "{resource_name}" {{',
        f'  id = {tf_value(group_id, True)}',
        "}"
    ]
    return "\n".join(lines)

def run_terraform_fmt(file_path):
    """
    Run `terraform fmt` on the generated file to format the code.
    """
    try:
        subprocess.run(["terraform", "fmt", file_path], check=True)
        print(f"Formatted {file_path} successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error running 'terraform fmt': {e}")
    except FileNotFoundError:
        print("Terraform binary not found. Please install Terraform or disable the formatting flag.")

def main():
    parser = argparse.ArgumentParser(
        description="Generate Terraform config (with import blocks at the top, data lookups, and interpolation) from Okta PASSWORD policies and rules."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--full-domain",
        help="Your full Okta domain (e.g., 'andrewdoering.okta.com')."
    )
    group.add_argument(
        "--subdomain",
        help="Your Okta subdomain (e.g., 'andrewdoering'). Use with --domain."
    )
    parser.add_argument(
        "--domain",
        help="Your Okta domain (e.g., 'okta.com'). Required if --subdomain is provided."
    )
    parser.add_argument("--api-token", required=True, help="Okta API token (without the 'SSWS ' prefix)")
    parser.add_argument("--output", required=True, help="Output Terraform file path (e.g., './policy-password.tf')")
    parser.add_argument("--terraform-fmt", action="store_true", help="Run 'terraform fmt' on the output file after generation")
    args = parser.parse_args()

    if args.full_domain:
        if "." not in args.full_domain:
            print("Error: --full-domain must be in the format 'subdomain.domain' (e.g., andrewdoering.okta.com)")
            sys.exit(1)
        subdomain, domain = args.full_domain.split(".", 1)
    else:
        if not args.domain:
            print("Error: When using --subdomain, you must also provide --domain.")
            sys.exit(1)
        subdomain = args.subdomain
        domain = args.domain

    api_token = args.api_token

    try:
        policies = fetch_policies(subdomain, domain, api_token)
    except Exception as e:
        print("Error fetching policies:", e)
        sys.exit(1)

    global_group_ids = set()
    import_blocks = []
    resource_blocks = []

    for policy in policies:
        if policy.get("type") != "PASSWORD":
            continue
        policy_id = policy.get("id")
        policy_block, policy_resource_type, policy_resource_name = generate_policy_block(policy, global_group_ids)
        import_blocks.append(generate_import_block(policy_resource_type, policy_resource_name, policy_id))
        resource_blocks.append(policy_block)

        try:
            rules = fetch_policy_rules(subdomain, domain, api_token, policy_id)
        except Exception as e:
            print(f"Error fetching rules for policy {policy_id}: {e}")
            rules = []
        for rule in rules:
            rule_id = rule.get("id")
            rule_block = generate_rule_block(rule, policy_resource_type, policy_resource_name)
            # Create a combined name for the rule resource in the format name_id
            base_name = normalize_name(rule.get("name", rule_id))
            normalized_rule_id = rule_id.replace("-", "_")
            combined_rule_name = f"{base_name}_{normalized_rule_id}"
            import_blocks.append(generate_import_block("okta_policy_rule_password", combined_rule_name, rule_id))
            resource_blocks.append(rule_block)

    data_blocks = []
    for group_id in sorted(global_group_ids):
        data_blocks.append(generate_data_block_for_group(group_id))

    full_tf_config = "\n\n".join(data_blocks) + "\n\n" + "\n\n".join(import_blocks) + "\n\n" + "\n\n".join(resource_blocks)
    with open(args.output, "w") as f:
        f.write(full_tf_config)

    print(f"Terraform configuration generated and written to {args.output}")

    if args.terraform_fmt:
        run_terraform_fmt(args.output)

if __name__ == "__main__":
    main()