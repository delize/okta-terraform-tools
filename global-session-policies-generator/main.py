#!/usr/bin/env python3
import argparse
import json
import re
import requests
import subprocess
import shutil
from pathlib import Path

def get_okta_domain(subdomain, domain_flag):
    """
    Build the Okta domain URL using a subdomain and domain_flag.
    """
    domain_map = {
        "default": "okta.com",
        "emea": "okta-emea.com",
        "preview": "oktapreview.com",
        "gov": "okta-gov.com",
        "mil": "okta.mil"
    }
    domain = domain_map.get(domain_flag, "okta.com")
    return f"{subdomain}.{domain}"

def fetch_policies(base_url, api_token):
    """
    Retrieve all OKTA_SIGN_ON policies from the given base URL.
    """
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json"
    }
    url = f"{base_url}/api/v1/policies?type=OKTA_SIGN_ON"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def fetch_policy_rules(base_url, api_token, policy_id):
    """
    Retrieve all rules for a specific policy.
    """
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json"
    }
    url = f"{base_url}/api/v1/policies/{policy_id}/rules"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def fetch_group_detail(base_url, api_token, group_id):
    """
    Retrieve group details for a given group_id.
    Returns the group's display name from profile.name.
    """
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json"
    }
    url = f"{base_url}/api/v1/groups/{group_id}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()
    return data.get("profile", {}).get("name", group_id)

def normalize_group_name(group_name):
    """
    Normalize a group name into a Terraform-friendly identifier.
    Example: "# automation" becomes "automation" (all lowercase, underscores)
    """
    normalized = re.sub(r'^#+', '', group_name).strip()
    normalized = re.sub(r'[\s-]+', '_', normalized)
    normalized = normalized.lower()
    normalized = re.sub(r'[^a-z0-9_]', '', normalized)
    return normalized

def generate_rule_block(rule, env_prefix):
    """
    Generate a full Terraform configuration block for a rule,
    including most of the configurable options and the count attribute.
    The env_prefix (e.g. "prod" or "test") is used to reference the parent policy.
    """
    resource_name = f"rule_{env_prefix}_{rule['id']}"
    parent_policy_id = rule.get("policyId", "unknown")
    tf_block = f'resource "okta_policy_rule_signon" "{resource_name}" {{\n'
    tf_block += f'  count = var.CONFIG == "{env_prefix}" ? 1 : 0\n'
    tf_block += f'  name               = "{rule.get("name", "unnamed")}"\n'
    tf_block += f'  status             = "{rule.get("status", "ACTIVE")}"\n'
    access = rule.get("actions", {}).get("signon", {}).get("access", "ALLOW")
    tf_block += f'  access             = "{access}"\n'
    authtype = rule.get("actions", {}).get("signon", {}).get("authtype", "ANY")
    tf_block += f'  authtype           = "{authtype}"\n'
    behaviors = rule.get("actions", {}).get("signon", {}).get("behaviors", [])
    if behaviors:
        behav_str = ", ".join([f'"{b}"' for b in behaviors])
        tf_block += f'  behaviors          = [{behav_str}]\n'
    else:
        tf_block += f'  behaviors          = []\n'
    network_connection = rule.get("conditions", {}).get("network", {}).get("connection", "ANYWHERE")
    tf_block += f'  network_connection = "{network_connection}"\n'
    identity_provider = rule.get("conditions", {}).get("identityProvider", {}).get("provider", "ANY")
    tf_block += f'  identity_provider  = "{identity_provider}"\n'
    mfa_lifetime = rule.get("actions", {}).get("signon", {}).get("mfa_lifetime", 120)
    tf_block += f'  mfa_lifetime       = {mfa_lifetime}\n'
    mfa_prompt = rule.get("actions", {}).get("signon", {}).get("mfa_prompt", "SESSION")
    tf_block += f'  mfa_prompt         = "{mfa_prompt}"\n'
    mfa_remember_device = rule.get("actions", {}).get("signon", {}).get("mfa_remember_device", False)
    tf_block += f'  mfa_remember_device = {str(mfa_remember_device).lower()}\n'
    mfa_required = rule.get("actions", {}).get("signon", {}).get("mfa_required", False)
    tf_block += f'  mfa_required       = {str(mfa_required).lower()}\n'
    primary_factor = rule.get("actions", {}).get("signon", {}).get("primaryFactor", "PASSWORD_IDP_ANY_FACTOR")
    tf_block += f'  primary_factor     = "{primary_factor}"\n'
    priority = rule.get("priority", 1)
    tf_block += f'  priority           = {priority}\n'
    tf_block += f'  risc_level         = ""\n'
    risk_level = rule.get("conditions", {}).get("riskScore", {}).get("level", "ANY")
    tf_block += f'  risk_level         = "{risk_level}"\n'
    session_idle = rule.get("actions", {}).get("signon", {}).get("session", {}).get("maxSessionIdleMinutes", 120)
    tf_block += f'  session_idle       = {session_idle}\n'
    session_lifetime = rule.get("actions", {}).get("signon", {}).get("session", {}).get("maxSessionLifetimeMinutes", 120)
    tf_block += f'  session_lifetime   = {session_lifetime}\n'
    session_persistent = rule.get("actions", {}).get("signon", {}).get("session", {}).get("usePersistentCookie", False)
    tf_block += f'  session_persistent = {str(session_persistent).lower()}\n'
    tf_block += f'  policy_id          = okta_policy_signon.policy_{env_prefix}_{parent_policy_id}[0].id\n'
    tf_block += "}\n\n"
    tf_block += "import {\n"
    tf_block += f'  for_each = var.CONFIG == "{env_prefix}" ? toset(["{env_prefix}"]) : []\n'
    tf_block += f'  to       = okta_policy_rule_signon.{resource_name}[0]\n'
    tf_block += f'  id       = "{rule["policyId"]}/{rule["id"]}"\n'
    tf_block += "}\n\n"
    return tf_block

def generate_terraform_config(prod_policies, preview_policies, prod_rules, preview_rules, prod_group_map, preview_group_map, prod_env, preview_env):
    """
    Generate the Terraform configuration string for policies, rules,
    and data blocks for groups, with conditional creation using count.
    The prod_env and preview_env values (e.g. "prod" and "test") determine the resource name prefixes.
    """
    tf_config = ""
    tf_config += (
        'variable "CONFIG" {\n'
        '  description = "Environment configuration: prod, test, preview, etc."\n'
        '  type        = string\n'
        '}\n\n'
    )

    # --- Generate Data Blocks for Production Groups ---
    for group in prod_group_map.values():
        tf_config += f'data "okta_group" "{prod_env}_{group["normalized"]}" {{\n'
        tf_config += f'  name = "{group["name"]}"\n'
        tf_config += "}\n\n"

    # --- Generate Data Blocks for Preview Groups ---
    for group in preview_group_map.values():
        tf_config += f'data "okta_group" "{preview_env}_{group["normalized"]}" {{\n'
        tf_config += f'  name = "{group["name"]}"\n'
        tf_config += "}\n\n"

    # --- Production Policies ---
    for policy in prod_policies:
        resource_name = f"policy_{prod_env}_{policy['id']}"
        tf_config += f'resource "okta_policy_signon" "{resource_name}" {{\n'
        tf_config += f'  count = var.CONFIG == "{prod_env}" ? 1 : 0\n'
        tf_config += f'  name            = "{policy.get("name", "unnamed")}"\n'
        tf_config += f'  status          = "{policy.get("status", "ACTIVE")}"\n'
        if policy.get("description"):
            tf_config += f'  description     = "{policy.get("description")}"\n'
        groups = policy.get("conditions", {}).get("people", {}).get("groups", {}).get("include", [])
        if groups:
            group_refs = []
            for gid in groups:
                if gid in prod_group_map:
                    group_refs.append(f"data.okta_group.{prod_env}_{prod_group_map[gid]['normalized']}.id")
                else:
                    group_refs.append(f'"{gid}"')
            tf_config += f'  groups_included = [{", ".join(group_refs)}]\n'
        tf_config += f'  priority        = {policy.get("priority", 1)}\n'
        tf_config += "}\n\n"
        tf_config += "import {\n"
        tf_config += f'  for_each = var.CONFIG == "{prod_env}" ? toset(["{prod_env}"]) : []\n'
        tf_config += f'  to       = okta_policy_signon.{resource_name}[0]\n'
        tf_config += f'  id       = "{policy["id"]}"\n'
        tf_config += "}\n\n"

    # --- Production Policy Rules ---
    for rule in prod_rules:
        tf_config += generate_rule_block(rule, prod_env)

    # --- Preview Policies ---
    for policy in preview_policies:
        resource_name = f"policy_{preview_env}_{policy['id']}"
        tf_config += f'resource "okta_policy_signon" "{resource_name}" {{\n'
        tf_config += f'  count = var.CONFIG == "{preview_env}" ? 1 : 0\n'
        tf_config += f'  name            = "{policy.get("name", "unnamed")}"\n'
        tf_config += f'  status          = "{policy.get("status", "ACTIVE")}"\n'
        if policy.get("description"):
            tf_config += f'  description     = "{policy.get("description")}"\n'
        groups = policy.get("conditions", {}).get("people", {}).get("groups", {}).get("include", [])
        if groups:
            group_refs = []
            for gid in groups:
                if gid in preview_group_map:
                    group_refs.append(f"data.okta_group.{preview_env}_{preview_group_map[gid]['normalized']}.id")
                else:
                    group_refs.append(f'"{gid}"')
            tf_config += f'  groups_included = [{", ".join(group_refs)}]\n'
        tf_config += f'  priority        = {policy.get("priority", 1)}\n'
        tf_config += "}\n\n"
        tf_config += "import {\n"
        tf_config += f'  for_each = var.CONFIG == "{preview_env}" ? toset(["{preview_env}"]) : []\n'
        tf_config += f'  to       = okta_policy_signon.{resource_name}[0]\n'
        tf_config += f'  id       = "{policy["id"]}"\n'
        tf_config += "}\n\n"

    # --- Preview Policy Rules ---
    for rule in preview_rules:
        tf_config += generate_rule_block(rule, preview_env)

    return tf_config

def main():
    parser = argparse.ArgumentParser(
        description="Query Okta Global Session Policies and generate a Terraform configuration file."
    )
    parser.add_argument("--preview-subdomain", help="Preview subdomain", default="preview")
    parser.add_argument("--prod-subdomain", help="Production subdomain", default="prod")
    parser.add_argument("--preview-domain-flag", help="Preview domain flag (e.g., preview)", default="preview")
    parser.add_argument("--prod-domain-flag", help="Production domain flag (e.g., default)", default="default")
    parser.add_argument("--preview-full-url", help="Preview full URL for Okta API", default="")
    parser.add_argument("--prod-full-url", help="Production full URL for Okta API", default="")
    parser.add_argument("--preview-api-token", help="Preview API token", default="")
    parser.add_argument("--prod-api-token", help="Production API token", default="")
    parser.add_argument("--prod-env", help="Environment prefix for production resources (e.g., prod)", default="prod")
    parser.add_argument("--preview-env", help="Environment prefix for preview resources (e.g., test)", default="preview")
    parser.add_argument("--output-file", help="Output Terraform file", default="output.tf")
    parser.add_argument("--run-terraform-fmt", action="store_true", help="Run 'terraform fmt' on the generated file")
    args = parser.parse_args()

    prod_policies = []
    prod_rules = []
    preview_policies = []
    preview_rules = []

    # Fetch Production Policies and Rules
    if args.prod_full_url and args.prod_api_token:
        prod_base_url = args.prod_full_url
        print("Fetching production policies...")
        try:
            prod_policies = fetch_policies(prod_base_url, args.prod_api_token)
            for policy in prod_policies:
                rules = fetch_policy_rules(prod_base_url, args.prod_api_token, policy["id"])
                for rule in rules:
                    rule["policyId"] = policy["id"]
                    prod_rules.append(rule)
        except Exception as e:
            print(f"Error fetching production data: {e}")
    else:
        print("Skipping production data fetch; no valid prod-full-url or prod-api-token provided.")

    # Fetch Preview Policies and Rules
    if args.preview_full_url and args.preview_api_token:
        preview_base_url = args.preview_full_url
        print("Fetching preview policies...")
        try:
            preview_policies = fetch_policies(preview_base_url, args.preview_api_token)
            for policy in preview_policies:
                rules = fetch_policy_rules(preview_base_url, args.preview_api_token, policy["id"])
                for rule in rules:
                    rule["policyId"] = policy["id"]
                    preview_rules.append(rule)
        except Exception as e:
            print(f"Error fetching preview data: {e}")
    else:
        print("Skipping preview data fetch; no valid preview-full-url or preview-api-token provided.")

    # Build set of policy IDs for filtering rules
    prod_policy_ids = {policy["id"] for policy in prod_policies}
    preview_policy_ids = {policy["id"] for policy in preview_policies}
    filtered_prod_rules = [rule for rule in prod_rules if rule["policyId"] in prod_policy_ids]
    filtered_preview_rules = [rule for rule in preview_rules if rule["policyId"] in preview_policy_ids]

    # Collect group IDs separately for prod and preview.
    prod_group_ids = set()
    for policy in prod_policies:
        groups = policy.get("conditions", {}).get("people", {}).get("groups", {}).get("include", [])
        for gid in groups:
            prod_group_ids.add(gid)
    preview_group_ids = set()
    for policy in preview_policies:
        groups = policy.get("conditions", {}).get("people", {}).get("groups", {}).get("include", [])
        for gid in groups:
            preview_group_ids.add(gid)

    # Build separate group maps.
    prod_group_map = {}
    preview_group_map = {}
    if args.prod_full_url and args.prod_api_token:
        for gid in prod_group_ids:
            try:
                group_name = fetch_group_detail(args.prod_full_url, args.prod_api_token, gid)
                normalized = normalize_group_name(group_name)
                prod_group_map[gid] = {"name": group_name, "normalized": normalized}
            except Exception as e:
                print(f"Error fetching details for production group {gid}: {e}")
                normalized = normalize_group_name(gid)
                prod_group_map[gid] = {"name": gid, "normalized": normalized}
    if args.preview_full_url and args.preview_api_token:
        for gid in preview_group_ids:
            try:
                group_name = fetch_group_detail(args.preview_full_url, args.preview_api_token, gid)
                normalized = normalize_group_name(group_name)
                preview_group_map[gid] = {"name": group_name, "normalized": normalized}
            except Exception as e:
                print(f"Error fetching details for preview group {gid}: {e}")
                normalized = normalize_group_name(gid)
                preview_group_map[gid] = {"name": gid, "normalized": normalized}

    print("Generating Terraform configuration...")
    tf_config = generate_terraform_config(
        prod_policies, preview_policies, filtered_prod_rules, filtered_preview_rules,
        prod_group_map, preview_group_map, args.prod_env, args.preview_env
    )
    output_path = Path(args.output_file)
    output_path.write_text(tf_config)
    print(f"Terraform configuration written to {args.output_file}")

    if args.run_terraform_fmt:
        print("Attempting to run 'terraform fmt'...")
        terraform_path = shutil.which("terraform")
        if terraform_path:
            try:
                subprocess.run([terraform_path, "fmt", args.output_file], check=True)
                print("terraform fmt executed successfully.")
            except subprocess.CalledProcessError as e:
                print(f"Error running terraform fmt: {e}")
        else:
            print("Terraform executable not found in PATH; skipping terraform fmt.")

if __name__ == "__main__":
    main()