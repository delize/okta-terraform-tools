#!/usr/bin/env python3
import argparse
import json
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

def generate_rule_block(rule, env):
    """
    Generate a full Terraform configuration block for a rule,
    including most of the configurable options.
    """
    resource_name = f"rule_{env}_{rule['id']}"
    parent_policy_id = rule.get("policyId", "unknown")
    tf_block = f'resource "okta_policy_rule_signon" "{resource_name}" {{\n'
    tf_block += f'  name               = "{rule.get("name", "unnamed")}"\n'
    tf_block += f'  status             = "{rule.get("status", "ACTIVE")}"\n'
    # Access from actions.signon; default to "ALLOW"
    access = rule.get("actions", {}).get("signon", {}).get("access", "ALLOW")
    tf_block += f'  access             = "{access}"\n'
    # Authtype – default "ANY" if not provided
    authtype = rule.get("actions", {}).get("signon", {}).get("authtype", "ANY")
    tf_block += f'  authtype           = "{authtype}"\n'
    # Behaviors – expect a list; if empty, output an empty list.
    behaviors = rule.get("actions", {}).get("signon", {}).get("behaviors", [])
    if behaviors:
        behav_str = ", ".join([f'"{b}"' for b in behaviors])
        tf_block += f'  behaviors          = [{behav_str}]\n'
    else:
        tf_block += f'  behaviors          = []\n'
    # Network connection
    network_connection = rule.get("conditions", {}).get("network", {}).get("connection", "ANYWHERE")
    tf_block += f'  network_connection = "{network_connection}"\n'
    # Identity Provider
    identity_provider = rule.get("conditions", {}).get("identityProvider", {}).get("provider", "ANY")
    tf_block += f'  identity_provider  = "{identity_provider}"\n'
    # MFA settings (if available, otherwise defaults)
    mfa_lifetime = rule.get("actions", {}).get("signon", {}).get("mfa_lifetime", 120)
    tf_block += f'  mfa_lifetime       = {mfa_lifetime}\n'
    mfa_prompt = rule.get("actions", {}).get("signon", {}).get("mfa_prompt", "SESSION")
    tf_block += f'  mfa_prompt         = "{mfa_prompt}"\n'
    mfa_remember_device = rule.get("actions", {}).get("signon", {}).get("mfa_remember_device", False)
    tf_block += f'  mfa_remember_device= {str(mfa_remember_device).lower()}\n'
    mfa_required = rule.get("actions", {}).get("signon", {}).get("mfa_required", False)
    tf_block += f'  mfa_required       = {str(mfa_required).lower()}\n'
    # Primary factor; default as per example
    primary_factor = rule.get("actions", {}).get("signon", {}).get("primaryFactor", "PASSWORD_IDP_ANY_FACTOR")
    tf_block += f'  primary_factor     = "{primary_factor}"\n'
    # Priority (if provided)
    priority = rule.get("priority", 1)
    tf_block += f'  priority           = {priority}\n'
    # risc_level is deprecated; set to empty string as per instructions
    tf_block += f'  risc_level         = ""\n'
    # risk_level – from riskScore conditions, default to "ANY"
    risk_level = rule.get("conditions", {}).get("riskScore", {}).get("level", "ANY")
    tf_block += f'  risk_level         = "{risk_level}"\n'
    # Session parameters from actions.signon.session
    session_idle = rule.get("actions", {}).get("signon", {}).get("session", {}).get("maxSessionIdleMinutes", 120)
    tf_block += f'  session_idle       = {session_idle}\n'
    session_lifetime = rule.get("actions", {}).get("signon", {}).get("session", {}).get("maxSessionLifetimeMinutes", 120)
    tf_block += f'  session_lifetime   = {session_lifetime}\n'
    session_persistent = rule.get("actions", {}).get("signon", {}).get("session", {}).get("usePersistentCookie", False)
    tf_block += f'  session_persistent = {str(session_persistent).lower()}\n'
    # Reference the parent policy resource
    tf_block += f'  policy_id          = okta_policy_signon.policy_{env}_{parent_policy_id}.id\n'
    tf_block += "}\n\n"
    # Terraform import block for the rule resource.
    tf_block += "import {\n"
    tf_block += f'  for_each = var.CONFIG == "{env}" ? toset(["{env}"]) : []\n'
    tf_block += f'  to       = okta_policy_rule_signon.{resource_name}[0]\n'
    tf_block += f'  id       = "{rule["id"]}"\n'
    tf_block += "}\n\n"
    return tf_block

def generate_terraform_config(prod_policies, preview_policies, prod_rules, preview_rules):
    """
    Generate the Terraform configuration string for policies and rules,
    including embedded import blocks.
    """
    tf_config = ""

    # Terraform variable to control environment configuration.
    tf_config += (
        'variable "CONFIG" {\n'
        '  description = "Environment configuration: prod or preview"\n'
        '  type        = string\n'
        '}\n\n'
    )

    # --- Production Policies ---
    for policy in prod_policies:
        resource_name = f"policy_prod_{policy['id']}"
        tf_config += f'resource "okta_policy_signon" "{resource_name}" {{\n'
        tf_config += f'  name            = "{policy.get("name", "unnamed")}"\n'
        tf_config += f'  status          = "{policy.get("status", "ACTIVE")}"\n'
        if policy.get("description"):
            tf_config += f'  description     = "{policy.get("description")}"\n'
        groups = policy.get("conditions", {}).get("people", {}).get("groups", {}).get("include", [])
        if groups:
            # Using interpolation so that the group ID is dynamically retrieved.
            tf_config += f'  groups_included = [${{data.okta_group.example.id}}]\n'
        tf_config += f'  priority        = {policy.get("priority", 1)}\n'
        tf_config += "}\n\n"

        tf_config += "import {\n"
        tf_config += '  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []\n'
        tf_config += f'  to       = okta_policy_signon.{resource_name}\n'
        tf_config += f'  id       = "{policy["id"]}"\n'
        tf_config += "}\n\n"

    # --- Production Policy Rules ---
    for rule in prod_rules:
        tf_config += generate_rule_block(rule, "prod")

    # --- Preview Policies ---
    for policy in preview_policies:
        resource_name = f"policy_preview_{policy['id']}"
        tf_config += f'resource "okta_policy_signon" "{resource_name}" {{\n'
        tf_config += f'  name            = "{policy.get("name", "unnamed")}"\n'
        tf_config += f'  status          = "{policy.get("status", "ACTIVE")}"\n'
        if policy.get("description"):
            tf_config += f'  description     = "{policy.get("description")}"\n'
        groups = policy.get("conditions", {}).get("people", {}).get("groups", {}).get("include", [])
        if groups:
            tf_config += f'  groups_included = [${{data.okta_group.example.id}}]\n'
        tf_config += f'  priority        = {policy.get("priority", 1)}\n'
        tf_config += "}\n\n"

        tf_config += "import {\n"
        tf_config += '  for_each = var.CONFIG == "preview" ? toset(["preview"]) : []\n'
        tf_config += f'  to       = okta_policy_signon.{resource_name}\n'
        tf_config += f'  id       = "{policy["id"]}"\n'
        tf_config += "}\n\n"

    # --- Preview Policy Rules ---
    for rule in preview_rules:
        tf_config += generate_rule_block(rule, "preview")

    return tf_config

def main():
    parser = argparse.ArgumentParser(
        description="Query Okta Global Session Policies and generate a Terraform configuration file."
    )
    # Optional arguments with default values for development.
    parser.add_argument("--preview-subdomain", help="Preview subdomain", default="preview")
    parser.add_argument("--prod-subdomain", help="Production subdomain", default="prod")
    parser.add_argument("--preview-domain-flag", help="Preview domain flag (e.g., preview)", default="preview")
    parser.add_argument("--prod-domain-flag", help="Production domain flag (e.g., default)", default="default")
    parser.add_argument("--preview-full-url", help="Preview full URL for Okta API (e.g., https://your-preview-domain)", default="")
    parser.add_argument("--prod-full-url", help="Production full URL for Okta API (e.g., https://your-prod-domain)", default="")
    parser.add_argument("--preview-api-token", help="Preview API token", default="")
    parser.add_argument("--prod-api-token", help="Production API token", default="")
    parser.add_argument("--output-file", help="Output Terraform file", default="output.tf")
    parser.add_argument("--run-terraform-fmt", action="store_true", help="Run 'terraform fmt' on the generated file")
    args = parser.parse_args()

    prod_policies = []
    prod_rules = []
    preview_policies = []
    preview_rules = []

    # --- Fetch Production Data Only If a Valid URL and API Token Provided ---
    if args.prod_full_url and args.prod_api_token:
        prod_base_url = args.prod_full_url  # Or use: get_okta_domain(args.prod_subdomain, args.prod_domain_flag)
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

    # --- Fetch Preview Data Only If a Valid URL and API Token Provided ---
    if args.preview_full_url and args.preview_api_token:
        preview_base_url = args.preview_full_url  # Or use: get_okta_domain(args.preview_subdomain, args.preview_domain_flag)
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

    # --- Generate Terraform Configuration ---
    print("Generating Terraform configuration...")
    tf_config = generate_terraform_config(prod_policies, preview_policies, prod_rules, preview_rules)

    # Write the Terraform configuration to the output file.
    output_path = Path(args.output_file)
    output_path.write_text(tf_config)
    print(f"Terraform configuration written to {args.output_file}")

    # Optionally run terraform fmt on the generated file.
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