#!/usr/bin/env python3
import argparse
import json
import subprocess
import requests
import sys
import re

def normalize_name(name):
    """
    Normalize a string for use in a Terraform resource name:
    - Convert to lowercase.
    - Replace any non-alphanumeric character with an underscore.
    - Collapse multiple underscores into one.
    - Strip leading/trailing underscores.
    """
    name = name.lower()
    name = re.sub(r'[^a-z0-9]', '_', name)
    name = re.sub(r'_+', '_', name)
    return name.strip('_')

def construct_okta_domain(subdomain, domain, full_domain):
    """
    Determine the Okta domain based on inputs.
    If a full domain is provided and it starts with http:// or https://, remove the protocol.
    """
    if full_domain:
        if full_domain.startswith("https://"):
            full_domain = full_domain[len("https://"):]
        elif full_domain.startswith("http://"):
            full_domain = full_domain[len("http://"):]
        return full_domain
    elif subdomain and domain:
        return f"{subdomain}.{domain}"
    else:
        raise ValueError("Either --full-domain or both --subdomain and --domain must be provided.")

def fetch_org_info(okta_domain):
    """
    Fetch organization information from the Okta well-known endpoint.
    Example URL: https://{yourOktaDomain}/.well-known/okta-organization
    """
    url = f"https://{okta_domain}/.well-known/okta-organization"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as err:
        print(f"Failed to fetch organization info: {err}")
        return {}

def fetch_policies(okta_domain, api_token):
    """
    Fetch MFA_ENROLL policies from the Okta API.
    Uses the provided API token in the request header.
    """
    url = f"https://{okta_domain}/api/v1/policies"
    params = {"type": "MFA_ENROLL"}
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()

def fetch_rules(okta_domain, policy_id, api_token):
    """
    Fetch rules for a given policy from the Okta API.
    """
    url = f"https://{okta_domain}/api/v1/policies/{policy_id}/rules"
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }
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

def generate_terraform_from_policy(policy, is_oie_flag, global_groups):
    """
    Generate a Terraform resource block from a single policy.
    
    - For non-default policies (system is false), generate an okta_policy_mfa resource.
    - For default policies (system is true), generate an okta_policy_mfa_default resource.
    
    Returns a tuple:
      (resource_block, resource_type, resource_name, resource_id)
    """
    is_default = policy.get("system", False)
    priority = policy.get("priority")
    priority_str = str(priority) if priority is not None else "null"
    policy_id = policy.get("id", "")
    
    # Use the normalized policy name plus the normalized ID to form resource_name (name_id)
    name = policy.get("name", "default_policy")
    norm_name = normalize_name(name)
    norm_id = policy_id.replace("-", "_")
    resource_name = f"{norm_name}_{norm_id}"
    
    if not is_default:
        description = policy.get("description", "")
        status = policy.get("status", "ACTIVE")
        groups = policy.get("conditions", {}).get("people", {}).get("groups", {}).get("include", [])
        if groups and isinstance(groups, list):
            global_groups.update(groups)
            groups_str = "[" + ", ".join(f"data.okta_group.group_{g}.id" for g in groups) + "]"
        else:
            groups_str = "null"
        
        terraform_settings = ""
        settings = policy.get("settings", {})
        if "authenticators" in settings:
            for auth in settings["authenticators"]:
                key = auth.get("key")
                enroll = auth.get("enroll", {}).get("self")
                terraform_settings += f'  {key} = {{\n    enroll = "{enroll}"\n  }}\n'
        elif "factors" in settings:
            for factor, details in settings["factors"].items():
                enroll = details.get("enroll", {}).get("self")
                terraform_settings += f'  {factor} = {{\n    enroll = "{enroll}"\n  }}\n'
        
        resource_block = f'''resource "okta_policy_mfa" "{resource_name}" {{
  name            = "{name}"
  description     = "{description}"
  status          = "{status}"
  priority        = {priority_str}
  is_oie          = {str(is_oie_flag).lower()}
  groups_included = {groups_str}
{terraform_settings}}}'''
        resource_type = "okta_policy_mfa"
    else:
        settings = policy.get("settings", {})
        terraform_settings = ""
        if "authenticators" in settings:
            for auth in settings["authenticators"]:
                key = auth.get("key")
                enroll = auth.get("enroll", {}).get("self")
                terraform_settings += f'  {key} = {{\n    enroll = "{enroll}"\n  }}\n'
        elif "factors" in settings:
            for factor, details in settings["factors"].items():
                enroll = details.get("enroll", {}).get("self")
                terraform_settings += f'  {factor} = {{\n    enroll = "{enroll}"\n  }}\n'
        
        resource_block = f'''resource "okta_policy_mfa_default" "{resource_name}" {{
  is_oie = {str(is_oie_flag).lower()}
{terraform_settings}}}'''
        resource_type = "okta_policy_mfa_default"
    
    return resource_block, resource_type, resource_name, policy_id

def generate_terraform_from_rule(rule, policy_id, policy_resource_name, policy_resource_type, is_oie_flag):
    """
    Generate a Terraform resource block for a rule.
    
    For OIE organizations, generate an okta_policy_rule_mfa resource using the new schema.
    For Classic organizations, generate an okta_policy_mfa_rule resource using inline JSON.
    
    Adds a depends_on statement so the rule depends on its parent policy.
    
    Returns a tuple:
      (resource_block, resource_type, resource_name, rule_id)
    """
    rule_id = rule.get("id", "")
    # Create a combined resource name using normalized rule name and rule ID
    rule_name = rule.get("name", "unnamed_rule")
    norm_rule = normalize_name(rule_name)
    norm_rule_id = rule_id.replace("-", "_")
    rule_resource_name_final = f"{norm_rule}_{norm_rule_id}"
    
    depends_line = f'  depends_on = [ {policy_resource_type}.{policy_resource_name} ]'
    
    if is_oie_flag:
        enroll = rule.get("actions", {}).get("enroll", {}).get("self", "null")
        network_conn = rule.get("conditions", {}).get("network", {}).get("connection", "ANYWHERE")
        network_excludes = rule.get("conditions", {}).get("network", {}).get("excludes")
        network_includes = rule.get("conditions", {}).get("network", {}).get("includes")
        network_excludes_str = f'jsonencode({json.dumps(network_excludes)})' if network_excludes else "null"
        network_includes_str = f'jsonencode({json.dumps(network_includes)})' if network_includes else "null"
        priority = rule.get("priority")
        priority_str = str(priority) if priority is not None else "null"
        status = rule.get("status", "ACTIVE")
        users_excluded = rule.get("conditions", {}).get("people", {}).get("users", {}).get("exclude", [])
        users_excluded_str = f'jsonencode({json.dumps(users_excluded)})' if users_excluded else "null"
        rule_policy_id = f"{policy_resource_type}.{policy_resource_name}.id"
        resource_block = f'''resource "okta_policy_rule_mfa" "{rule_resource_name_final}" {{
  policy_id = {rule_policy_id}
  name      = "{rule_name}"
  enroll    = "{enroll}"
  network_connection = "{network_conn}"
  network_excludes   = {network_excludes_str}
  network_includes   = {network_includes_str}
  priority  = {priority_str}
  status    = "{status}"
  users_excluded = {users_excluded_str}
{depends_line}
}}'''
        resource_type = "okta_policy_rule_mfa"
    else:
        status = rule.get("status", "ACTIVE")
        priority = rule.get("priority")
        priority_str = str(priority) if priority is not None else "null"
        conditions = rule.get("conditions", {})
        actions = rule.get("actions", {})
        conditions_str = f'jsonencode({json.dumps(conditions)})' if conditions else "null"
        actions_str = f'jsonencode({json.dumps(actions)})' if actions else "null"
        resource_block = f'''resource "okta_policy_mfa_rule" "{rule_resource_name_final}" {{
  policy_id = "{policy_id}"
  name      = "{rule_name}"
  status    = "{status}"
  priority  = {priority_str}
  conditions = {conditions_str}
  actions    = {actions_str}
{depends_line}
}}'''
        resource_type = "okta_policy_mfa_rule"
    
    return resource_block, resource_type, rule_resource_name_final, rule_id

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
        f'  id = "{group_id}"',
        "}"
    ]
    return "\n".join(lines)

def generate_terraform_file(policies, okta_domain, api_token, is_oie_flag):
    """
    Generate the complete Terraform configuration content.
    For each policy and its rules, collect the resource blocks and structured import info.
    Prepend an import section in HCL syntax at the top.
    """
    resource_blocks = []
    import_blocks = []
    global_group_ids = set()
    
    for policy in policies:
        if policy.get("type") != "MFA_ENROLL":
            continue
        pol_block, pol_type, pol_name, pol_id = generate_terraform_from_policy(policy, is_oie_flag, global_group_ids)
        resource_blocks.append(pol_block)
        # Generate the import block for the policy:
        import_blocks.append(f'''import {{
  to = {pol_type}.{pol_name}
  id = "{pol_id}"
}}''')
        
        try:
            rules = fetch_rules(okta_domain, pol_id, api_token)
        except requests.RequestException as err:
            print(f"Failed to fetch rules for policy {pol_id}: {err}")
            continue
        
        for rule in rules:
            rule_block, rule_type, rule_name, rule_id = generate_terraform_from_rule(rule, pol_id, pol_name, pol_type, is_oie_flag)
            resource_blocks.append(rule_block)
            import_blocks.append(f'''import {{
  to = {rule_type}.{rule_name}
  id = "{pol_id}/{rule_id}"
}}''')
    
    import_section = "\n\n".join(import_blocks)
    resources_section = "\n\n".join(resource_blocks)
    # Generate data blocks for groups.
    data_blocks = []
    for group_id in sorted(global_group_ids):
        data_blocks.append(generate_data_block_for_group(group_id))
    data_section = "\n\n".join(data_blocks)
    
    full_content = data_section + "\n\n" + import_section + "\n\n\n" + resources_section
    return full_content

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
        description="Generate Terraform code for Okta MFA policies and rules from the Okta API."
    )
    parser.add_argument("--subdomain", help="Subdomain for the Okta domain")
    parser.add_argument("--domain", help="Domain for the Okta domain")
    parser.add_argument("--full-domain", help="Full domain for the Okta domain (without protocol)")
    parser.add_argument("--api-token", help="Okta API token (used only for fetching policies and rules)", required=True)
    parser.add_argument("--output", help="Output file name for the Terraform configuration", default="main.tf")
    parser.add_argument("--terraform-fmt", action="store_true", help="Run 'terraform fmt' on the generated file")
    
    args = parser.parse_args()
    
    try:
        okta_domain = construct_okta_domain(args.subdomain, args.domain, args.full_domain)
    except ValueError as err:
        print(f"Error: {err}")
        sys.exit(1)
    
    # Fetch organization info to determine if the pipeline is idx (OIE)
    org_info = fetch_org_info(okta_domain)
    pipeline = org_info.get("pipeline", "").lower()
    is_oie_flag = (pipeline == "idx")
    print(f"Organization pipeline: {pipeline} -> is_oie set to {is_oie_flag}")
    
    try:
        policies = fetch_policies(okta_domain, args.api_token)
    except requests.RequestException as err:
        print(f"Failed to fetch policies: {err}")
        sys.exit(1)
    
    terraform_code = generate_terraform_file(policies, okta_domain, args.api_token, is_oie_flag)
    
    with open(args.output, "w") as f:
        f.write(terraform_code)
    print(f"Terraform configuration written to {args.output}")
    
    if args.terraform_fmt:
        run_terraform_fmt(args.output)

if __name__ == "__main__":
    main()