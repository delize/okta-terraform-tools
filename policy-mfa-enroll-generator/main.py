import argparse
import json
import subprocess
import requests
import sys

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

def generate_terraform_from_policy(policy, is_oie_flag):
    """
    Generate a Terraform resource block from a single policy.
    
    - For non-default policies (system is false), generate an okta_policy_mfa resource
      including the name, description, status, priority, groups_included and factor/authenticator settings.
    - For default policies (system is true), generate an okta_policy_mfa_default resource.
    
    The API’s provided priority is used directly (or null if missing).
    """
    is_default = policy.get("system", False)
    priority = policy.get("priority")
    priority_str = str(priority) if priority is not None else "null"
    
    if not is_default:
        name = policy.get("name", "Unnamed_Policy")
        description = policy.get("description", "")
        status = policy.get("status", "ACTIVE")
        groups = policy.get("conditions", {}).get("people", {}).get("groups", {}).get("include", [])
        groups_str = "[" + ", ".join(f'"{g}"' for g in groups) + "]"
        
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
        
        resource_name = name.replace(" ", "_").lower()
        resource_block = f'''resource "okta_policy_mfa" "{resource_name}" {{
  name            = "{name}"
  description     = "{description}"
  status          = "{status}"
  priority        = {priority_str}
  is_oie          = {str(is_oie_flag).lower()}
  groups_included = {groups_str}
{terraform_settings}}}'''
        return resource_block, resource_name, policy.get("id", "")
    else:
        # For default policies, use the okta_policy_mfa_default resource.
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
        
        resource_name = policy.get("name", "default_policy").replace(" ", "_").lower()
        resource_block = f'''resource "okta_policy_mfa_default" "{resource_name}" {{
  is_oie = {str(is_oie_flag).lower()}
{terraform_settings}}}'''
        return resource_block, resource_name, policy.get("id", "")

def generate_terraform_from_rule(rule, policy_id, policy_resource_name, is_oie_flag):
    """
    Generate a Terraform resource block for a rule.
    
    For OIE (idx) organizations, generate an okta_policy_rule_mfa resource using the new schema:
      - Required fields: name, enroll, network_connection, policy_id, priority, status, users_excluded.
      - Optionally, network_excludes and network_includes are output via jsonencode() if present.
    
    For Classic organizations, fallback to generating an okta_policy_mfa_rule resource that
    outputs inline JSON for conditions and actions.
    """
    if is_oie_flag:
        rule_name = rule.get("name", "unnamed_rule")
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
        
        rule_resource_name_final = f"{policy_resource_name}_{rule_name.replace(' ', '_').lower()}"
        resource_block = f'''resource "okta_policy_rule_mfa" "{rule_resource_name_final}" {{
  policy_id = "{policy_id}"
  name      = "{rule_name}"
  enroll    = "{enroll}"
  network_connection = "{network_conn}"
  network_excludes   = {network_excludes_str}
  network_includes   = {network_includes_str}
  priority  = {priority_str}
  status    = "{status}"
  users_excluded = {users_excluded_str}
}}'''
        return resource_block
    else:
        rule_name = rule.get("name", "unnamed_rule")
        status = rule.get("status", "ACTIVE")
        priority = rule.get("priority")
        priority_str = str(priority) if priority is not None else "null"
        conditions = rule.get("conditions", {})
        actions = rule.get("actions", {})
        conditions_str = f'jsonencode({json.dumps(conditions)})' if conditions else "null"
        actions_str = f'jsonencode({json.dumps(actions)})' if actions else "null"
        rule_resource_name_final = f"{policy_resource_name}_{rule_name.replace(' ', '_').lower()}"
        resource_block = f'''resource "okta_policy_mfa_rule" "{rule_resource_name_final}" {{
  policy_id = "{policy_id}"
  name      = "{rule_name}"
  status    = "{status}"
  priority  = {priority_str}
  conditions = {conditions_str}
  actions    = {actions_str}
}}'''
        return resource_block

def generate_terraform_file(policies, okta_domain, api_token, is_oie_flag):
    """
    Generate the complete Terraform configuration content.
    
    For each policy, generate its resource block.
    Then fetch and generate the associated rule resource blocks regardless of whether the policy is default.
    """
    blocks = []
    for policy in policies:
        policy_block, policy_resource_name, policy_id = generate_terraform_from_policy(policy, is_oie_flag)
        blocks.append(policy_block)
        try:
            rules = fetch_rules(okta_domain, policy_id, api_token)
        except requests.RequestException as err:
            print(f"Failed to fetch rules for policy {policy_id}: {err}")
            continue
        for rule in rules:
            rule_block = generate_terraform_from_rule(rule, policy_id, policy_resource_name, is_oie_flag)
            blocks.append(rule_block)
    return "\n\n".join(blocks)

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