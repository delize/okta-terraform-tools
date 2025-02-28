#!/usr/bin/env python3
import argparse
import requests
import json
import re
import time

def get_okta_domain(subdomain, domain_flag):
    """
    Build the Okta domain URL using a subdomain and domain_flag.
    domain_flag can be 'default', 'emea', 'preview', 'gov', or 'mil'.
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

def get_api_data(url, headers, retry_count=3):
    """Helper function to query an Okta API endpoint with basic rate-limit handling."""
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json(), response.headers
    elif response.status_code == 429:
        reset = response.headers.get("x-rate-limit-reset")
        if reset:
            current_time = time.time()
            sleep_time = int(reset) - current_time
            if sleep_time < 0:
                sleep_time = 1
            print(f"Rate limit reached. Sleeping for {sleep_time:.2f} seconds before retrying {url}.")
            time.sleep(sleep_time)
        else:
            print("Rate limit reached but no reset header found. Sleeping for 60 seconds.")
            time.sleep(60)
        if retry_count > 0:
            return get_api_data(url, headers, retry_count - 1)
        else:
            print(f"Retries exhausted for {url}")
            return None, response.headers
    else:
        print(f"Error: {response.status_code} when querying {url}")
        return None, response.headers

def fetch_roles(okta_domain, headers):
    roles = []
    endpoint = f"https://{okta_domain}/api/v1/iam/roles"
    while endpoint:
        print(f"Fetching roles from: {endpoint}")
        data, _ = get_api_data(endpoint, headers)
        if not data:
            break
        roles.extend(data.get("roles", []))
        next_link = data.get("_links", {}).get("next", {}).get("href")
        endpoint = next_link if next_link else None
    return roles

def fetch_role_permissions(okta_domain, role_id, headers):
    permissions_endpoint = f"https://{okta_domain}/api/v1/iam/roles/{role_id}/permissions"
    print(f"Fetching permissions from: {permissions_endpoint}")
    data, _ = get_api_data(permissions_endpoint, headers)
    if data and "permissions" in data:
        return [perm.get("label") for perm in data["permissions"] if perm.get("label")]
    return []

def fetch_resource_sets(okta_domain, headers):
    resource_sets = []
    endpoint = f"https://{okta_domain}/api/v1/iam/resource-sets"
    while endpoint:
        print(f"Fetching resource sets from: {endpoint}")
        data, _ = get_api_data(endpoint, headers)
        if not data:
            break
        resource_sets.extend(data.get("resource-sets", []))
        next_link = data.get("_links", {}).get("next", {}).get("href")
        endpoint = next_link if next_link else None
    return resource_sets

def fetch_resource_set_resources(okta_domain, resource_set_id, headers):
    endpoint = f"https://{okta_domain}/api/v1/iam/resource-sets/{resource_set_id}/resources"
    print(f"Fetching resource set resources from: {endpoint}")
    data, _ = get_api_data(endpoint, headers)
    resources = []
    if data and "resources" in data:
        for res in data["resources"]:
            links = res.get("_links")
            if not links:
                print(f"DEBUG: Resource {res.get('id')} (ORN: {res.get('orn')}) missing '_links'.")
                continue
            self_link_obj = links.get("self")
            if not self_link_obj:
                print(f"DEBUG: Resource {res.get('id')} (ORN: {res.get('orn')}) missing 'self' link.")
                continue
            href = self_link_obj.get("href")
            if href:
                resources.append(href)
            else:
                print(f"DEBUG: Resource {res.get('id')} (ORN: {res.get('orn')}) has 'self' but no 'href'.")
    else:
        print(f"DEBUG: No 'resources' key in response for resource set {resource_set_id}.")
    return resources

def fetch_all_groups(okta_domain, headers):
    groups = []
    endpoint = f"https://{okta_domain}/api/v1/groups"
    while endpoint:
        print(f"Fetching groups from: {endpoint}")
        resp = requests.get(endpoint, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            groups.extend(data)
            link_header = resp.headers.get("Link")
            next_url = None
            if link_header:
                links = re.findall(r'<([^>]+)>;\s*rel="next"', link_header)
                if links:
                    next_url = links[0]
            endpoint = next_url
        else:
            print(f"Error: {resp.status_code} when fetching groups from {endpoint}")
            break
    return groups

def fetch_all_users(okta_domain, headers):
    users = []
    endpoint = f"https://{okta_domain}/api/v1/users"
    while endpoint:
        print(f"Fetching users from: {endpoint}")
        resp = requests.get(endpoint, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            users.extend(data)
            link_header = resp.headers.get("Link")
            next_url = None
            if link_header:
                links = re.findall(r'<([^>]+)>;\s*rel="next"', link_header)
                if links:
                    next_url = links[0]
            endpoint = next_url
        else:
            print(f"Error: {resp.status_code} when fetching users from {endpoint}")
            break
    return users

def fetch_group_roles(okta_domain, group_id, headers):
    endpoint = f"https://{okta_domain}/api/v1/groups/{group_id}/roles"
    print(f"Fetching group roles for group {group_id} from: {endpoint}")
    data, _ = get_api_data(endpoint, headers)
    return data if data else []

def fetch_user_roles(okta_domain, user_id, headers):
    endpoint = f"https://{okta_domain}/api/v1/users/{user_id}/roles"
    print(f"Fetching user roles for user {user_id} from: {endpoint}")
    data, _ = get_api_data(endpoint, headers)
    return data if data else []

# ----- Aggregation for Custom Assignments -----

def aggregate_custom_assignments(group_roles_by_group, user_roles_by_user):
    """
    Aggregate custom role assignments from groups and users.
    Returns a dict keyed by (custom_role_id, resource_set_id) with a set of member hrefs.
    """
    custom_assignments = {}
    # Process group custom assignments.
    for group_id, assignments in group_roles_by_group.items():
        for assignment in assignments:
            if assignment.get("type") == "CUSTOM":
                custom_role_id = assignment.get("role")
                resource_set_id = assignment.get("resource-set")
                key = (custom_role_id, resource_set_id)
                # Escape curly braces for literal output.
                member_href = '${{local.org_url}}/api/v1/groups/{}'.format(group_id)
                custom_assignments.setdefault(key, set()).add(member_href)
    # Process user custom assignments.
    for user_id, assignments in user_roles_by_user.items():
        for assignment in assignments:
            if assignment.get("type") == "CUSTOM":
                custom_role_id = assignment.get("role")
                resource_set_id = assignment.get("resource-set")
                key = (custom_role_id, resource_set_id)
                member_href = '${{local.org_url}}/api/v1/users/{}'.format(user_id)
                custom_assignments.setdefault(key, set()).add(member_href)
    return custom_assignments

def generate_terraform_custom_assignments(custom_assignments, tf_file, terraform_format):
    with open(tf_file, "a") as f:
        f.write("\n# Terraform configuration for Custom Role Assignments (okta_admin_role_custom_assignments)\n\n")
        for (custom_role_id, resource_set_id), members in custom_assignments.items():
            resource_name = f"ca_{custom_role_id}_{resource_set_id}"
            members_list = ", ".join([f'"{m}"' for m in members])
            if terraform_format == "hcl":
                block = f'''
resource "okta_admin_role_custom_assignments" "{resource_name}" {{
  resource_set_id = "{resource_set_id}"
  custom_role_id  = "{custom_role_id}"
  members         = [{members_list}]
}}
'''
            else:
                block = json.dumps({
                    "resource": {
                        "okta_admin_role_custom_assignments": {
                            resource_name: {
                                "resource_set_id": resource_set_id,
                                "custom_role_id": custom_role_id,
                                "members": list(members)
                            }
                        }
                    }
                }, indent=2) + "\n"
            f.write(block)

def generate_import_blocks_for_custom_assignments(custom_assignments, tf_file):
    with open(tf_file, "a") as f:
        f.write("\n# Import blocks for Custom Role Assignments\n")
        for (custom_role_id, resource_set_id) in custom_assignments.keys():
            resource_name = f"ca_{custom_role_id}_{resource_set_id}"
            block = f'''
import {{
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_admin_role_custom_assignments.{resource_name}
  id       = "{resource_set_id}/{custom_role_id}"
}}
'''
            f.write(block)

# ----- Generate Non-Custom Group and User Roles -----

def generate_terraform_group_roles(group_roles_by_group, tf_file, terraform_format):
    with open(tf_file, "a") as f:
        f.write("\n# Terraform configuration for Standard Group Roles (okta_group_role)\n\n")
        for group_id, assignments in group_roles_by_group.items():
            for assignment in assignments:
                if assignment.get("type") == "CUSTOM":
                    continue
                role_type = assignment.get("type")
                resource_name = f"group_{group_id}_{assignment.get('id')}"
                block = f'''
resource "okta_group_role" "{resource_name}" {{
  group_id  = "{group_id}"
  role_type = "{role_type}"
}}
'''
                f.write(block)

def generate_import_blocks_for_group_roles(group_roles_by_group, tf_file):
    with open(tf_file, "a") as f:
        f.write("\n# Import blocks for Standard Group Roles\n")
        for group_id, assignments in group_roles_by_group.items():
            for assignment in assignments:
                if assignment.get("type") == "CUSTOM":
                    continue
                resource_name = f"group_{group_id}_{assignment.get('id')}"
                block = f'''
import {{
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_group_role.{resource_name}
  id       = "{assignment.get('id')}"
}}
'''
                f.write(block)

def generate_terraform_user_roles(user_roles_by_user, tf_file, terraform_format):
    with open(tf_file, "a") as f:
        f.write("\n# Terraform configuration for Standard User Admin Roles (okta_user_admin_roles)\n\n")
        for user_id, assignments in user_roles_by_user.items():
            standard_roles = [assignment.get("type") for assignment in assignments if assignment.get("type") != "CUSTOM"]
            if not standard_roles:
                continue
            roles_list = list(set(standard_roles))
            roles_formatted = ", ".join([f'"{r}"' for r in roles_list])
            resource_name = f"user_{user_id}"
            block = f'''
resource "okta_user_admin_roles" "{resource_name}" {{
  user_id     = "{user_id}"
  admin_roles = [{roles_formatted}]
}}
'''
            f.write(block)

def generate_import_blocks_for_user_roles(user_roles_by_user, tf_file):
    with open(tf_file, "a") as f:
        f.write("\n# Import blocks for Standard User Admin Roles\n")
        for user_id, assignments in user_roles_by_user.items():
            standard_roles = [assignment.get("type") for assignment in assignments if assignment.get("type") != "CUSTOM"]
            if not standard_roles:
                continue
            resource_name = f"user_{user_id}"
            block = f'''
import {{
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_user_admin_roles.{resource_name}
  id       = "{user_id}"
}}
'''
            f.write(block)

# ----- Main IAM Role and Resource Set Blocks -----

def generate_terraform_roles(roles, tf_file, terraform_format, okta_domain, headers):
    with open(tf_file, "a") as f:
        f.write("\n# Terraform configuration for Okta IAM Admin Roles (okta_admin_role_custom)\n\n")
        for role in roles:
            role_id = role.get("id")
            label = role.get("label")
            description = role.get("description", "")
            permissions = fetch_role_permissions(okta_domain, role_id, headers)
            if terraform_format == "hcl":
                perms_formatted = ", ".join([f'"{perm}"' for perm in permissions])
                block = f'''
resource "okta_admin_role_custom" "role_{role_id}" {{
  label       = "{label}"
  description = "{description}"
  permissions = [{perms_formatted}]
}}
'''
            else:
                block = json.dumps({
                    "resource": {
                        "okta_admin_role_custom": {
                            f"role_{role_id}": {
                                "label": label,
                                "description": description,
                                "permissions": permissions
                            }
                        }
                    }
                }, indent=2) + "\n"
            f.write(block)

def generate_terraform_resource_sets(resource_sets, tf_file, terraform_format, okta_domain, headers):
    with open(tf_file, "a") as f:
        f.write("\n# Terraform configuration for Okta Resource Sets (okta_resource_set)\n\n")
        for rs in resource_sets:
            rs_id = rs.get("id")
            label = rs.get("label")
            description = rs.get("description", "")
            endpoints = fetch_resource_set_resources(okta_domain, rs_id, headers)
            if terraform_format == "hcl":
                endpoints_formatted = ", ".join([f'"{ep}"' for ep in endpoints])
                block = f'''
resource "okta_resource_set" "rs_{rs_id}" {{
  label       = "{label}"
  description = "{description}"
  resources   = [{endpoints_formatted}]
}}
'''
            else:
                block = json.dumps({
                    "resource": {
                        "okta_resource_set": {
                            f"rs_{rs_id}": {
                                "label": label,
                                "description": description,
                                "resources": endpoints
                            }
                        }
                    }
                }, indent=2) + "\n"
            f.write(block)

def generate_import_blocks_for_resource_sets(resource_sets, tf_file):
    with open(tf_file, "a") as f:
        f.write("\n# Import blocks for Okta Resource Sets\n")
        for rs in resource_sets:
            rs_id = rs.get("id")
            block = f'''
import {{
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_resource_set.rs_{rs_id}[0]
  id       = "{rs_id}"
}}
'''
            f.write(block)

def generate_import_blocks_for_admin_roles(roles, tf_file):
    with open(tf_file, "a") as f:
        f.write("\n# Import blocks for Okta IAM Admin Roles\n")
        for role in roles:
            role_id = role.get("id")
            block = f'''
import {{
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_admin_role_custom.role_{role_id}
  id       = "{role_id}"
}}
'''
            f.write(block)

# ----- Main Function -----

def main():
    parser = argparse.ArgumentParser(description="Generate Terraform config from Okta API data.")
    parser.add_argument("--subdomain", required=True, help="Okta subdomain (e.g. eqtpartners)")
    parser.add_argument("--domain-flag", choices=["default", "emea", "preview", "gov", "mil"], default="default",
                        help="Domain flag to determine the Okta domain suffix")
    parser.add_argument("--api-token", help="Okta API token", required=True)
    parser.add_argument("--output-prefix", help="Prefix for the output Terraform file", default="okta")
    parser.add_argument("--terraform-format", choices=["hcl", "json"], default="hcl",
                        help="Output format for Terraform configuration (hcl or json)")
    parser.add_argument("--all-groups", action="store_true", help="Iterate over all groups to fetch group roles")
    parser.add_argument("--all-users", action="store_true", help="Iterate over all users to fetch user roles")
    
    args = parser.parse_args()

    okta_domain = get_okta_domain(args.subdomain, args.domain_flag)
    print(f"Using Okta domain: {okta_domain}")

    headers = {
        "Authorization": f"SSWS {args.api_token}",
        "Accept": "application/json"
    }

    tf_file = f"{args.output_prefix}_resources.tf"
    with open(tf_file, "w") as f:
        f.write("""# Generated Terraform configuration for Okta resources

data "okta_org_metadata" "_" {}
locals {
  org_url = try(
    data.okta_org_metadata._.alternate,
    data.okta_org_metadata._.organization
  )
}

""")
    
    # Fetch IAM roles and resource sets.
    roles = fetch_roles(okta_domain, headers)
    resource_sets = fetch_resource_sets(okta_domain, headers)
    
    # Write import blocks for IAM roles and resource sets.
    generate_import_blocks_for_resource_sets(resource_sets, tf_file)
    generate_import_blocks_for_admin_roles(roles, tf_file)
    
    # Process groups and users if requested.
    group_roles_by_group = {}
    user_roles_by_user = {}
    if args.all_groups:
        groups = fetch_all_groups(okta_domain, headers)
        for group in groups:
            group_id = group.get("id")
            assignments = fetch_group_roles(okta_domain, group_id, headers)
            if assignments:
                group_roles_by_group[group_id] = assignments
        generate_import_blocks_for_group_roles(group_roles_by_group, tf_file)
        generate_terraform_group_roles(group_roles_by_group, tf_file, args.terraform_format)
    if args.all_users:
        users = fetch_all_users(okta_domain, headers)
        for user in users:
            user_id = user.get("id")
            assignments = fetch_user_roles(okta_domain, user_id, headers)
            if assignments:
                user_roles_by_user[user_id] = assignments
        generate_import_blocks_for_user_roles(user_roles_by_user, tf_file)
        generate_terraform_user_roles(user_roles_by_user, tf_file, args.terraform_format)
    
    # Aggregate custom assignments and generate blocks.
    custom_assignments = aggregate_custom_assignments(group_roles_by_group, user_roles_by_user)
    generate_import_blocks_for_custom_assignments(custom_assignments, tf_file)
    generate_terraform_custom_assignments(custom_assignments, tf_file, args.terraform_format)
    
    # Generate the main IAM role and resource set blocks.
    generate_terraform_roles(roles, tf_file, args.terraform_format, okta_domain, headers)
    generate_terraform_resource_sets(resource_sets, tf_file, args.terraform_format, okta_domain, headers)
    
    # --- Store complete user API data as a Terraform locals block for interpolation ---
    users = fetch_all_users(okta_domain, headers)
    user_map = { user["email"]: user["id"] for user in users if "email" in user and "id" in user }
    locals_block = "locals {\n  user_map = " + json.dumps(user_map, indent=2) + "\n}\n"
    with open(tf_file, "a") as f:
        f.write("\n# Locals mapping for users (for interpolation)\n")
        f.write(locals_block)
    
    print(f"Terraform configuration written to {tf_file}")

if __name__ == "__main__":
    main()