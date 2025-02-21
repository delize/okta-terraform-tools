#!/usr/bin/env python3
import sys
import requests
import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate Terraform HCL code for Okta Resource Sets and Admin Roles using both new and legacy endpoints."
    )
    parser.add_argument(
        "--subdomain",
        help="Your Okta subdomain (e.g. mycompany). If provided (with --domain-flag), the script builds the Okta URL."
    )
    parser.add_argument(
        "--domain-flag",
        default="default",
        help="One of: default, emea, preview, gov, mil, fedramp, etc. (default is 'default' -> okta.com)."
    )
    parser.add_argument(
        "--org-url",
        help="Full Okta Org URL, e.g. https://mycompany.okta.com. If provided, this is used instead of subdomain/domain-flag."
    )
    parser.add_argument(
        "--api-token",
        required=True,
        help="Your Okta API Token (SSWS token)."
    )
    parser.add_argument(
        "--output-file",
        help="Path to a file where the Terraform code should be written. If omitted, prints to stdout."
    )
    return parser.parse_args()

def get_okta_domain(subdomain, domain_flag=None):
    domain_map = {
        "default": "okta.com",
        "emea": "okta-emea.com",
        "preview": "oktapreview.com",
        "gov": "okta-gov.com",
        "mil": "okta.mil",
        "fedramp": "oktafed.com",
    }
    if not domain_flag:
        domain_flag = "default"
    okta_domain = domain_map.get(domain_flag.lower(), "okta.com")
    return f"https://{subdomain}.{okta_domain}"

def get_headers(api_token):
    return {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

# --------------------------
# New IAM Endpoints
# --------------------------

def get_resource_sets_new(org_url, headers):
    """
    GET /api/v1/iam/resource-sets returns a JSON object with key "resource-sets".
    """
    return paginated_get(
        start_url=f"{org_url}/api/v1/iam/resource-sets",
        headers=headers,
        list_key="resource-sets"
    )

def get_roles_new(org_url, headers):
    """
    GET /api/v1/iam/roles returns a JSON object with key "roles".
    """
    return paginated_get(
        start_url=f"{org_url}/api/v1/iam/roles",
        headers=headers,
        list_key="roles"
    )

def get_role_assignments_new(org_url, headers, role_id):
    """
    GET /api/v1/iam/roles/{roleId}/assignments.
    Raises HTTPError if the endpoint returns 404/405.
    """
    url = f"{org_url}/api/v1/iam/roles/{role_id}/assignments"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return {
        "users": data.get("userAssignments", []),
        "groups": data.get("groupAssignments", [])
    }

def get_resource_set_resources(org_url, headers, resource_set_id):
    """
    GET /api/v1/iam/resource-sets/{resource_set_id}/resources.
    Returns a list of resource objects (each should include an "orn" field).
    """
    url = f"{org_url}/api/v1/iam/resource-sets/{resource_set_id}/resources"
    return paginated_get(url, headers, list_key="resources")

def get_role_permissions(org_url, headers, role_id):
    """
    GET /api/v1/iam/roles/{roleId}/permissions returns an object with key "permissions".
    Extracts and returns a list of permission labels.
    """
    url = f"{org_url}/api/v1/iam/roles/{role_id}/permissions"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    perms = data.get("permissions", [])
    labels = [perm.get("label") for perm in perms if perm.get("label")]
    return labels

# --------------------------
# Legacy Endpoints
# --------------------------

def get_roles_legacy(org_url, headers):
    """
    GET /api/v1/roles returns a list directly.
    """
    return paginated_get(
        start_url=f"{org_url}/api/v1/roles",
        headers=headers,
        list_key=None
    )

def get_role_targets_users_legacy(org_url, headers, role_id):
    url = f"{org_url}/api/v1/roles/{role_id}/targets/users"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return resp.json()

def get_role_targets_groups_legacy(org_url, headers, role_id):
    url = f"{org_url}/api/v1/roles/{role_id}/targets/groups"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return resp.json()

# --------------------------
# Pagination Helper
# --------------------------

def paginated_get(start_url, headers, list_key=None):
    results = []
    url = start_url
    while url:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        if list_key:
            items = data.get(list_key, [])
        else:
            if isinstance(data, list):
                items = data
            else:
                items = data.get("resourceSets", data.get("roles", []))
        results.extend(items)
        next_link = None
        if "Link" in resp.headers:
            links = resp.headers["Link"].split(",")
            for link in links:
                if 'rel="next"' in link:
                    next_link = link[link.find("<")+1:link.find(">")]
        url = next_link
    return results

# --------------------------
# Helpers for Import Blocks
# --------------------------

def generate_import_block(resource_type, resource_name, id_value):
    """
    Generate an HCL import block for a given resource.
    Example output:
    
    import "okta_resource_set" "my_resource" {
      for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
      to       = okta_resource_set.my_resource[0]
      id       = "resource_id_value"
    }
    """
    block = f'''import "{resource_type}" "{resource_name}" {{
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = {resource_type}.{resource_name}[0]
  id       = "{id_value}"
}}'''
    return block

# --------------------------
# Terraform Code Generation
# --------------------------

def generate_tf_code(org_url, headers, resource_sets, new_roles, legacy_roles, roles_dict):
    tf_lines = []
    tf_lines.append("############################################")
    tf_lines.append("# IMPORT BLOCKS")
    tf_lines.append("############################################")
    
    # Resource Sets Import Blocks (including ORNs not in import but used in resource blocks)
    if resource_sets:
        tf_lines.append("\n# Resource Sets Imports")
        for rs in resource_sets:
            rs_id = rs.get("id")
            rs_label = rs.get("label") or f"resource_set_{rs_id}"
            rs_name = rs_label.lower().replace(" ", "_")
            import_block = generate_import_block("okta_resource_set", rs_name, rs_id)
            tf_lines.append(import_block)
    
    # Admin Roles Import Blocks
    tf_lines.append("\n# Admin Roles Imports")
    for rid, info in roles_dict.items():
        role_obj = info["role"]
        role_label = role_obj.get("label") or role_obj.get("name") or f"role_{rid}"
        role_name = role_label.lower().replace(" ", "_")
        if rid.startswith("cr"):
            # Custom Admin Role
            import_block = generate_import_block("okta_admin_role_custom", role_name, rid)
            tf_lines.append(import_block)
        else:
            # Legacy Admin Role targets – placeholder for composite key
            import_block = generate_import_block("okta_admin_role_targets", role_name, f"<user_id>/{rid}")
            tf_lines.append(import_block)
    
    tf_lines.append("\n############################################")
    tf_lines.append("# SAMPLE TERRAFORM RESOURCE BLOCKS")
    tf_lines.append("############################################")
    
    # Resource Sets Resource Blocks (including ORNs)
    if resource_sets:
        tf_lines.append("\n# Resource Sets")
        for rs in resource_sets:
            rs_id = rs.get("id")
            rs_label = rs.get("label") or f"resource_set_{rs_id}"
            rs_name = rs_label.lower().replace(" ", "_")
            try:
                rs_resources = get_resource_set_resources(org_url, headers, rs_id)
                orns = [r.get("orn") for r in rs_resources if r.get("orn")]
            except Exception as ex:
                print(f"[WARNING] Could not retrieve resources for resource set {rs_id}: {ex}")
                orns = []
            resources_tf = ",\n    ".join(f'"{o}"' for o in orns) if orns else "// TODO: Add resource endpoints"
            block = f'''
resource "okta_resource_set" "{rs_name}" {{
  label       = "{rs_label}"
  description = "{rs.get("description") or ""}"
  resources   = [
    {resources_tf}
  ]
}}
'''.strip()
            tf_lines.append(block)
    
    # Custom Admin Roles Resource Blocks (for roles with IDs starting with "cr")
    tf_lines.append("\n# Custom Admin Roles")
    for rid, info in roles_dict.items():
        if not rid.startswith("cr"):
            continue
        role_obj = info["role"]
        role_label = role_obj.get("label") or role_obj.get("name") or f"role_{rid}"
        role_name = role_label.lower().replace(" ", "_")
        # Retrieve permissions from the API
        try:
            perms = get_role_permissions(org_url, headers, rid)
            if perms:
                permissions_tf = ",\n    ".join(f'"{p}"' for p in perms)
            else:
                permissions_tf = "// TODO: List permissions"
        except Exception as ex:
            print(f"[WARNING] Could not retrieve permissions for role {rid}: {ex}")
            permissions_tf = "// TODO: List permissions"
        block = f'''
resource "okta_admin_role_custom" "{role_name}" {{
  label       = "{role_label}"
  description = "{role_obj.get("description") or ""}"
  permissions = [
    {permissions_tf}
  ]
}}
'''.strip()
        tf_lines.append(block)
    
    # Custom Role Assignments Sample Block (Early Access)
    tf_lines.append("\n# Custom Role Assignments (Early Access)")
    tf_lines.append('''
# Example: Assign a custom role to users/groups using a resource set.
# resource "okta_admin_role_custom_assignments" "example" {
#   resource_set_id = okta_resource_set.<resource_set_name>.id
#   custom_role_id  = okta_admin_role_custom.<custom_role_name>.id
#   members = [
#     "${local.org_url}/api/v1/users/<user_id>",
#     "${local.org_url}/api/v1/groups/<group_id>"
#   ]
# }
'''.strip())
    
    # Legacy Admin Role Targets Sample Block
    tf_lines.append("\n# Legacy Admin Role Targets")
    tf_lines.append('''
# Example: Manage legacy role assignments.
# resource "okta_admin_role_targets" "example" {
#   user_id   = "<user_id>"
#   role_type = "<ROLE_TYPE>"   // e.g., APP_ADMIN, GROUP_ADMIN, etc.
#   apps      = ["<app_name>"]  // or specify groups instead
# }
'''.strip())
    
    return "\n".join(tf_lines)

# --------------------------
# Main Script
# --------------------------

def main():
    args = parse_args()
    if args.org_url:
        org_url = args.org_url.rstrip("/")
    elif args.subdomain:
        org_url = get_okta_domain(args.subdomain, args.domain_flag)
    else:
        sys.exit("Error: Provide either --org-url or both --subdomain and --domain-flag.")
    
    headers = get_headers(args.api_token)
    
    # Retrieve new IAM roles and resource sets
    try:
        new_roles = get_roles_new(org_url, headers)
        print(f"[INFO] Retrieved {len(new_roles)} new IAM role(s) from /api/v1/iam/roles.")
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code in (404, 405):
            print("[INFO] /api/v1/iam/roles not available. Skipping new roles.")
            new_roles = []
        else:
            raise
    
    try:
        resource_sets = get_resource_sets_new(org_url, headers)
        print(f"[INFO] Retrieved {len(resource_sets)} resource set(s) from /api/v1/iam/resource-sets.")
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code in (404, 405):
            print("[INFO] /api/v1/iam/resource-sets not available. Skipping resource sets.")
            resource_sets = []
        else:
            raise
    
    # Retrieve legacy roles
    try:
        legacy_roles = get_roles_legacy(org_url, headers)
        print(f"[INFO] Retrieved {len(legacy_roles)} legacy role(s) from /api/v1/roles.")
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code in (404, 405):
            print("[INFO] /api/v1/roles not available. Skipping legacy roles.")
            legacy_roles = []
        else:
            raise
    
    # Merge roles from new and legacy endpoints into a dictionary keyed by role ID
    roles_dict = {}
    for role in new_roles:
        rid = role.get("id")
        roles_dict[rid] = {
            "role": role,
            "assignments": {"users": [], "groups": []},
            "source": "new"
        }
    for role in legacy_roles:
        rid = role.get("id")
        if rid in roles_dict:
            roles_dict[rid]["source"] += "+legacy"
        else:
            roles_dict[rid] = {
                "role": role,
                "assignments": {"users": [], "groups": []},
                "source": "legacy"
            }
    
    # Retrieve assignments for each role
    for rid, info in roles_dict.items():
        assignments = {"users": [], "groups": []}
        if rid.startswith("cr") or "new" in info["source"]:
            try:
                assignments = get_role_assignments_new(org_url, headers, rid)
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code in (404, 405):
                    print(f"[WARNING] New assignment endpoint for role {rid} returned {e.response.status_code}. Skipping assignments for this role.")
                else:
                    raise
        else:
            try:
                assignments["users"] = get_role_targets_users_legacy(org_url, headers, rid)
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code in (404, 405):
                    print(f"[WARNING] Legacy user targets for role {rid} returned {e.response.status_code}.")
                    assignments["users"] = []
                else:
                    raise
            try:
                assignments["groups"] = get_role_targets_groups_legacy(org_url, headers, rid)
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code in (404, 405):
                    print(f"[WARNING] Legacy group targets for role {rid} returned {e.response.status_code}.")
                    assignments["groups"] = []
                else:
                    raise
        info["assignments"] = assignments
    
    # Generate Terraform code (including HCL import blocks)
    tf_output = generate_tf_code(org_url, headers, resource_sets, new_roles, legacy_roles, roles_dict)
    
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(tf_output + "\n")
        print(f"[INFO] Terraform code has been written to {args.output_file}")
    else:
        print(tf_output)

if __name__ == "__main__":
    main()