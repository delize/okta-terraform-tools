#!/usr/bin/env python3
"""
Generates a comprehensive Terraform .tf file for Okta, with:

  1) Merging new IAM + legacy roles
  2) Group prefix filtering
  3) Environment-agnostic resource blocks
  4) Locals for for_each resource definitions
  5) Real permissions from role_obj["_links"]["permissions"]["href"]
  6) A single `import { for_each = ... }` block for each resource to import,
     using valid Terraform 1.5+ syntax (no extraneous labels).
  7) Replaces invalid chars in resource names (e.g., '/', '(', ')') with underscores.

Requires Terraform >= 1.5 to parse the new import block.
"""

import sys
import requests
import argparse
import urllib.parse
import pandas as pd
import re
import json

# --------------------------------------------------------------------
# Parse arguments
# --------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate environment-agnostic Terraform .tf for Okta with valid import blocks (Terraform 1.5+)."
    )
    parser.add_argument("--subdomain", help="Okta subdomain (e.g. mydomain).")
    parser.add_argument("--domain", default="default",
                        help="Domain: 'default' -> okta.com, 'emea' -> okta-emea.com, etc.")
    parser.add_argument("--org-url",
                        help="Full Okta Org URL (e.g. https://mydomain.okta-emea.com). Overrides --subdomain/--domain.")
    parser.add_argument("--api-token", required=True, help="Okta API Token (SSWS).")
    parser.add_argument("--group-prefix",
                        help="If provided, only groups whose name starts with this prefix (e.g. 'okta_admin_').")
    parser.add_argument("--output-file",
                        help="Path to the .tf output file. If omitted, prints to stdout.")
    return parser.parse_args()

# --------------------------------------------------------------------
# Construct Okta domain
# --------------------------------------------------------------------
def get_okta_domain(subdomain, domain):
    domain_map = {
        "default": "okta.com",
        "emea": "okta-emea.com",
        "preview": "oktapreview.com",
        "gov": "okta-gov.com",
        "mil": "okta.mil",
        "fedramp": "oktafed.com",
    }
    chosen_domain = domain_map.get(domain.lower(), "okta.com")
    full_url = f"https://{subdomain}.{chosen_domain}"
    print(f"[DEBUG] Constructed base Okta URL: {full_url}")
    return full_url

# --------------------------------------------------------------------
# Headers
# --------------------------------------------------------------------
def get_headers(api_token):
    return {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

# --------------------------------------------------------------------
# Paginated GET
# --------------------------------------------------------------------
def paginated_get(start_url, headers, key_hints=None):
    if not key_hints:
        key_hints = ["roles", "resource-sets", "groups", "permissions", "resourceSets"]
    results = []
    url = start_url
    while url:
        print(f"[DEBUG] GET {url}")
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            items = data
        else:
            items = []
            for k in key_hints:
                if k in data:
                    items = data[k]
                    break
        if not isinstance(items, list):
            items = []
        results.extend(items)

        # link-based pagination
        next_link = None
        if "Link" in resp.headers:
            for linkpart in resp.headers["Link"].split(","):
                if 'rel="next"' in linkpart:
                    next_link = linkpart[linkpart.find("<") + 1 : linkpart.find(">")]
        url = next_link
    return results

# --------------------------------------------------------------------
# get resource sets, new roles
# --------------------------------------------------------------------
def get_resource_sets_new(org_url, headers):
    url = f"{org_url}/api/v1/iam/resource-sets"
    return paginated_get(url, headers, ["resource-sets"])

def get_roles_new(org_url, headers):
    url = f"{org_url}/api/v1/iam/roles"
    return paginated_get(url, headers, ["roles"])

# --------------------------------------------------------------------
# fetch custom role assignments from links
# --------------------------------------------------------------------
def get_role_assignments_new(role_obj, headers):
    links = role_obj.get("_links", {})
    as_href = links.get("assignments", {}).get("href")
    if not as_href:
        return {"users": [], "groups": []}
    print(f"[DEBUG] GET role assignments from {as_href}")
    resp = requests.get(as_href, headers=headers)
    if resp.status_code in [404, 405]:
        return {"users": [], "groups": []}
    resp.raise_for_status()
    data = resp.json()
    return {
        "users": data.get("userAssignments", []),
        "groups": data.get("groupAssignments", [])
    }

def get_resource_set_resources(org_url, headers, rs_id):
    url = f"{org_url}/api/v1/iam/resource-sets/{rs_id}/resources"
    return paginated_get(url, headers, ["resources"])

# --------------------------------------------------------------------
# fetch custom role permissions from role_obj["_links"]["permissions"]["href"]
# --------------------------------------------------------------------
def get_role_permissions_via_links(role_obj, headers):
    links = role_obj.get("_links", {})
    perms_href = links.get("permissions", {}).get("href")
    if not perms_href:
        return []
    print(f"[DEBUG] GET permissions from {perms_href}")
    resp = requests.get(perms_href, headers=headers)
    if resp.status_code in [404, 405]:
        return []
    resp.raise_for_status()
    data = resp.json()
    items = data.get("permissions", [])
    return [p["label"] for p in items if "label" in p]

# --------------------------------------------------------------------
# legacy roles
# --------------------------------------------------------------------
def get_roles_legacy(org_url, headers):
    url = f"{org_url}/api/v1/roles"
    return paginated_get(url, headers)

def get_role_targets_users_legacy(org_url, headers, rid):
    url = f"{org_url}/api/v1/roles/{rid}/targets/users"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return resp.json()

def get_role_targets_groups_legacy(org_url, headers, rid):
    url = f"{org_url}/api/v1/roles/{rid}/targets/groups"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return resp.json()

# --------------------------------------------------------------------
# group endpoints
# --------------------------------------------------------------------
def get_groups_by_prefix(org_url, headers, prefix):
    query = urllib.parse.quote(f'profile.name sw "{prefix}"')
    url = f"{org_url}/api/v1/groups?search={query}"
    return paginated_get(url, headers)

def get_group_roles(org_url, headers, group_id):
    url = f"{org_url}/api/v1/groups/{group_id}/roles"
    return paginated_get(url, headers)

# --------------------------------------------------------------------
# sanitize resource names
# --------------------------------------------------------------------
def sanitize_name(original_str):
    """
    Replaces invalid Terraform name chars (/, (, ), spaces, etc.) with underscores.
    """
    out = original_str.lower()
    out = re.sub(r"[^a-z0-9_-]+", "_", out)
    return out

# --------------------------------------------------------------------
# create dataframes for group
# --------------------------------------------------------------------
def create_groups_df(groups):
    df = pd.DataFrame(groups)
    df['group_name'] = df['profile'].apply(lambda x: x.get('name', '') if isinstance(x, dict) else '')
    df['normalized'] = df['group_name'].str.lower().str.replace(r"[^a-z0-9_-]+", "_", regex=True)
    df['normalized'] = df['normalized'].str.replace("^okta_admin_", "", regex=True)
    return df

# --------------------------------------------------------------------
# build resource set + group mappings
# --------------------------------------------------------------------
def build_mappings(resource_sets, groups):
    rs_map = {}
    for rs in resource_sets:
        rsid = rs.get("id")
        label = rs.get("label") or f"rs_{rsid}"
        nm = sanitize_name(label)
        rs_map[rsid] = nm

    g_map = {}
    for g in groups:
        gid = g.get("id")
        gp = g.get("profile", {})
        label = gp.get("name", f"group_{gid}")
        nm = sanitize_name(label)
        g_map[gid] = nm

    return rs_map, g_map

# --------------------------------------------------------------------
# generate a single import block with for_each
# --------------------------------------------------------------------
def generate_import_block(resources_to_import):
    """
    resources_to_import is a dict:
      "key" -> {
        "to": "okta_resource_set.okta_sf_admin",
        "id": "0prcbzafd2rTo9bWP0i7"
      }

    We'll produce valid HCL for Terraform 1.5+:

    import {
      for_each = {
        "okta_sf_admin" = {
          to = "okta_resource_set.okta_sf_admin"
          id = "0prcbzafd2rTo9bWP0i7"
        }
      }
      to = each.value.to
      id = each.value.id
    }
    """
    lines = []
    lines.append('import {')
    lines.append('  for_each = {')
    for k, v in resources_to_import.items():
        lines.append(f'    "{k}" = {{')
        lines.append(f'      to = "{v["to"]}"')
        lines.append(f'      id = "{v["id"]}"')
        lines.append('    },')
    lines.append('  }')
    lines.append('')
    lines.append('  to = each.value.to')
    lines.append('  id = each.value.id')
    lines.append('}')
    return "\n".join(lines)

# --------------------------------------------------------------------
# gather resources -> local map => generate the single "import" block
# --------------------------------------------------------------------
def build_import_map(resource_sets, roles_dict, groups):
    """
    We'll produce a dictionary:
      {
        "okta_sf_admin_set" : {
          "to": "okta_resource_set.okta_sf_admin",
          "id": "0prcbzafd2rTo9bWP0i7"
        },
        ...
      }
    """
    import_data = {}

    # 1) Resource Sets
    for rs in resource_sets:
        rs_id = rs.get("id")
        lbl = rs.get("label") or f"rs_{rs_id}"
        nm = sanitize_name(lbl)
        key = f"resource_set_{nm}"
        import_data[key] = {
            "to": f"okta_resource_set.{nm}",
            "id": rs_id
        }

    # 2) Roles (custom + legacy)
    for rid, info in roles_dict.items():
        r_obj = info["role"]
        label = r_obj.get("label") or r_obj.get("name", rid)
        nm = sanitize_name(label)
        if rid.startswith("cr"):
            # custom
            key = f"custom_role_{nm}"
            import_data[key] = {
                "to": f"okta_admin_role_custom.{nm}",
                "id": rid
            }
        else:
            # standard or legacy
            # we don't know which user/group it's assigned to, so do a partial
            # "id" might be "<user_id>/<role_id>"
            # but let's store just the role for now
            # note that Terraform's "okta_admin_role_targets" often needs a user/group
            # for now we'll do a placeholder
            key = f"legacy_role_{nm}"
            import_data[key] = {
                "to": f"okta_admin_role_targets.{nm}",
                "id": f"<user_or_group_id>/{rid}"
            }

    # 3) Groups
    for g in groups:
        gid = g.get("id")
        gp = g.get("profile", {})
        gname = gp.get("name", f"group_{gid}")
        nm = sanitize_name(gname)
        key = f"group_{nm}"
        import_data[key] = {
            "to": f"okta_group.{nm}",
            "id": gid
        }

    return import_data

# --------------------------------------------------------------------
# Generate the resource blocks for explicit approach + locals + for_each
# --------------------------------------------------------------------
def generate_for_each_resources():
    lines = []
    lines.append("############################################")
    lines.append("# DYNAMIC RESOURCE BLOCKS (Using for_each on locals)")
    lines.append("############################################\n")

    lines.append('resource "okta_resource_set" "dynamic" {')
    lines.append('  for_each    = local.okta_resource_sets')
    lines.append('  label       = each.value.label')
    lines.append('  description = each.value.description')
    lines.append('  resources   = each.value.resources')
    lines.append('}\n')

    lines.append('resource "okta_admin_role_custom" "dynamic" {')
    lines.append('  for_each    = local.okta_admin_role_customs')
    lines.append('  label       = each.value.label')
    lines.append('  description = each.value.description')
    lines.append('  permissions = each.value.permissions')
    lines.append('}\n')

    lines.append('resource "okta_admin_role_custom_assignments" "dynamic" {')
    lines.append('  for_each         = local.okta_admin_role_custom_assignments')
    lines.append('  resource_set_id  = each.value.resource_set_ref')
    lines.append('  custom_role_id   = each.value.custom_role_ref')
    lines.append('  members          = ["${var.TFC_OKTA_ORG_NAME}${var.TFC_OKTA_BASE_URL}/api/v1/groups/${each.value.group_resource_ref}"]')
    lines.append('}\n')

    lines.append('resource "okta_admin_role_targets" "dynamic" {')
    lines.append('  for_each = local.okta_admin_role_targets')
    lines.append('  user_id   = each.value.user_id')
    lines.append('  role_type = each.value.role_type')
    lines.append('  apps      = each.value.apps')
    lines.append('}\n')

    lines.append('resource "okta_group" "dynamic" {')
    lines.append('  for_each = local.okta_groups')
    lines.append('  name        = each.value.name')
    lines.append('  description = each.value.description')
    lines.append('}\n')

    return "\n".join(lines)

# --------------------------------------------------------------------
# Generate locals blocks
# --------------------------------------------------------------------
def generate_locals_blocks(roles_dict, rs_mapping, group_mapping, groups):
    lines = []

    resource_sets_local = {}
    for rsid, rsname in rs_mapping.items():
        resource_sets_local[rsname] = {
            "label": rsname,
            "description": f"Description for {rsname}",
            "resources": []
        }

    # custom roles
    custom_roles_local = {}
    df = create_groups_df(groups)
    for rid, info in roles_dict.items():
        if rid.startswith("cr"):
            r_obj = info["role"]
            label = r_obj.get("label") or r_obj.get("name", rid)
            nm = sanitize_name(label)
            perms = info.get("permissions", [])
            custom_roles_local[nm] = {
                "label": label,
                "description": r_obj.get("description", ""),
                "permissions": perms
            }

    # custom role assignments
    custom_assignments_local = {}
    for rid, info in roles_dict.items():
        if rid.startswith("cr"):
            r_obj = info["role"]
            label = r_obj.get("label") or r_obj.get("name", rid)
            nm = sanitize_name(label)

            rs_id = r_obj.get("resource-set")
            if rs_id and rs_id in rs_mapping:
                rs_ref = f"okta_resource_set.{rs_mapping[rs_id]}.id"
            else:
                rs_ref = "<RESOURCE_SET_ID>"

            matched_group_ref = "<group_ref>"
            matched = df[df['normalized'] == nm]
            if not matched.empty:
                gid = matched.iloc[0]['id']
                matched_group_ref = f"okta_group.{group_mapping.get(gid, 'unknown')}.id"

            custom_assignments_local[nm] = {
                "resource_set_ref": rs_ref,
                "custom_role_ref": f"okta_admin_role_custom.{nm}.id",
                "group_resource_ref": matched_group_ref
            }

    # legacy role targets
    legacy_targets_local = {}
    for rid, info in roles_dict.items():
        if not rid.startswith("cr"):
            r_obj = info["role"]
            label = r_obj.get("label") or r_obj.get("name", rid)
            nm = sanitize_name(label)
            legacy_targets_local[nm] = {
                "user_id": "<user_id>",
                "role_type": "<ROLE_TYPE>",
                "apps": []
            }

    # groups
    groups_local = {}
    for g in groups:
        gid = g.get("id")
        gp = g.get("profile", {})
        label = gp.get("name", f"group_{gid}")
        groups_local[label] = {
            "name": label,
            "description": gp.get("description", "")
        }

    lines.append("locals {\n  okta_resource_sets = " + json.dumps(resource_sets_local, indent=4) + "\n}")
    lines.append("locals {\n  okta_admin_role_customs = " + json.dumps(custom_roles_local, indent=4) + "\n}")
    lines.append("locals {\n  okta_admin_role_custom_assignments = " + json.dumps(custom_assignments_local, indent=4) + "\n}")
    lines.append("locals {\n  okta_admin_role_targets = " + json.dumps(legacy_targets_local, indent=4) + "\n}")
    lines.append("locals {\n  okta_groups = " + json.dumps(groups_local, indent=4) + "\n}")
    return "\n\n".join(lines)

# --------------------------------------------------------------------
# Build the final TF code
# --------------------------------------------------------------------
def generate_tf_code(org_url, headers, resource_sets, new_roles, legacy_roles, roles_dict, groups):
    lines = []

    # 1) Single import block with for_each
    lines.append("############################################")
    lines.append("# IMPORT BLOCK (Terraform 1.5+), environment-specific")
    lines.append("############################################")
    import_map = build_import_map(resource_sets, roles_dict, groups)
    lines.append(generate_import_block(import_map))

    # 2) Environment-agnostic resource blocks
    lines.append("\n############################################")
    lines.append("# ENVIRONMENT AGNOSTIC RESOURCE BLOCKS (Explicit)")
    lines.append("############################################")

    rs_mapping, group_mapping = build_mappings(resource_sets, groups)

    # 2a) Resource sets (explicit)
    if resource_sets:
        lines.append("\n# Resource Sets (Explicit blocks)")
        for rs in resource_sets:
            rsid = rs.get("id")
            label = rs.get("label") or f"rs_{rsid}"
            nm = sanitize_name(label)
            desc = rs.get("description", "")
            # resources
            try:
                fetched = get_resource_set_resources(org_url, headers, rsid)
                new_res = []
                for item in fetched:
                    orn = item.get("orn", "")
                    if "groups:" in orn:
                        mm = re.search(r"groups:([^:]+)", orn)
                        if mm:
                            gr_id = mm.group(1)
                            if gr_id in group_mapping:
                                new_res.append(
                                    f'${{var.TFC_OKTA_ORG_NAME}}${{var.TFC_OKTA_BASE_URL}}/api/v1/groups/${{okta_group.{group_mapping[gr_id]}.id}}'
                                )
                            else:
                                new_res.append(orn)
                        else:
                            new_res.append(orn)
                    else:
                        new_res.append(orn)
            except:
                new_res = []
            block = []
            block.append(f'resource "okta_resource_set" "{nm}" {{')
            block.append(f'  label       = "{label}"')
            block.append(f'  description = "{desc}"')
            if new_res:
                block.append("  resources = [")
                for r2 in new_res:
                    block.append(f'    "{r2}",')
                block.append("  ]")
            else:
                block.append("  resources = []")
            block.append("}\n")
            lines.append("\n".join(block))

    # 2b) Custom roles (explicit)
    lines.append("\n# Custom Admin Roles (Explicit)")
    for rid, info in roles_dict.items():
        if rid.startswith("cr"):
            r_obj = info["role"]
            label = r_obj.get("label") or r_obj.get("name", rid)
            nm = sanitize_name(label)
            perms = info.get("permissions", [])
            block = []
            block.append(f'resource "okta_admin_role_custom" "{nm}" {{')
            block.append(f'  label       = "{label}"')
            block.append(f'  description = "{r_obj.get("description", "")}"')
            block.append("  permissions = [")
            for p in perms:
                block.append(f'    "{p}",')
            block.append("  ]")
            block.append("}\n")
            lines.append("\n".join(block))

    # 3) Locals blocks for dynamic for_each
    lines.append("\n############################################")
    lines.append("# LOCALS BLOCKS (for dynamic for_each usage)")
    lines.append("############################################\n")

    # ensure we fill custom role perms
    for rid, info in roles_dict.items():
        if rid.startswith("cr"):
            # might already have been filled
            pass

    locals_text = generate_locals_blocks(roles_dict, rs_mapping, group_mapping, groups)
    lines.append(locals_text)

    # 4) for_each resource blocks
    lines.append("\n############################################")
    lines.append("# DYNAMIC for_each RESOURCE BLOCKS")
    lines.append("############################################\n")
    lines.append(generate_for_each_resources())

    return "\n".join(lines)

# --------------------------------------------------------------------
# main
# --------------------------------------------------------------------
def main():
    args = parse_args()

    if args.org_url:
        org_url = args.org_url.rstrip("/")
    elif args.subdomain:
        org_url = get_okta_domain(args.subdomain, args.domain)
    else:
        sys.exit("[ERROR] Provide either --org-url or both --subdomain and --domain.")

    headers = get_headers(args.api_token)

    # 1) Resource sets
    print("[INFO] Retrieving resource sets from new IAM endpoint...")
    try:
        resource_sets = get_resource_sets_new(org_url, headers)
        print(f"[INFO] Found {len(resource_sets)} resource set(s).")
    except requests.HTTPError:
        resource_sets = []

    # 2) new IAM roles
    print("[INFO] Retrieving new IAM roles (/api/v1/iam/roles)...")
    try:
        new_iam_roles = get_roles_new(org_url, headers)
        print(f"[INFO] Found {len(new_iam_roles)} new IAM role(s).")
    except requests.HTTPError:
        new_iam_roles = []

    # 3) legacy roles
    print("[INFO] Retrieving legacy roles (/api/v1/roles)...")
    try:
        legacy_roles = get_roles_legacy(org_url, headers)
        print(f"[INFO] Found {len(legacy_roles)} legacy role(s).")
    except requests.HTTPError:
        legacy_roles = []

    # combine roles
    roles_dict = {}
    for r in new_iam_roles:
        rid = r.get("id")
        roles_dict[rid] = {
            "role": r,
            "assignments": {"users": [], "groups": []},
            "source": "new"
        }
    for r in legacy_roles:
        rid = r.get("id")
        if rid in roles_dict:
            roles_dict[rid]["source"] += "+legacy"
        else:
            roles_dict[rid] = {
                "role": r,
                "assignments": {"users": [], "groups": []},
                "source": "legacy"
            }

    # 4) fill roles with assignments/permissions
    for rid, info in roles_dict.items():
        r_obj = info["role"]
        if rid.startswith("cr") or "new" in info["source"]:
            # fetch assignments
            try:
                asg = get_role_assignments_new(r_obj, headers)
                info["assignments"] = asg
            except:
                pass
            # fetch perms from links
            perms = get_role_permissions_via_links(r_obj, headers)
            info["permissions"] = perms
        else:
            # legacy user / group targets
            try:
                ut = get_role_targets_users_legacy(org_url, headers, rid)
                info["assignments"]["users"] = ut
            except:
                pass
            try:
                gt = get_role_targets_groups_legacy(org_url, headers, rid)
                info["assignments"]["groups"] = gt
            except:
                pass

    # 5) groups if prefix
    groups = []
    if args.group_prefix:
        try:
            groups = get_groups_by_prefix(org_url, headers, args.group_prefix)
            print(f"[INFO] Found {len(groups)} group(s) matching prefix '{args.group_prefix}'.")
        except:
            pass

    # 6) build final tf code
    tf_code = generate_tf_code(org_url, headers, resource_sets, new_iam_roles, legacy_roles, roles_dict, groups)

    # 7) output
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(tf_code + "\n")
        print("[INFO] Wrote Terraform code to", args.output_file)
    else:
        print(tf_code)

if __name__ == "__main__":
    main()