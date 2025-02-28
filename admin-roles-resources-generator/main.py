#!/usr/bin/env python3
import argparse
import requests
import json

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

def get_api_data(url, headers):
    """Helper function to query an Okta API endpoint."""
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} when querying {url}")
        return None

def fetch_roles(okta_domain, headers):
    """Fetch all roles from Okta, handling pagination if necessary."""
    roles = []
    endpoint = f"https://{okta_domain}/api/v1/iam/roles"
    
    while endpoint:
        print(f"Fetching roles from: {endpoint}")
        data = get_api_data(endpoint, headers)
        if not data:
            break
        roles.extend(data.get("roles", []))
        next_link = data.get("_links", {}).get("next", {}).get("href")
        endpoint = next_link if next_link else None
    return roles

def fetch_role_permissions(okta_domain, role_id, headers):
    """
    Fetch the permissions for a given role using its permissions endpoint.
    Returns a list of permission labels.
    """
    permissions_endpoint = f"https://{okta_domain}/api/v1/iam/roles/{role_id}/permissions"
    print(f"Fetching permissions from: {permissions_endpoint}")
    data = get_api_data(permissions_endpoint, headers)
    if data and "permissions" in data:
        perms = [perm.get("label") for perm in data["permissions"] if perm.get("label")]
        return perms
    return []

def fetch_resource_sets(okta_domain, headers):
    """Fetch all resource sets from Okta, handling pagination if necessary."""
    resource_sets = []
    endpoint = f"https://{okta_domain}/api/v1/iam/resource-sets"
    
    while endpoint:
        print(f"Fetching resource sets from: {endpoint}")
        data = get_api_data(endpoint, headers)
        if not data:
            break
        resource_sets.extend(data.get("resource-sets", []))
        next_link = data.get("_links", {}).get("next", {}).get("href")
        endpoint = next_link if next_link else None
    return resource_sets

# def fetch_resource_set_resources(okta_domain, resource_set_id, headers):
#     """
#     Fetch resources for a given resource set.
#     Returns a list of endpoints derived from the resource's self link.
#     Outputs debug information when expected keys are missing.
#     """
#     endpoint = f"https://{okta_domain}/api/v1/iam/resource-sets/{resource_set_id}/resources"
#     print(f"Fetching resource set resources from: {endpoint}")
#     data = get_api_data(endpoint, headers)
#     resources = []
#     if data and "resources" in data:
#         for res in data["resources"]:
#             # Check for the _links object.
#             links = res.get("_links")
#             if not links:
#                 print(f"DEBUG: Resource {res.get('id')} missing '_links'. Full resource: {json.dumps(res, indent=2)}")
#                 continue
#             # Check for the self link.
#             self_link_obj = links.get("self")
#             if not self_link_obj:
#                 print(f"DEBUG: Resource {res.get('id')} missing 'self' link. Full _links: {json.dumps(links, indent=2)}")
#                 continue
#             href = self_link_obj.get("href")
#             if href:
#                 resources.append(href)
#             else:
#                 print(f"DEBUG: Resource {res.get('id')} has a 'self' link but no 'href'. Full self object: {json.dumps(self_link_obj, indent=2)}")
#     else:
#         print(f"DEBUG: No 'resources' key in response for resource set {resource_set_id}. Full response: {json.dumps(data, indent=2)}")
#     return resources

def fetch_resource_set_resources(okta_domain, resource_set_id, headers):
    """
    Fetch resources for a given resource set.
    Returns a list of endpoints derived from the resource's self link.
    Outputs enhanced debug information when expected keys are missing.
    """
    endpoint = f"https://{okta_domain}/api/v1/iam/resource-sets/{resource_set_id}/resources"
    print(f"Fetching resource set resources from: {endpoint}")
    data = get_api_data(endpoint, headers)
    resources = []
    if data and "resources" in data:
        for res in data["resources"]:
            # Check for the _links object.
            links = res.get("_links")
            if not links:
                print(f"DEBUG: Resource {res.get('id')} (ORN: {res.get('orn')}) missing '_links'. Full resource: {json.dumps(res, indent=2)}")
                continue
            # Check for the self link.
            self_link_obj = links.get("self")
            if not self_link_obj:
                print(f"DEBUG: Resource {res.get('id')} (ORN: {res.get('orn')}) missing 'self' link. Full _links: {json.dumps(links, indent=2)}")
                continue
            href = self_link_obj.get("href")
            if href:
                resources.append(href)
            else:
                print(f"DEBUG: Resource {res.get('id')} (ORN: {res.get('orn')}) has a 'self' link but no 'href'. Full self object: {json.dumps(self_link_obj, indent=2)}")
    else:
        print(f"DEBUG: No 'resources' key in response for resource set {resource_set_id}. Full response: {json.dumps(data, indent=2)}")
    return resources

def generate_terraform_roles(roles, tf_file, terraform_format, okta_domain, headers):
    """Generate Terraform blocks for Okta custom roles, including permissions."""
    with open(tf_file, "a") as f:
        f.write("# Terraform configuration for Okta Custom Admin Roles\n\n")
        for role in roles:
            role_id = role.get("id")
            label = role.get("label")
            description = role.get("description", "")
            permissions = fetch_role_permissions(okta_domain, role_id, headers)
            
            if terraform_format == "hcl":
                perms_formatted = ", ".join([f'"{perm}"' for perm in permissions])
                terraform_block = f'''
resource "okta_admin_role_custom" "role_{role_id}" {{
  label       = "{label}"
  description = "{description}"
  permissions = [{perms_formatted}]
}}

'''
            else:
                terraform_block = json.dumps({
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
            f.write(terraform_block)

def generate_terraform_resource_sets(resource_sets, tf_file, terraform_format, okta_domain, headers):
    """Generate Terraform blocks for Okta Resource Sets including their resources."""
    with open(tf_file, "a") as f:
        f.write("# Terraform configuration for Okta Resource Sets\n\n")
        for rs in resource_sets:
            rs_id = rs.get("id")
            label = rs.get("label")
            description = rs.get("description", "")
            endpoints = fetch_resource_set_resources(okta_domain, rs_id, headers)
            if terraform_format == "hcl":
                endpoints_formatted = ", ".join([f'"{ep}"' for ep in endpoints])
                terraform_block = f'''
resource "okta_resource_set" "rs_{rs_id}" {{
  label       = "{label}"
  description = "{description}"
  resources   = [{endpoints_formatted}]
}}

'''
            else:
                terraform_block = json.dumps({
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
            f.write(terraform_block)

def main():
    parser = argparse.ArgumentParser(description="Generate Terraform config from Okta API data.")
    parser.add_argument("--subdomain", required=True,
                        help="Okta subdomain (e.g. eqtpartners)")
    parser.add_argument("--domain-flag", choices=["default", "emea", "preview", "gov", "mil"], default="default",
                        help="Domain flag to determine the Okta domain suffix")
    parser.add_argument("--api-token", help="Okta API token", required=True)
    parser.add_argument("--output-prefix", help="Prefix for the output Terraform file", default="okta")
    parser.add_argument("--terraform-format", choices=["hcl", "json"], default="hcl",
                        help="Output format for Terraform configuration (hcl or json)")
    
    args = parser.parse_args()

    okta_domain = get_okta_domain(args.subdomain, args.domain_flag)
    print(f"Using Okta domain: {okta_domain}")

    headers = {
        "Authorization": f"SSWS {args.api_token}",
        "Accept": "application/json"
    }

    tf_file = f"{args.output_prefix}_resources.tf"
    with open(tf_file, "w") as f:
        f.write("# Generated Terraform configuration for Okta resources\n\n")

    roles = fetch_roles(okta_domain, headers)
    resource_sets = fetch_resource_sets(okta_domain, headers)

    generate_terraform_roles(roles, tf_file, args.terraform_format, okta_domain, headers)
    generate_terraform_resource_sets(resource_sets, tf_file, args.terraform_format, okta_domain, headers)

    print(f"Terraform configuration written to {tf_file}")

if __name__ == "__main__":
    main()