#!/usr/bin/env python3
import argparse
import json
import requests
import subprocess
import os
import re

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

def fetch_brands(base_url, api_token):
    """
    Fetch brands from the Okta API endpoint.
    """
    url = f"{base_url}/api/v1/brands"
    headers = {"Authorization": f"SSWS {api_token}"} if api_token else {}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def fetch_themes_from_brand(brand, api_token):
    """
    Fetch themes for a given brand using the URL in the brand's _links.
    """
    theme_url = brand.get("_links", {}).get("themes", {}).get("href")
    if not theme_url:
        return []
    headers = {"Authorization": f"SSWS {api_token}"} if api_token else {}
    response = requests.get(theme_url, headers=headers)
    response.raise_for_status()
    return response.json()

def fetch_app(base_url, app_id, api_token):
    """
    Fetch application details from the Okta Application API.
    """
    url = f"{base_url}/api/v1/apps/{app_id}"
    headers = {"Authorization": f"SSWS {api_token}"} if api_token else {}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def fetch_domains(base_url, api_token):
    """
    Fetch domains from the Okta API endpoint.
    Returns a list of domain objects.
    """
    url = f"{base_url}/api/v1/domains"
    headers = {"Authorization": f"SSWS {api_token}"} if api_token else {}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()
    return data.get("domains", [])

def sanitize_tf_name(name):
    """
    Sanitize a string to be used as a Terraform resource name:
    Lowercases, replaces spaces with underscores, and removes non-alphanumeric characters.
    """
    name = name.lower().replace(" ", "_")
    return re.sub(r'[^a-z0-9_]', '', name)

def generate_brand_tf(brand, env):
    """
    Generates a Terraform resource block for an okta_brand.
    Returns a tuple: (resource_block, import_block)
    The resource name is suffixed with the environment.
    """
    res_lines = []
    res_lines.append(f'resource "okta_brand" "brand_{brand["id"]}_{env}" {{')
    res_lines.append(f'  count = var.CONFIG == "{env}" ? 1 : 0')
    res_lines.append(f'  name = "{brand["name"]}"')
    res_lines.append(f'  remove_powered_by_okta = {str(brand["removePoweredByOkta"]).lower()}')
    if brand.get("customPrivacyPolicyUrl") is not None:
        res_lines.append(f'  custom_privacy_policy_url = "{brand["customPrivacyPolicyUrl"]}"')
    res_lines.append(f'  agree_to_custom_privacy_policy = {str(brand["agreeToCustomPrivacyPolicy"]).lower()}')
    if "defaultApp" in brand and brand["defaultApp"]:
        app = brand["defaultApp"]
        if app.get("appInstanceId"):
            if env == "prod":
                res_lines.append(f'  default_app_app_instance_id = data.okta_app.app_{app["appInstanceId"]}_by_label[0].id')
            else:
                res_lines.append(f'  # default_app_app_instance_id omitted for preview environment')
        if app.get("appLinkName"):
            res_lines.append(f'  default_app_app_link_name = "{app["appLinkName"]}"')
        if app.get("classicApplicationUri"):
            res_lines.append(f'  default_app_classic_application_uri = "{app["classicApplicationUri"]}"')
    res_lines.append("}")
    resource_block = "\n".join(res_lines)
    import_block = (
        f'import {{\n'
        f'  for_each = var.CONFIG == "{env}" ? toset(["{env}"]) : []\n'
        f'  to       = okta_brand.brand_{brand["id"]}_{env}[0]\n'
        f'  id       = "{brand["id"]}"\n'
        f'}}\n'
    )
    return resource_block, import_block

def generate_theme_tf(theme, brand_id, env):
    """
    Generates a Terraform resource block for an okta_theme.
    Returns a tuple: (resource_block, import_block)
    The resource name is suffixed with the environment, and the brand reference is updated accordingly.
    """
    res_lines = []
    res_lines.append(f'resource "okta_theme" "theme_{theme["id"]}_{env}" {{')
    res_lines.append(f'  count = var.CONFIG == "{env}" ? 1 : 0')
    # Note the index [0] for the referenced brand resource.
    res_lines.append(f'  brand_id = okta_brand.brand_{brand_id}_{env}[0].id')
    if theme.get("logo"):
        res_lines.append(f'  logo = "{theme["logo"]}"')
    if theme.get("favicon"):
        res_lines.append(f'  favicon = "{theme["favicon"]}"')
    if theme.get("backgroundImage"):
        res_lines.append(f'  background_image = "{theme["backgroundImage"]}"')
    if theme.get("primaryColorHex"):
        res_lines.append(f'  primary_color_hex = "{theme["primaryColorHex"]}"')
    if theme.get("primaryColorContrastHex"):
        res_lines.append(f'  primary_color_contrast_hex = "{theme["primaryColorContrastHex"]}"')
    if theme.get("secondaryColorHex"):
        res_lines.append(f'  secondary_color_hex = "{theme["secondaryColorHex"]}"')
    if theme.get("secondaryColorContrastHex"):
        res_lines.append(f'  secondary_color_contrast_hex = "{theme["secondaryColorContrastHex"]}"')
    if theme.get("signInPageTouchPointVariant"):
        res_lines.append(f'  sign_in_page_touch_point_variant = "{theme["signInPageTouchPointVariant"]}"')
    if theme.get("endUserDashboardTouchPointVariant"):
        res_lines.append(f'  end_user_dashboard_touch_point_variant = "{theme["endUserDashboardTouchPointVariant"]}"')
    if theme.get("errorPageTouchPointVariant"):
        res_lines.append(f'  error_page_touch_point_variant = "{theme["errorPageTouchPointVariant"]}"')
    if theme.get("emailTemplateTouchPointVariant"):
        res_lines.append(f'  email_template_touch_point_variant = "{theme["emailTemplateTouchPointVariant"]}"')
    res_lines.append("}")
    resource_block = "\n".join(res_lines)
    import_block = (
        f'import {{\n'
        f'  for_each = var.CONFIG == "{env}" ? toset(["{env}"]) : []\n'
        f'  to       = okta_theme.theme_{theme["id"]}_{env}[0]\n'
        f'  id       = "{theme["id"]}"\n'
        f'}}\n'
    )
    return resource_block, import_block

def generate_domain_tf(domain, env):
    """
    Generates a Terraform resource block for an okta_domain.
    Returns a tuple: (resource_block, import_block)
    The resource name is suffixed with the environment.
    """
    res_lines = []
    res_lines.append(f'resource "okta_domain" "domain_{domain["id"]}_{env}" {{')
    res_lines.append(f'  count = var.CONFIG == "{env}" ? 1 : 0')
    res_lines.append(f'  name = "{domain["domain"]}"')
    if domain.get("brandId"):
        res_lines.append(f'  brand_id = "{domain["brandId"]}"')
    if domain.get("certificateSourceType"):
        res_lines.append(f'  certificate_source_type = "{domain["certificateSourceType"]}"')
    res_lines.append("}")
    resource_block = "\n".join(res_lines)
    import_block = (
        f'import {{\n'
        f'  for_each = var.CONFIG == "{env}" ? toset(["{env}"]) : []\n'
        f'  to       = okta_domain.domain_{domain["id"]}_{env}[0]\n'
        f'  id       = "{domain["id"]}"\n'
        f'}}\n'
    )
    return resource_block, import_block

def generate_app_data_block(app_id, app_label):
    """
    Generates a Terraform data block for an okta_app using a search by label.
    (This block is production-only.)
    """
    lines = []
    lines.append(f'data "okta_app" "app_{app_id}_by_label" {{')
    lines.append(f'  count = var.CONFIG == "prod" ? 1 : 0')
    lines.append(f'  label = "{app_label}"')
    lines.append("}")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Generate Terraform configuration from Okta API data")
    parser.add_argument("--preview-subdomain", help="Preview subdomain", default="preview")
    parser.add_argument("--prod-subdomain", help="Production subdomain", default="prod")
    parser.add_argument("--preview-domain-flag", help="Preview domain flag (e.g., preview)", default="preview")
    parser.add_argument("--prod-domain-flag", help="Production domain flag (e.g., default)", default="default")
    parser.add_argument("--preview-full-url", help="Preview full URL for Okta API", default="")
    parser.add_argument("--prod-full-url", help="Production full URL for Okta API", default="")
    parser.add_argument("--preview-api-token", help="Preview API token", default="")
    parser.add_argument("--prod-api-token", help="Production API token", default="")
    parser.add_argument("--output-file", help="Output Terraform file", default="output.tf")
    parser.add_argument("--terraform-fmt", action="store_true", help="Run 'terraform fmt' on the generated file")
    args = parser.parse_args()

    if args.preview_full_url:
        preview_base_url = args.preview_full_url.rstrip("/")
    else:
        preview_base_url = f"https://{get_okta_domain(args.preview_subdomain, args.preview_domain_flag)}"
    if args.prod_full_url:
        prod_base_url = args.prod_full_url.rstrip("/")
    else:
        prod_base_url = f"https://{get_okta_domain(args.prod_subdomain, args.prod_domain_flag)}"

    tf_content = "# Terraform configuration generated by script\n\n"
    tf_content += "locals {\n"
    tf_content += f'  okta_preview_url = "{preview_base_url}"\n'
    tf_content += f'  okta_prod_url = "{prod_base_url}"\n'
    tf_content += '  is_prod = var.CONFIG == "prod"\n'
    tf_content += "}\n\n"

    resource_blocks = []
    import_blocks = []
    prod_app_map = {}  # app_id -> app_label

    # Process both environments: preview and prod.
    for env, base_url, token in [
        ("preview", preview_base_url, args.preview_api_token),
        ("prod", prod_base_url, args.prod_api_token)
    ]:
        if token:
            try:
                brands = fetch_brands(base_url, token)
            except Exception as e:
                print(f"Error fetching brands for {env} environment: {e}")
                continue

            for brand in brands:
                res, imp = generate_brand_tf(brand, env)
                resource_blocks.append(f"# {env.capitalize()} Environment - Brand {brand['id']}\n" + res)
                import_blocks.append(imp)
                if env == "prod" and "defaultApp" in brand and brand["defaultApp"]:
                    app = brand["defaultApp"]
                    if app.get("appInstanceId"):
                        try:
                            app_detail = fetch_app(prod_base_url, app["appInstanceId"], args.prod_api_token)
                            app_label = app_detail.get("label", app["appInstanceId"])
                            prod_app_map[app["appInstanceId"]] = app_label
                        except Exception as e:
                            print(f"Error fetching application details for app_id {app['appInstanceId']}: {e}")
                try:
                    themes = fetch_themes_from_brand(brand, token)
                except Exception as e:
                    print(f"Error fetching themes for brand {brand['id']} in {env} environment: {e}")
                    themes = []
                for theme in themes:
                    res, imp = generate_theme_tf(theme, brand["id"], env)
                    resource_blocks.append(f"# {env.capitalize()} Environment - Theme {theme['id']} (Brand {brand['id']})\n" + res)
                    import_blocks.append(imp)

            try:
                domains = fetch_domains(base_url, token)
            except Exception as e:
                print(f"Error fetching domains for {env} environment: {e}")
                domains = []
            if domains:
                for domain in domains:
                    res, imp = generate_domain_tf(domain, env)
                    resource_blocks.append(f"# {env.capitalize()} Environment - Domain {domain['id']}\n" + res)
                    import_blocks.append(imp)

    data_blocks = "# Data blocks for Okta Applications (Production only, searched by label)\n\n"
    if args.prod_api_token:
        for app_id, app_label in prod_app_map.items():
            data_blocks += generate_app_data_block(app_id, app_label) + "\n\n"
    else:
        data_blocks += "# No production API token provided for application lookup\n\n"

    tf_content += data_blocks + "\n".join(resource_blocks)
    tf_content += "\n\n# =====================================================\n"
    tf_content += "# Consolidated Import Block Section\n"
    tf_content += "# =====================================================\n\n"
    tf_content += "\n".join(import_blocks)

    with open(args.output_file, "w") as f:
        f.write(tf_content)
    print(f"Terraform configuration written to {args.output_file}")

    if args.terraform_fmt:
        try:
            subprocess.run(["terraform", "fmt", args.output_file], check=True)
            print("Terraform file formatted using 'terraform fmt'.")
        except Exception as e:
            print(f"Error running 'terraform fmt': {e}")

if __name__ == "__main__":
    main()