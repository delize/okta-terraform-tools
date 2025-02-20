import argparse
import os
from groups import get_okta_domain, fetch_okta_groups, process_and_export_groups
from group_rules import get_okta_domain as get_okta_domain_rules, fetch_okta_group_rules, process_and_export_rules
from terraform_generator import generate_terraform_resources, generate_terraform_imports, group_data, group_rule_data

def run_groups(args):
    """Run the Okta Groups export."""
    api_token = args.token or os.getenv("OKTA_API_TOKEN")
    if not api_token:
        print("Error: API token must be provided either as an argument or via the OKTA_API_TOKEN environment variable.")
        return

    okta_domain = get_okta_domain(args.subdomain, args.domain)
    groups = fetch_okta_groups(okta_domain, api_token)
    
    if groups:
        process_and_export_groups(groups, args.output)
    else:
        print("No groups found.")

def run_group_rules(args):
    """Run the Okta Group Rules export."""
    api_token = args.token or os.getenv("OKTA_API_TOKEN")
    if not api_token:
        print("Error: API token must be provided either as an argument or via the OKTA_API_TOKEN environment variable.")
        return

    okta_domain = get_okta_domain_rules(args.subdomain, args.domain)
    rules = fetch_okta_group_rules(okta_domain, api_token)

    if rules:
        process_and_export_rules(rules, args.output)
    else:
        print("No group rules found.")

def run_terraform(args):
    """Run the Terraform Generator."""
    terraform_output = generate_terraform_resources(group_data, group_rule_data)
    import_output = generate_terraform_imports(group_data, group_rule_data)

    resource_file = "generated-terraform.tf"
    import_file = "terraform-imports.tf"
    
    with open(resource_file, "w") as f:
        f.write(terraform_output)

    with open(import_file, "w") as f:
        f.write(import_output)

    print(f"Terraform resource file generated: {resource_file}")
    print(f"Terraform import file generated: {import_file}")

def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(description="Unified CLI for Okta Group Management and Terraform Generation")

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Groups Command
    parser_groups = subparsers.add_parser("groups", help="Fetch and export Okta groups")
    parser_groups.add_argument("--subdomain", required=True, help="Your Okta subdomain (e.g., yourcompany)")
    parser_groups.add_argument("--domain", choices=["default", "emea", "preview", "gov", "mil"], default="default", help="Select Okta domain")
    parser_groups.add_argument("--token", help="Okta API token (can also be set via OKTA_API_TOKEN env variable)")
    parser_groups.add_argument("--output", default="okta_groups.csv", help="Output CSV file")
    parser_groups.set_defaults(func=run_groups)

    # Group Rules Command
    parser_group_rules = subparsers.add_parser("group-rules", help="Fetch and export Okta group rules")
    parser_group_rules.add_argument("--subdomain", required=True, help="Your Okta subdomain (e.g., yourcompany)")
    parser_group_rules.add_argument("--domain", choices=["default", "emea", "preview", "gov", "mil"], default="default", help="Select Okta domain")
    parser_group_rules.add_argument("--token", help="Okta API token (can also be set via OKTA_API_TOKEN env variable)")
    parser_group_rules.add_argument("--output", default="okta_group_rules.csv", help="Output CSV file")
    parser_group_rules.set_defaults(func=run_group_rules)

    # Terraform Command
    parser_terraform = subparsers.add_parser("terraform", help="Generate Terraform configuration from Okta data")
    parser_terraform.set_defaults(func=run_terraform)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()