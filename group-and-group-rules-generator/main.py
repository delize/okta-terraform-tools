import argparse
import os
from groups import get_okta_domain, fetch_okta_groups, process_and_export_groups
from group_rules import get_okta_domain as get_okta_domain_rules, fetch_okta_group_rules, process_and_export_rules
from terraform_generator import load_csv, generate_terraform_resources, generate_terraform_imports

def run_terraform(args):
    """Run the Terraform Generator with provided CSV file paths."""
    files = {
        "prod_groups": args.prod_groups,
        "prod_rules": args.prod_rules,
        "preview_groups": args.preview_groups,  # Optional
        "preview_rules": args.preview_rules,  # Optional
    }

    # Load only existing CSV files
    group_data = {}
    group_rule_data = {}

    for env in ["prod", "preview"]:
        if files[f"{env}_groups"]:
            group_data[env] = load_csv(files[f"{env}_groups"])
        else:
            print(f"⚠️  Skipping {env}_groups: No file provided.")

        if files[f"{env}_rules"]:
            group_rule_data[env] = load_csv(files[f"{env}_rules"])
        else:
            print(f"⚠️  Skipping {env}_rules: No file provided.")

    # Generate Terraform configuration
    terraform_output = generate_terraform_resources(group_data, group_rule_data)
    import_output = generate_terraform_imports(group_data, group_rule_data)

    # Save output files
    with open("generated-terraform.tf", "w") as f:
        f.write(terraform_output)
    with open("terraform-imports.tf", "w") as f:
        f.write(import_output)

    print("✅ Terraform files successfully generated!")

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

    # Terraform Command (✅ Preview files are now optional!)
    parser_terraform = subparsers.add_parser("terraform", help="Generate Terraform configuration from Okta data")
    parser_terraform.add_argument("--prod_groups", type=str, required=True, help="File path for production groups CSV")
    parser_terraform.add_argument("--prod_rules", type=str, required=True, help="File path for production rules CSV")
    parser_terraform.add_argument("--preview_groups", type=str, required=False, help="(Optional) File path for preview groups CSV")
    parser_terraform.add_argument("--preview_rules", type=str, required=False, help="(Optional) File path for preview rules CSV")
    parser_terraform.set_defaults(func=run_terraform)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()