# Okta Terraform Tools

This repository contains a collection of Python-based tools for generating Terraform configuration from Okta API data. These tools help automate the process of importing and managing Okta resources in Terraform. They are especially useful for organizations that have a large amount of data they would like to import into Terraform and would prefer to not do certain aspects by hand (for example, writing all groups and group rules into Terraform).


# Getting Started

## Prerequisites

- Python 3 – The tools are written in Python.
- Terraform – To run terraform fmt and manage Terraform configurations.
- Okta API Token – An API token with the required permissions to fetch Okta policies and related data.

## Installation

1.	Clone the Repository:
```sh
git clone https://github.com/yourusername/okta-terraform-tools.git
cd okta-terraform-tools
```
2.	Install Required Python Libraries:
It is recommended to use a virtual environment, in the folder you would like to run:
```sh
python3 -m venv ./
source venv/bin/activate
pip install -r requirements.txt
```
(If a requirements.txt file is not provided, the tools primarily use the standard libraries along with requests.)


# Okta Terraform Tools - Argument Summary

Each of the sections below outlines the arguments for each of the folder's python scripts.
---

## Admin Rules and Resources

- **--subdomain** (required)  
  *Okta subdomain (e.g. "mydomain")*

- **--domain-flag**  
  *Choices: "default", "emea", "preview", "gov", "mil" (default: "default")*  
  *Determines the Okta domain suffix.*

- **--api-token** (required)  
  *Okta API token*

- **--output-prefix**  
  *Prefix for the output Terraform file (default: "okta")*

- **--terraform-format**  
  *Choices: "hcl", "json" (default: "hcl")*  
  *Specifies the output format for Terraform configuration.*

- **--all-groups**  
  *Iterate over all groups to fetch group roles.*

- **--all-users**  
  *Iterate over all users to fetch user roles.*

- **--tf-fmt**  
  *Run `terraform fmt` on the generated file.*

---

## Brand Theme Generator

- **--preview-subdomain**  
  *Preview subdomain (default: "preview")*

- **--prod-subdomain**  
  *Production subdomain (default: "prod")*

- **--preview-domain-flag**  
  *Preview domain flag (default: "preview")*

- **--prod-domain-flag**  
  *Production domain flag (default: "default")*

- **--preview-full-url**  
  *Preview full URL for Okta API (default: empty)*

- **--prod-full-url**  
  *Production full URL for Okta API (default: empty)*

- **--preview-api-token**  
  *Preview API token (default: empty)*

- **--prod-api-token**  
  *Production API token (default: empty)*

- **--output-file**  
  *Output Terraform file (default: "output.tf")*

- **--terraform-fmt**  
  *Run `terraform fmt` on the generated file.*

---

## Global Session Policies

- **--preview-subdomain**  
  *Preview subdomain (default: "preview")*

- **--prod-subdomain**  
  *Production subdomain (default: "prod")*

- **--preview-domain-flag**  
  *Preview domain flag (default: "preview")*

- **--prod-domain-flag**  
  *Production domain flag (default: "default")*

- **--preview-full-url**  
  *Preview full URL for Okta API (default: empty)*

- **--prod-full-url**  
  *Production full URL for Okta API (default: empty)*

- **--preview-api-token**  
  *Preview API token (default: empty)*

- **--prod-api-token**  
  *Production API token (default: empty)*

- **--prod-env**  
  *Environment prefix for production resources (e.g., "prod") (default: "prod")*

- **--preview-env**  
  *Environment prefix for preview resources (e.g., "test") (default: "preview")*

- **--output-file**  
  *Output Terraform file (default: "output.tf")*

- **--run-terraform-fmt**  
  *Run `terraform fmt` on the generated file.*

---

## Groups and Group Rules

- **--subdomain**  
  *Your Okta subdomain (e.g., "yourcompany")*

- **--domain**  
  *Choices: "default", "emea", "preview", "gov", "mil" (default: "default")*  
  *Selects the Okta domain.*

- **--token**  
  *Okta API token (can also be set via the OKTA_API_TOKEN environment variable)*

- **--groups_output**  
  *Output CSV for Okta Groups (default: "okta_groups_dynamic.csv")*

- **--rules_output**  
  *Output CSV for Okta Group Rules (default: "okta_group_rules.csv")*

- **--prod_groups**  
  *File path for prod_groups CSV*

- **--prod_rules**  
  *File path for prod_rules CSV*

- **--preview_groups**  
  *File path for preview_groups CSV*

- **--preview_rules**  
  *File path for preview_rules CSV*

- **--fetch_okta_groups**  
  *Fetch groups from Okta (type=OKTA_GROUP) and export CSV*

- **--fetch_okta_rules**  
  *Fetch group rules from Okta and export CSV*

- **--generate_tf**  
  *Generate Terraform from CSV data*

---

## Move Block Generator

- **Usage Message Only:**  
  *Prints usage for generating move blocks:*

Usage: python generate_move_blocks.py input_file output_file

---

## Policy Auth Signon Generator (Dual Env)

- **--dual**  
*Generate files for both preview (test) and production (prod) environments.*

- **--api-token**  
*API token for single environment mode. Ignored in dual mode.*

- **--full-url**  
*Full base URL for the Okta API (single environment).*

- **--subdomain**  
*Your Okta subdomain for single environment (ignored if --full-url is provided).*

- **--domain-flag**  
*Base domain flag for single environment (default: "default"). Options: default, emea, preview, gov, mil. Ignored if --full-url is provided.*

- **--preview-full-url**  
*Full base URL for the preview Okta API (dual mode).*

- **--preview-subdomain**  
*Preview Okta subdomain (dual mode).*

- **--preview-domain-flag**  
*Domain flag for preview environment (default: "preview").*

- **--preview-api-token**  
*API token for the preview environment. If not provided, will look for OKTA_PREVIEW_API_TOKEN in the environment.*

- **--prod-full-url**  
*Full base URL for the production Okta API (dual mode).*

- **--prod-subdomain**  
*Production Okta subdomain (dual mode).*

- **--prod-domain-flag**  
*Domain flag for production environment (default: "default").*

- **--prod-api-token**  
*API token for the production environment. If not provided, will look for OKTA_PROD_API_TOKEN in the environment.*

- **--test**  
*Run in test mode using local JSON files for policies and rules.*

- **--fmt**  
*Run `terraform fmt` on the generated Terraform files after generation.*

---

## Policy Auth Generator (Single Env)

- **--api-token**  
*Your Okta API token. If not provided, the script will try to read the OKTA_API_TOKEN environment variable.*

- **--subdomain**  
*Your Okta subdomain (e.g., "dev-12345"). Ignored if --full-url is provided.*

- **--domain-flag**  
*Specify the base domain flag (default: "default"). Options: default, emea, preview, gov, mil. Ignored if --full-url is provided.*

- **--full-url**  
*Full base URL for the Okta API. If provided, --subdomain and --domain-flag are ignored.*

- **--test**  
*Run in test mode using local JSON files for policies and rules.*

---

## Policy MFA Enroll Generator

- **--subdomain**  
*Subdomain for the Okta domain.*

- **--domain**  
*Domain for the Okta domain.*

- **--full-domain**  
*Full domain for the Okta domain (without protocol).*

- **--api-token** (required)  
*Okta API token (without the "SSWS " prefix).*

- **--output** (required)  
*Output file name for the Terraform configuration (e.g., "./policy-password.tf").*

- **--terraform-fmt**  
*Run `terraform fmt` on the generated file after generation.*

---

## Policy Password Generator

- **--full-domain** (mutually exclusive with --subdomain)  
*Your full Okta domain (e.g., "andrewdoering.okta.com").*

- **--subdomain** (if --full-domain not provided)  
*Your Okta subdomain (e.g., "andrewdoering"). Use with --domain.*

- **--domain**  
*Your Okta domain (e.g., "okta.com"). Required if --subdomain is provided.*

- **--api-token** (required)  
*Okta API token (without the "SSWS " prefix).*

- **--output** (required)  
*Output Terraform file path (e.g., "./policy-password.tf").*

- **--terraform-fmt**  
*Run `terraform fmt` on the generated file after generation.*

---