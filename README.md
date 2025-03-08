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