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
It is recommended to use a virtual environment:
```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

(If a requirements.txt file is not provided, the tools primarily use the standard libraries along with requests.)