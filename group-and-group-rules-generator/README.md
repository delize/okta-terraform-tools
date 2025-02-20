# What is this?

This generator will generate resource and import blocks, using imports in a per environment setup, so that you don't have to write 1000s of resources in Terraform Manually.

# How to use

## Initial Steps

1. Use `groups.py` and `group-rules.py` to generate the necessary files from the API for each environment (EG: `preview` and `production`)
2. (Optional) If you have any pre-existing Terraformed Resources, you can exclude them from the CSV files that were generated
3. Run `terraform-generator.py` to create a terraform file that contains:
   1. Import Resource Blocks
   2. Groups
   3. Group Rules
4. Run `terraform fmt` and `terraform validate`, if necessary to verify that the file is working correctly
5. Run `terraform plan`, then subsequently run `terraform apply`

## Group Resource Usage

```bash
$ python3 group-and-group-rules-generator/groups.py --help                                                                                                                             [22:12:49]
usage: groups.py [-h] --subdomain SUBDOMAIN [--domain {default,emea,preview,gov,mil}] [--token TOKEN] [--output OUTPUT]

Export Okta Groups to CSV with Dynamic Headers

options:
  -h, --help            show this help message and exit
  --subdomain SUBDOMAIN
                        Your Okta subdomain (e.g., yourcompany)
  --domain {default,emea,preview,gov,mil}
                        Select Okta domain
  --token TOKEN         Okta API token (can also be set via OKTA_API_TOKEN env variable)
  --output OUTPUT       Output CSV file
```
## Group Rules Resource Usage


```bash
$ python3 group-and-group-rules-generator/group-rules.py --help                                                                                                                        [22:20:13]
usage: group-rules.py [-h] --subdomain SUBDOMAIN [--domain {default,emea,preview,gov,mil}] [--token TOKEN] [--output OUTPUT]

Export Okta Group Rules to CSV with Dynamic Headers

options:
  -h, --help            show this help message and exit
  --subdomain SUBDOMAIN
                        Your Okta subdomain (e.g., yourcompany)
  --domain {default,emea,preview,gov,mil}
                        Select Okta domain
  --token TOKEN         Okta API token (can also be set via OKTA_API_TOKEN env variable)
  --output OUTPUT       Output CSV file
```