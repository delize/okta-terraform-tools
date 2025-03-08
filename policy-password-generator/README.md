# Python Script Summary

## What This Does
- **Terraform Configuration Generation:**
  - Generates Terraform configuration for Okta PASSWORD policies and their rules.
  - Differentiates between default (system) and non-default password policies.
- **Data Retrieval:**
  - Fetches all PASSWORD policies from the Okta API.
  - For each policy, retrieves associated rules.
- **Resource Generation:**
  - Produces Terraform resource blocks for policies and policy rules.
  - Creates import blocks for each resource to map the Terraform resource to its corresponding Okta ID.
  - Generates data blocks for Okta groups referenced in the policies.
- **Post-Processing:**
  - Optionally formats the output file using `terraform fmt` to ensure proper formatting.

## APIs It Calls
- **Okta Policies API:**
  - **Endpoint:** `/api/v1/policies` with query parameter `type=PASSWORD`
  - **Method:** GET
  - **Headers:**  
    - `Authorization: SSWS {api_token}`
- **Okta Policy Rules API:**
  - **Endpoint:** `/api/v1/policies/{policy_id}/rules`
  - **Method:** GET
  - **Headers:**  
    - `Authorization: SSWS {api_token}`

## What the Arguments Are For
- **Domain Configuration:**
  - `--full-domain`: Provide your complete Okta domain (e.g., `andrewdoering.okta.com`).
  - `--subdomain` & `--domain`: Alternatively, specify the subdomain and domain separately.
- **API Authentication:**
  - `--api-token`: (Required) API token used for authenticating Okta API requests.
- **Output and Formatting:**
  - `--output`: The file path where the generated Terraform configuration will be written.
  - `--terraform-fmt`: If provided, runs `terraform fmt` on the generated file to format the code.

## What the Terraform Generated File Will Look Like
- **Data Blocks for Groups:**
  - Contains data blocks for each Okta group referenced in the policy conditions, enabling lookups (e.g., `data.okta_group.group_<group_id>.id`).
- **Import Blocks:**
  - Import blocks are created for every policy and rule resource to link the Terraform resource with its corresponding Okta resource ID.
- **Resource Blocks:**
  - **Policy Resource Blocks:**
    - Uses `okta_policy_password_default` for default (system) policies and `okta_policy_password` for non-default ones.
    - Includes attributes such as name, description, status, priority, and group references.
    - For non-default policies, maps additional settings (password complexity, history, age, lockout settings, recovery email token, etc.).
  - **Policy Rule Resource Blocks:**
    - Generated using `okta_policy_rule_password`, referencing the parent policy via Terraform interpolation.
    - Contains attributes for rule name, priority, status, network connection, actions (password change, reset, unlock), and user exclusions.