# Python Script Summary

## What This Does
- **Domain Construction:**  
  - Constructs the Okta domain using either a full domain (stripped of protocol) or a combination of subdomain and domain.
- **Organization Information:**  
  - Fetches organization details from the Okta well-known endpoint to determine the pipeline type (OIE vs. Classic).
- **Policy and Rule Fetching:**  
  - Retrieves MFA_ENROLL policies from the Okta API using the provided API token.
  - For each policy, fetches the associated rules.
- **Terraform Configuration Generation:**  
  - Generates Terraform resource blocks for each MFA policy and its rules.
  - Differentiates resource types based on whether the policy is default (system policy) or not.
  - Creates import blocks for each resource to map to the actual Okta IDs.
  - Generates data blocks for Okta groups referenced in policies.
- **Post-Processing:**  
  - Optionally runs `terraform fmt` on the output file to format the generated Terraform code.

## APIs It Calls
- **Organization Info:**  
  - **Endpoint:** `https://{okta_domain}/.well-known/okta-organization`  
  - **Method:** GET  
  - **Purpose:** Determines if the organization is using the IDX (OIE) pipeline.
- **Policies:**  
  - **Endpoint:** `https://{okta_domain}/api/v1/policies` with parameter `type=MFA_ENROLL`  
  - **Method:** GET  
  - **Headers:**  
    - `Authorization: SSWS {api_token}`  
    - `Accept: application/json`
- **Rules:**  
  - **Endpoint:** `https://{okta_domain}/api/v1/policies/{policy_id}/rules`  
  - **Method:** GET  
  - **Headers:**  
    - `Authorization: SSWS {api_token}`  
    - `Accept: application/json`

## What the Arguments Are For
- **Domain Configuration:**  
  - `--subdomain`: Subdomain to construct the Okta domain.  
  - `--domain`: Domain to construct the Okta domain.  
  - `--full-domain`: Full domain (without protocol) that overrides subdomain/domain settings.
- **API Authentication:**  
  - `--api-token`: (Required) API token for authenticating Okta API requests.
- **Output and Formatting:**  
  - `--output`: Specifies the output file name for the Terraform configuration (default is "main.tf").  
  - `--terraform-fmt`: If set, runs `terraform fmt` on the generated file to format the Terraform code.

## What the Terraform Generated File Will Look Like
- **Data Blocks for Groups:**  
  - Contains data blocks for each Okta group referenced in the policy conditions.
- **Import Blocks:**  
  - Import blocks are generated for every policy and rule resource to map the Terraform resource to the corresponding Okta resource ID.
- **Resource Blocks:**
  - **For Policies:**
    - **Non-default Policies:**  
      - Uses the resource type `okta_policy_mfa` with attributes such as name, description, status, priority, and MFA settings.
      - Includes a reference to groups (if any) using data block lookups.
    - **Default (System) Policies:**  
      - Uses the resource type `okta_policy_mfa_default` with MFA settings.
  - **For Rules:**
    - **OIE Organizations:**  
      - Generates `okta_policy_rule_mfa` resource blocks with properties like enrollment method, network settings, priority, status, and excluded users.
      - References the parent policy using Terraform interpolation.
    - **Classic Organizations:**  
      - Generates `okta_policy_mfa_rule` resource blocks embedding conditions and actions as JSON.