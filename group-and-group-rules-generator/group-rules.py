import requests
import csv
import os
import argparse

def get_okta_domain(subdomain, domain_flag):
    domain_map = {
        "default": "okta.com",
        "emea": "okta-emea.com",
        "preview": "oktapreview.com",
        "gov": "okta-gov.com",
        "mil": "okta.mil"
    }
    domain = domain_map.get(domain_flag, "okta.com")
    return f"https://{subdomain}.{domain}"

def fetch_okta_group_rules(okta_domain, api_token):
    """Fetch all group rules from Okta API with pagination."""
    url = f"{okta_domain}/api/v1/groups/rules"
    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}
    rules = []
    
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Error fetching group rules: {response.status_code}, {response.text}")
            return []
        
        data = response.json()
        rules.extend(data)

        url = None
        if "link" in response.headers:
            links = response.headers["link"].split(", ")
            for link in links:
                if 'rel="next"' in link:
                    url = link[link.find("<") + 1: link.find(">")]
    
    return rules

def process_and_export_group_rules(rules, output_csv="okta_group_rules.csv"):
    """Process group rules dynamically and export them to CSV."""
    
    headers = set(["id", "name", "status", "created", "lastUpdated", "allGroupsValid"])
    for rule in rules:
        conditions = rule.get("conditions", {})
        actions = rule.get("actions", {}).get("assignUserToGroups", {})
        embedded = rule.get("_embedded", {}).get("groupIdToGroupNameMap", {})
        
        # Add dynamic headers from nested JSON fields
        if "people" in conditions:
            headers.update(["excludedUsers", "excludedGroups"])
        if "expression" in conditions:
            headers.update(conditions["expression"].keys())
        headers.update(actions.keys())
        headers.update(embedded.keys())
    
    headers = sorted(headers)  # Sort headers for consistency
    
    with open(output_csv, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()

        for rule in rules:
            row = {
                "id": rule.get("id", "Not Available"),
                "name": rule.get("name", "Not Available"),
                "status": rule.get("status", "Not Available"),
                "created": rule.get("created", "Not Available"),
                "lastUpdated": rule.get("lastUpdated", "Not Available"),
                "allGroupsValid": "true" if rule.get("allGroupsValid", False) else "false"
            }
            
            conditions = rule.get("conditions", {})
            actions = rule.get("actions", {}).get("assignUserToGroups", {})
            embedded = rule.get("_embedded", {}).get("groupIdToGroupNameMap", {})
            
            if "people" in conditions:
                row["excludedUsers"] = ",".join(conditions["people"].get("users", {}).get("exclude", [])) or "Not Available"
                row["excludedGroups"] = ",".join(conditions["people"].get("groups", {}).get("exclude", [])) or "Not Available"
            
            if "expression" in conditions:
                for key in conditions["expression"]:
                    row[key] = conditions["expression"].get(key, "Not Available")
            
            for key in actions:
                row[key] = ",".join(actions.get(key, [])) or "Not Available"
            
            for key, value in embedded.items():
                row[key] = value
            
            writer.writerow(row)
    
    print(f"CSV file '{output_csv}' has been created successfully.")

def main():
    parser = argparse.ArgumentParser(description="Export Okta Group Rules to CSV with Dynamic Headers")
    parser.add_argument("--subdomain", required=True, help="Your Okta subdomain (e.g., yourcompany)")
    parser.add_argument("--domain", choices=["default", "emea", "preview", "gov", "mil"], default="default", help="Select Okta domain")
    parser.add_argument("--token", help="Okta API token (can also be set via OKTA_API_TOKEN env variable)")
    parser.add_argument("--output", default="okta_group_rules.csv", help="Output CSV file")
    
    args = parser.parse_args()
    
    api_token = args.token or os.getenv("OKTA_API_TOKEN")
    if not api_token:
        print("Error: API token must be provided either as an argument or via the OKTA_API_TOKEN environment variable.")
        exit(1)
    
    okta_domain = get_okta_domain(args.subdomain, args.domain)
    rules = fetch_okta_group_rules(okta_domain, api_token)
    if rules:
        process_and_export_group_rules(rules, args.output)

if __name__ == "__main__":
    main()