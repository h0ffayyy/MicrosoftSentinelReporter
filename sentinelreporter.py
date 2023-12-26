import argparse
import os
import sys
from tqdm import tqdm
from modules.azure import Azure
from modules.attack import Attack

TENANT_ID = os.environ.get("AZURE_TENANT_ID")
SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID")
WORKSPACE_NAME = os.environ.get("AZURE_WORKSPACE_NAME")
RESOURCE_GROUP_NAME = os.environ.get("AZURE_RESOURCE_GROUP_NAME")


def review_attack(AZ):
    alert_rules = AZ.get_alert_rules()
    ATTACK = Attack()

    print("[+] Getting scheduled analytics rules")
    for rule in tqdm(list(alert_rules)):
        if rule.kind == "Scheduled":
            json_data = AZ.get_alert_rule_by_name(rule.name)
            
            tactics = json_data['properties']['tactics']
            techniques = json_data['properties']['techniques']

            if tactics is not None:
                if techniques is not None:
                    for technique in techniques:
                        ATTACK.get_attack_technique_by_name(technique)
            
    print("[+] Creating MITRE ATT&CK Navigator layer")
    ATTACK.create_nav_layer()


def parse_args():
    parser = argparse.ArgumentParser(description='Sentinel Reporter - a python tool to generate reports from Microsoft Sentinel')
    parser.add_argument('--tenant', help='Azure tenant ID')
    parser.add_argument('--subscription_id', help='Azure subscription ID')
    parser.add_argument('--resource_group', help='Microsoft Sentinel resource group name')
    parser.add_argument('--workspace', help='Microsoft Sentinel workspace name')
    args = parser.parse_args()

    if args.tenant is None:
        if TENANT_ID is None:
            print("Please set the AZURE_TENANT_ID environment variable")
            sys.exit(1)
        args.tenant = TENANT_ID

    if args.subscription_id is None:
        if SUBSCRIPTION_ID is None:
            print("Please set the AZURE_SUBSCRIPTION_ID environment variable")
            sys.exit(1)
        args.subscription_id = SUBSCRIPTION_ID

    if args.resource_group is None:
        if RESOURCE_GROUP_NAME is None:
            print("Please set the AZURE_RESOURCE_GROUP_NAME environment variable")
            sys.exit(1)
        args.resource_group = RESOURCE_GROUP_NAME

    if args.workspace is None:
        if WORKSPACE_NAME is None:
            print("Please set the AZURE_WORKSPACE_NAME environment variable")
            sys.exit(1)
        args.workspace = WORKSPACE_NAME

    return args
    

if __name__ == "__main__":
    args = parse_args()
    print("[+] Setting up Azure client")
    AZ = Azure(args.tenant, args.subscription_id, args.resource_group, args.workspace)
    review_attack(AZ)
