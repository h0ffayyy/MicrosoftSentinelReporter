import requests
import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights

logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
logging.getLogger("azure.identity").setLevel(logging.WARNING)


class Azure:
    def __init__(self, AzureTenantId, AzureSubscriptionId, AzureResourceGroup, AzureWorkspace):
        self.AzureTenantId = AzureTenantId
        self.AzureSubscriptionId = AzureSubscriptionId
        self.AzureResourceGroup = AzureResourceGroup
        self.AzureWorkspace = AzureWorkspace
        self.AzureCredential = self.get_azure_client()

    def get_azure_client(self):
        resource = "https://management.azure.com/"
        credential = DefaultAzureCredential()
        return credential
    
    def get_oauth_token(self):
        try:
            token = self.AzureCredential.get_token("https://management.azure.com/.default")
            return token
        except Exception as e:
            print(f"Failed to get Azure token: {e}")
    
    def get_security_insights_client(self):
        security_insights_client = SecurityInsights(
            credential=self.AzureCredential, 
            subscription_id=self.AzureSubscriptionId
        )
        return security_insights_client
    
    def get_alert_rules(self):
        alert_rules = self.get_security_insights_client().alert_rules.list(
            resource_group_name=self.AzureResourceGroup, 
            workspace_name=self.AzureWorkspace
        )
        return alert_rules
    
    def get_alert_rule_by_name(self, alert_rule_name):
        url = f"https://management.azure.com/subscriptions/{self.AzureSubscriptionId}/resourceGroups/{self.AzureResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{self.AzureWorkspace}/providers/Microsoft.SecurityInsights/alertRules/{alert_rule_name}?api-version=2023-09-01-preview"

        headers = {
            "Authorization": f"Bearer {self.get_oauth_token().token}",
            "Content-Type": "application/json"
        }

        alert_rule = requests.get(url, headers=headers)
        json_data = alert_rule.json()
        return json_data