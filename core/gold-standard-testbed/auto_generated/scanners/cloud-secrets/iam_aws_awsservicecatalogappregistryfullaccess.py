# Vulnerable: IAM-AWS-AWSServiceCatalogAppRegistryFullAccess
[
  {
    "Action": [
      "cloudformation:UpdateStack",
      "tag:GetResources"
    ],
    "Condition": {
      "ForAnyValue:StringEquals": {
...
  }
]
