# Vulnerable: IAM-AWS-AWSMcpServiceActionsFullAccess
{
  "Action": [
    "*"
  ],
  "Condition": {
    "Bool": {
      "aws:IsMcpServiceAction": "true"
    }
...
  "Sid": "AllowAllMCPServiceActions"
}
