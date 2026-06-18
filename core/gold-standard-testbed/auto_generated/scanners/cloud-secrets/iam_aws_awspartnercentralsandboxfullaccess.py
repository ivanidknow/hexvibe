# Vulnerable: IAM-AWS-AWSPartnerCentralSandboxFullAccess
[
  {
    "Action": [
      "partnercentral:*"
    ],
    "Condition": {
      "StringEquals": {
        "partnercentral:Catalog": "Sandbox"
...
  }
]
