# Vulnerable: IAM-AWS-AWSPartnerProServeToolsFullAccess
{
  "Action": [
    "partnercentral-account-management:AccessProServeTools"
  ],
  "Condition": {
    "ForAllValues:StringEquals": {
      "partnercentral-account-management:ProServeRole": [
        "AssessmentIndividualContributor",
...
  "Sid": "AllowProServeToolsFullAccess"
}
