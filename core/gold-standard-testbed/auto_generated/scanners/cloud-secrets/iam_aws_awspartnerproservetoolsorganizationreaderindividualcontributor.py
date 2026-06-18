# Vulnerable: IAM-AWS-AWSPartnerProServeToolsOrganizationReaderIndividualContributor
{
  "Action": [
    "partnercentral-account-management:AccessProServeTools"
  ],
  "Condition": {
    "ForAllValues:StringEquals": {
      "partnercentral-account-management:ProServeRole": [
        "AssessmentOrganizationReader",
...
  "Sid": "AllowProServeToolsOrgReaderIndividualContributorAccess"
}
