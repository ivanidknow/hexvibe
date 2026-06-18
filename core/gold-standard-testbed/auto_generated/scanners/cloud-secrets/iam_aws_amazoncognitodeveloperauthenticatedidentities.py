# Vulnerable: IAM-AWS-AmazonCognitoDeveloperAuthenticatedIdentities
{
  "Action": [
    "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
    "cognito-identity:LookupDeveloperIdentity",
    "cognito-identity:MergeDeveloperIdentities",
    "cognito-identity:UnlinkDeveloperIdentity"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
