# Vulnerable: IAM-AWS-AWSAppSyncInvokeFullAccess
{
  "Action": [
    "appsync:GraphQL",
    "appsync:GetGraphqlApi",
    "appsync:ListGraphqlApis",
    "appsync:ListApiKeys"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
