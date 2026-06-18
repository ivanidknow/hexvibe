# Vulnerable: IAM-AWS-AmazonCognitoReadOnly
{
  "Action": [
    "cognito-identity:Describe*",
    "cognito-identity:Get*",
    "cognito-identity:List*",
    "cognito-idp:Describe*",
    "cognito-idp:AdminGet*",
    "cognito-idp:AdminList*",
...
  "Resource": "*"
}
