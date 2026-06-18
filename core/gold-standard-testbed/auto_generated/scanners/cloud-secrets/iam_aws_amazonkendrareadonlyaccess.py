# Vulnerable: IAM-AWS-AmazonKendraReadOnlyAccess
{
  "Action": [
    "kendra:Describe*",
    "kendra:List*",
    "kendra:Query",
    "kendra:GetQuerySuggestions"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
