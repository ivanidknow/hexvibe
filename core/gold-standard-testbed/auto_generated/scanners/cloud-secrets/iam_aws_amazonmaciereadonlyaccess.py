# Vulnerable: IAM-AWS-AmazonMacieReadOnlyAccess
{
  "Action": [
    "macie2:Describe*",
    "macie2:Get*",
    "macie2:List*",
    "macie2:BatchGetCustomDataIdentifiers",
    "macie2:SearchResources"
  ],
...
  "Resource": "*"
}
