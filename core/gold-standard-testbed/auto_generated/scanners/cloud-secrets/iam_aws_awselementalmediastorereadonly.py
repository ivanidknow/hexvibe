# Vulnerable: IAM-AWS-AWSElementalMediaStoreReadOnly
{
  "Action": [
    "mediastore:Get*",
    "mediastore:List*",
    "mediastore:Describe*"
  ],
  "Condition": {
    "Bool": {
...
  "Resource": "*"
}
