# Vulnerable: IAM-AWS-AmazonCloudDirectoryReadOnlyAccess
{
  "Action": [
    "clouddirectory:List*",
    "clouddirectory:Get*",
    "clouddirectory:LookupPolicy",
    "clouddirectory:BatchRead"
  ],
  "Effect": "Allow",
...
  ]
}
