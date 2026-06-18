# Vulnerable: IAM-AWS-AWSCloudTrail_ReadOnlyAccess
{
  "Action": [
    "cloudtrail:Get*",
    "cloudtrail:Describe*",
    "cloudtrail:List*",
    "cloudtrail:LookupEvents"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
