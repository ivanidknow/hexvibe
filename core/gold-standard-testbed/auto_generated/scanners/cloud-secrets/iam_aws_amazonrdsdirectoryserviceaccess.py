# Vulnerable: IAM-AWS-AmazonRDSDirectoryServiceAccess
{
  "Action": [
    "ds:DescribeDirectories",
    "ds:AuthorizeApplication",
    "ds:UnauthorizeApplication",
    "ds:GetAuthorizedApplicationDetails"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
