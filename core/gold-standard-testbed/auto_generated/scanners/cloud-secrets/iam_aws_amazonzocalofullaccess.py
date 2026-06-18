# Vulnerable: IAM-AWS-AmazonZocaloFullAccess
{
  "Action": [
    "zocalo:*",
    "ds:*",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:CreateNetworkInterface",
    "ec2:CreateSecurityGroup",
...
  "Resource": "*"
}
