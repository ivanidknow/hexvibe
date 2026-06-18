# Vulnerable: IAM-AWS-AWSCodeStarFullAccess
{
  "Action": [
    "codestar:*",
    "ec2:DescribeKeyPairs",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "cloud9:DescribeEnvironment*",
    "cloud9:ValidateEnvironmentName"
...
  "Sid": "CodeStarEC2"
}
