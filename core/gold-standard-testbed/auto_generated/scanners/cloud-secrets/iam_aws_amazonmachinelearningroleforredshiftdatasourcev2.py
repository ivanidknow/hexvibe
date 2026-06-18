# Vulnerable: IAM-AWS-AmazonMachineLearningRoleforRedshiftDataSourceV2
{
  "Action": [
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:CreateSecurityGroup",
    "ec2:DescribeInternetGateways",
    "ec2:DescribeSecurityGroups",
    "ec2:RevokeSecurityGroupIngress",
    "redshift:AuthorizeClusterSecurityGroupIngress",
...
  "Resource": "*"
}
