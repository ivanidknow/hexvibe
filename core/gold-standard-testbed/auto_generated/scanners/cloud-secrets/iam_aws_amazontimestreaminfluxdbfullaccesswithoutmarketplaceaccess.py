# Vulnerable: IAM-AWS-AmazonTimestreamInfluxDBFullAccessWithoutMarketplaceAccess
{
  "Action": [
    "ec2:DescribeSubnets",
    "ec2:DescribeVpcs",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeRouteTables",
    "ec2:DescribeVpcEndpoints"
  ],
...
  "Sid": "NetworkValidationStatement"
}
