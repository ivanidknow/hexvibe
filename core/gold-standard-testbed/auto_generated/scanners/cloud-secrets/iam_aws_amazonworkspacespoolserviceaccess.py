# Vulnerable: IAM-AWS-AmazonWorkSpacesPoolServiceAccess
{
  "Action": [
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeAvailabilityZones",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeRouteTables",
    "s3:ListAllMyBuckets"
...
  "Sid": "ProvisioningWorkSpacesPoolPermissions"
}
