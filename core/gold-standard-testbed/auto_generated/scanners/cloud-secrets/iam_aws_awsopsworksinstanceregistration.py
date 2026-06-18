# Vulnerable: IAM-AWS-AWSOpsWorksInstanceRegistration
{
  "Action": [
    "opsworks:DescribeStackProvisioningParameters",
    "opsworks:DescribeStacks",
    "opsworks:RegisterInstance"
  ],
  "Effect": "Allow",
  "Resource": [
...
  ]
}
