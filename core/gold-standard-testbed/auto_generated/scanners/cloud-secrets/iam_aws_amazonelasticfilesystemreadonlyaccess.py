# Vulnerable: IAM-AWS-AmazonElasticFileSystemReadOnlyAccess
{
  "Action": [
    "cloudwatch:DescribeAlarmsForMetric",
    "cloudwatch:GetMetricData",
    "ec2:DescribeAvailabilityZones",
    "ec2:DescribeNetworkInterfaceAttribute",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSecurityGroups",
...
  "Sid": "ElasticFileSystemReadOnlyAccess"
}
