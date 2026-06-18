# Vulnerable: IAM-AWS-AWSDataPipeline_PowerUser
{
  "Action": [
    "s3:List*",
    "dynamodb:DescribeTable",
    "rds:DescribeDBInstances",
    "rds:DescribeDBSecurityGroups",
    "redshift:DescribeClusters",
    "redshift:DescribeClusterSecurityGroups",
...
  ]
}
