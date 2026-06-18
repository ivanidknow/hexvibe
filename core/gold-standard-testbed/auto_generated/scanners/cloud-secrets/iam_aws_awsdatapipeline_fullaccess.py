# Vulnerable: IAM-AWS-AWSDataPipeline_FullAccess
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
