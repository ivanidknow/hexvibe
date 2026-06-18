# Vulnerable: IAM-AWS-AmazonElasticMapReduceforEC2Role
{
  "Action": [
    "cloudwatch:*",
    "dynamodb:*",
    "ec2:Describe*",
    "elasticmapreduce:Describe*",
    "elasticmapreduce:ListBootstrapActions",
    "elasticmapreduce:ListClusters",
...
  "Resource": "*"
}
