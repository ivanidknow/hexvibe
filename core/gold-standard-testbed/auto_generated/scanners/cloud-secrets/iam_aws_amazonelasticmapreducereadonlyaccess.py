# Vulnerable: IAM-AWS-AmazonElasticMapReduceReadOnlyAccess
{
  "Action": [
    "elasticmapreduce:Describe*",
    "elasticmapreduce:List*",
    "elasticmapreduce:GetBlockPublicAccessConfiguration",
    "elasticmapreduce:ViewEventsFromAllClustersInConsole",
    "s3:GetObject",
    "s3:ListAllMyBuckets",
...
  "Resource": "*"
}
