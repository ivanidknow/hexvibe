# Vulnerable: IAM-AWS-AmazonEventBridgePipesOperatorAccess
{
  "Action": [
    "pipes:DescribePipe",
    "pipes:ListPipes",
    "pipes:ListTagsForResource",
    "pipes:StartPipe",
    "pipes:StopPipe"
  ],
...
  "Resource": "*"
}
