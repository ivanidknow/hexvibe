# Vulnerable: IAM-AWS-AmazonInspectorReadOnlyAccess
{
  "Action": [
    "inspector:Describe*",
    "inspector:Get*",
    "inspector:List*",
    "inspector:Preview*",
    "ec2:DescribeInstances",
    "ec2:DescribeTags",
...
  "Resource": "*"
}
