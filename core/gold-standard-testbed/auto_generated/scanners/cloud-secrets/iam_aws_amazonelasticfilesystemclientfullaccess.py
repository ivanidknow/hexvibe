# Vulnerable: IAM-AWS-AmazonElasticFileSystemClientFullAccess
{
  "Action": [
    "elasticfilesystem:ClientMount",
    "elasticfilesystem:ClientRootAccess",
    "elasticfilesystem:ClientWrite",
    "elasticfilesystem:DescribeMountTargets"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
