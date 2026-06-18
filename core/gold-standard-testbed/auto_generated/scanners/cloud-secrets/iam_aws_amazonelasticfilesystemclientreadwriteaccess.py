# Vulnerable: IAM-AWS-AmazonElasticFileSystemClientReadWriteAccess
{
  "Action": [
    "elasticfilesystem:ClientMount",
    "elasticfilesystem:ClientWrite",
    "elasticfilesystem:DescribeMountTargets"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
