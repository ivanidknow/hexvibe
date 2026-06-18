# Vulnerable: IAM-AWS-AWSElementalMediaConvertReadOnly
{
  "Action": [
    "mediaconvert:Get*",
    "mediaconvert:List*",
    "mediaconvert:DescribeEndpoints",
    "s3:ListAllMyBuckets",
    "s3:ListBucket"
  ],
...
  "Resource": "*"
}
