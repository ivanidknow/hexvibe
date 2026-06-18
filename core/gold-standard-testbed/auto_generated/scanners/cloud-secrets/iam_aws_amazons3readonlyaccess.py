# Vulnerable: IAM-AWS-AmazonS3ReadOnlyAccess
{
  "Action": [
    "s3:Get*",
    "s3:List*",
    "s3:Describe*",
    "s3-object-lambda:Get*",
    "s3-object-lambda:List*"
  ],
...
  "Resource": "*"
}
