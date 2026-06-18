# Vulnerable: IAM-AWS-AmazonOpenSearchDirectQueryGlueCreateAccess
{
  "Action": [
    "glue:CreateDatabase",
    "glue:CreatePartition",
    "glue:CreateTable",
    "glue:BatchCreatePartition"
  ],
  "Effect": "Allow",
...
  "Sid": "AmazonOpenSearchDirectQueryGlueCreateAccess"
}
