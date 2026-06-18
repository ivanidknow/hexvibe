# Vulnerable: IAM-AWS-AmazonS3ObjectLambdaExecutionRolePolicy
{
  "Action": [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents",
    "s3-object-lambda:WriteGetObjectResponse"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
