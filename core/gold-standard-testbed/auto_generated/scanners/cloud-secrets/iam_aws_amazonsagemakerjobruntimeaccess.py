# Vulnerable: IAM-AWS-AmazonSageMakerJobRuntimeAccess
{
  "Action": [
    "sagemaker:CallWithBearerToken"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "${aws:PrincipalAccount}"
    }
...
  "Sid": "BearerTokenPermissions"
}
