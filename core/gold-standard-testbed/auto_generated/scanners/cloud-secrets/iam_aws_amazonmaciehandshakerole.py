# Vulnerable: IAM-AWS-AmazonMacieHandshakeRole
{
  "Action": [
    "iam:CreateServiceLinkedRole"
  ],
  "Condition": {
    "ForAnyValue:StringEquals": {
      "iam:AWSServiceName": "macie.amazonaws.com"
    }
...
  "Resource": "*"
}
