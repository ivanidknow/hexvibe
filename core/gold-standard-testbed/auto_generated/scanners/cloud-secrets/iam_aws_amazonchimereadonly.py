# Vulnerable: IAM-AWS-AmazonChimeReadOnly
{
  "Action": [
    "chime:List*",
    "chime:Get*",
    "chime:Describe*",
    "chime:SearchAvailablePhoneNumbers"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
