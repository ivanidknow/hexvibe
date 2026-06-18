# Vulnerable: IAM-AWS-AWSElementalMediaLiveReadOnly
{
  "Action": [
    "medialive:Get*",
    "medialive:List*",
    "medialive:Describe*"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "AWSElementalMediaLiveReadOnly"
}
