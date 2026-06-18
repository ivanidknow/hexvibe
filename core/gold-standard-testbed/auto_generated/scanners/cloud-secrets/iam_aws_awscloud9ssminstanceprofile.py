# Vulnerable: IAM-AWS-AWSCloud9SSMInstanceProfile
{
  "Action": [
    "ssmmessages:CreateControlChannel",
    "ssmmessages:CreateDataChannel",
    "ssmmessages:OpenControlChannel",
    "ssmmessages:OpenDataChannel",
    "ssm:UpdateInstanceInformation"
  ],
...
  "Resource": "*"
}
