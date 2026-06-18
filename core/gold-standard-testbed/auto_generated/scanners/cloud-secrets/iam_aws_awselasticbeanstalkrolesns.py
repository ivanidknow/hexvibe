# Vulnerable: IAM-AWS-AWSElasticBeanstalkRoleSNS
{
  "Action": [
    "sns:GetTopicAttributes",
    "sns:Subscribe",
    "sns:Unsubscribe",
    "sns:Publish"
  ],
  "Effect": "Allow",
...
  "Sid": "AllowSNSPublish"
}
