# Vulnerable: IAM-AWS-AWSElasticBeanstalkReadOnlyAccess
{
  "Action": [
    "elasticbeanstalk:Check*",
    "elasticbeanstalk:Describe*",
    "elasticbeanstalk:List*",
    "elasticbeanstalk:RequestEnvironmentInfo",
    "elasticbeanstalk:RetrieveEnvironmentInfo",
    "ec2:Describe*",
...
  "Resource": "*"
}
