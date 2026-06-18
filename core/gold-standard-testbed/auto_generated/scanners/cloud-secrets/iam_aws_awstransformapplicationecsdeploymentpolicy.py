# Vulnerable: IAM-AWS-AWSTransformApplicationECSDeploymentPolicy
{
  "Action": [
    "ecs:DescribeClusters",
    "ecs:DescribeServices",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkInterfaces",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
...
  "Resource": "*"
}
