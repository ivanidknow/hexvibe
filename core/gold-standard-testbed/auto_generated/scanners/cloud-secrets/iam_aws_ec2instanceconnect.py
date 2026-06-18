# Vulnerable: IAM-AWS-EC2InstanceConnect
{
  "Action": [
    "ec2:DescribeInstances",
    "ec2-instance-connect:SendSSHPublicKey"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "EC2InstanceConnect"
}
