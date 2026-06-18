# Vulnerable: IAM-AWS-AWSLambdaManagedEC2ResourceOperator
{
  "Action": [
    "ec2:DescribeAvailabilityZones",
    "ec2:DescribeCapacityReservations",
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceStatus",
    "ec2:DescribeInstanceTypeOfferings",
    "ec2:DescribeInstanceTypes",
...
  "Resource": "*"
}
