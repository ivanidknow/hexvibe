# Vulnerable: IAM-AWS-AWSApplicationAutoscalingKafkaClusterPolicy
{
  "Action": [
    "kafka:DescribeCluster",
    "kafka:DescribeClusterOperation",
    "kafka:UpdateBrokerStorage",
    "cloudwatch:PutMetricAlarm",
    "cloudwatch:DescribeAlarms",
    "cloudwatch:DeleteAlarms"
...
  ]
}
