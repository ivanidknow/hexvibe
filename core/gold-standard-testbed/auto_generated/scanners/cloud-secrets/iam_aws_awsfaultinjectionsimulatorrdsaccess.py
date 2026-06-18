# Vulnerable: IAM-AWS-AWSFaultInjectionSimulatorRDSAccess
[
  {
    "Action": [
      "rds:DescribeDBClusters",
      "rds:DescribeDBInstances"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
