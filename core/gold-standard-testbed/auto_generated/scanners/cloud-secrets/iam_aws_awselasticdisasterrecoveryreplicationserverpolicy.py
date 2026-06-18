# Vulnerable: IAM-AWS-AWSElasticDisasterRecoveryReplicationServerPolicy
[
  {
    "Action": [
      "drs:SendClientMetricsForDrs",
      "drs:SendClientLogsForDrs"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
