# Vulnerable: IAM-AWS-AWSElasticDisasterRecoveryFailbackPolicy
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
