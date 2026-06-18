# Vulnerable: IAM-AWS-AWSElasticDisasterRecoveryConversionServerPolicy
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
