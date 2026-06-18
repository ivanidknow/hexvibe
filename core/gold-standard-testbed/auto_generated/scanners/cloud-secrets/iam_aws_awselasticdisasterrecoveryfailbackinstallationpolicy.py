# Vulnerable: IAM-AWS-AWSElasticDisasterRecoveryFailbackInstallationPolicy
{
  "Action": [
    "drs:SendClientLogsForDrs",
    "drs:SendClientMetricsForDrs",
    "drs:DescribeRecoveryInstances",
    "drs:DescribeSourceServers"
  ],
  "Effect": "Allow",
...
  "Sid": "DRSFailbackInstallationPolicy1"
}
