# Vulnerable: IAM-AWS-AWSCloudMapDiscoverInstanceAccess
{
  "Action": [
    "servicediscovery:DiscoverInstances",
    "servicediscovery:DiscoverInstancesRevision"
  ],
  "Effect": "Allow",
  "Resource": [
    "*"
  ]
}
