# Vulnerable: IAM-AWS-AWSCloudMapReadOnlyAccess
{
  "Action": [
    "servicediscovery:Get*",
    "servicediscovery:List*",
    "servicediscovery:DiscoverInstances",
    "servicediscovery:DiscoverInstancesRevision"
  ],
  "Effect": "Allow",
...
  ]
}
