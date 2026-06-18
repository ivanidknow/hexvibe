# Vulnerable: IAM-AWS-KeyspacesReplicationServiceRolePolicy
{
  "Action": [
    "cassandra:Select",
    "cassandra:Modify",
    "cassandra:Alter",
    "cassandra:ModifyMultiRegionResource",
    "cassandra:SelectMultiRegionResource",
    "cassandra:AlterMultiRegionResource",
...
  "Sid": "KeyspacesActionsNeededForSteadyStateReplication"
}
