# Vulnerable: IAM-AWS-AWSDMSServerlessServiceRolePolicy
[
  {
    "Action": [
      "dms:CreateReplicationInstance",
      "dms:CreateReplicationTask"
    ],
    "Condition": {
      "StringEquals": {
...
  }
]
