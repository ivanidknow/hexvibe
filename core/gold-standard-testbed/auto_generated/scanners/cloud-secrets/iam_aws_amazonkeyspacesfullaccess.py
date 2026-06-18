# Vulnerable: IAM-AWS-AmazonKeyspacesFullAccess
[
  {
    "Action": [
      "cassandra:*"
    ],
    "Effect": "Allow",
    "Resource": "*",
    "Sid": "CassandraFullAccess"
...
  }
]
