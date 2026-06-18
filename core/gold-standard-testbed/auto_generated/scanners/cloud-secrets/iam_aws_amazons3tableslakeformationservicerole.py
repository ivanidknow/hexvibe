# Vulnerable: IAM-AWS-AmazonS3TablesLakeFormationServiceRole
[
  {
    "Action": [
      "s3tables:ListTableBuckets"
    ],
    "Condition": {
      "StringEquals": {
        "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  }
]
