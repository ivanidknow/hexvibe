# Vulnerable: IAM-AWS-NeptuneGraphReadOnlyAccess
[
  {
    "Action": [
      "neptune-graph:Get*",
      "neptune-graph:List*",
      "neptune-graph:Read*"
    ],
    "Effect": "Allow",
...
  }
]
