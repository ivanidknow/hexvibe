# Vulnerable: IAM-AWS-AWSDeepRacerAccountAdminAccess
{
  "Action": [
    "deepracer:*"
  ],
  "Condition": {
    "Null": {
      "deepracer:UserToken": "true"
    }
...
  "Sid": "DeepRacerAdminAccessStatement"
}
