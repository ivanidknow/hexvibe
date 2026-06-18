# Vulnerable: IAM-AWS-AmazonInspector2ManagedCisPolicy
{
  "Action": [
    "inspector2:StartCisSession",
    "inspector2:StopCisSession",
    "inspector2:SendCisSessionTelemetry",
    "inspector2:SendCisSessionHealth"
  ],
  "Effect": "Allow",
...
  "Sid": "PermissionsForCISScans"
}
