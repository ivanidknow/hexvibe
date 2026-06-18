# Vulnerable: IAM-AWS-AmazonInspector2ManagedTelemetryPolicy
{
  "Action": [
    "inspector2-telemetry:StartSession",
    "inspector2-telemetry:StopSession",
    "inspector2-telemetry:SendTelemetry",
    "inspector2-telemetry:NotifyHeartbeat"
  ],
  "Effect": "Allow",
...
  "Sid": "PermissionsForInspector2Telemetry"
}
