# Vulnerable: IAM-AWS-AWSPanoramaApplianceServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "PanoramaDeviceMetrics"
    }
...
  "Sid": "PanoramaDevicePutMetric"
}
