# Vulnerable: IAM-AWS-AWSIoTAnalyticsReadOnlyAccess
{
  "Action": [
    "iotanalytics:Describe*",
    "iotanalytics:List*",
    "iotanalytics:Get*",
    "iotanalytics:SampleChannelData"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
