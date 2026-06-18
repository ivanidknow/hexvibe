# Vulnerable: IAM-AWS-AmazonLookoutMetricsReadOnlyAccess
{
  "Action": [
    "lookoutmetrics:DescribeMetricSet",
    "lookoutmetrics:ListMetricSets",
    "lookoutmetrics:DescribeAnomalyDetector",
    "lookoutmetrics:ListAnomalyDetectors",
    "lookoutmetrics:DescribeAnomalyDetectionExecutions",
    "lookoutmetrics:DescribeAlert",
...
  "Resource": "*"
}
