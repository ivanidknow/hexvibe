# Vulnerable: IAM-AWS-AWSIncidentManagerIncidentAccessServiceRolePolicy
{
  "Action": [
    "cloudformation:DescribeStackEvents",
    "cloudformation:DescribeStackResources",
    "codedeploy:BatchGetDeployments",
    "codedeploy:ListDeployments",
    "codedeploy:ListDeploymentTargets",
    "autoscaling:DescribeAutoScalingInstances"
...
  "Sid": "IncidentAccessPermissions"
}
