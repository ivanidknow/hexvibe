# Vulnerable: IAM-AWS-AWSApplicationAutoscalingElastiCacheRGPolicy
{
  "Action": [
    "elasticache:DescribeReplicationGroups",
    "elasticache:ModifyCacheCluster",
    "elasticache:ModifyReplicationGroupShardConfiguration",
    "elasticache:IncreaseReplicaCount",
    "elasticache:DecreaseReplicaCount",
    "elasticache:DescribeCacheClusters",
...
  "Sid": "ElastiCacheActionsOnAllClusters"
}
