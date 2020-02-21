output web_rulegroup_id {
  description = "AWS WAF web acl id."
  value       = aws_waf_rule_group.owasp_top_10.id
}

output web_rulegroup_name {
  description = "The name or description of the web ACL."
  value       = aws_waf_rule_group.owasp_top_10.name
}

output web_rulegroup_metric_name {
  description = "The name or description for the Amazon CloudWatch metric of this web ACL."
  value       = aws_waf_rule_group.owasp_top_10.metric_name
}