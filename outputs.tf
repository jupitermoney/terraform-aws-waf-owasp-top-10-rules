output "rule_group_id" {
  description = "AWS WAF Rule Group which contains all rules for OWASP Top 10 protection."
  value = lower(var.target_scope) == "regional" ? element(
    concat(
      aws_wafregional_rule_group.owasp_top_10.*.id,
      ["NOT_CREATED"],
    ),
    "0",
    ) : element(
    concat(aws_waf_rule_group.owasp_top_10.*.id, ["NOT_CREATED"]),
    "0",
  )
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
output "sql_injection_rule_id_01" {
  description = "AWS WAF Rule which mitigates SQL Injection Attacks."
  value = lower(var.target_scope) == "regional" ? element(
    concat(
      aws_wafregional_rule.owasp_01_sql_injection_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
    ) : element(
    concat(
      aws_waf_rule.owasp_01_sql_injection_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
  )
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
output "auth_token_rule_id_02" {
  description = "AWS WAF Rule which blacklists bad/hijacked JWT tokens or session IDs."
  value = lower(var.target_scope) == "regional" ? element(
    concat(
      aws_wafregional_rule.owasp_02_auth_token_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
    ) : element(
    concat(aws_waf_rule.owasp_02_auth_token_rule.*.id, ["NOT_CREATED"]),
    "0",
  )
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
output "xss_rule_id_03" {
  description = "AWS WAF Rule which mitigates Cross Site Scripting Attacks."
  value = lower(var.target_scope) == "regional" ? element(
    concat(aws_wafregional_rule.owasp_03_xss_rule.*.id, ["NOT_CREATED"]),
    "0",
    ) : element(
    concat(aws_waf_rule.owasp_03_xss_rule.*.id, ["NOT_CREATED"]),
    "0",
  )
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
output "paths_rule_id_04" {
  description = "AWS WAF Rule which mitigates Path Traversal, LFI, RFI."
  value = lower(var.target_scope) == "regional" ? element(
    concat(
      aws_wafregional_rule.owasp_04_paths_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
    ) : element(
    concat(aws_waf_rule.owasp_04_paths_rule.*.id, ["NOT_CREATED"]),
    "0",
  )
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
output "php_insecure_rule_id_06" {
  description = "AWS WAF Rule which mitigates PHP Specific Security Misconfigurations."
  value = lower(var.target_scope) == "regional" ? element(
    concat(
      aws_wafregional_rule.owasp_06_php_insecure_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
    ) : element(
    concat(
      aws_waf_rule.owasp_06_php_insecure_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
  )
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
output "size_restriction_rule_id_07" {
  description = "AWS WAF Rule which mitigates abnormal requests via size restrictions."
  value = lower(var.target_scope) == "regional" ? element(
    concat(
      aws_wafregional_rule.owasp_07_size_restriction_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
    ) : element(
    concat(
      aws_waf_rule.owasp_07_size_restriction_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
  )
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
output "csrf_rule_id_08" {
  description = "AWS WAF Rule which enforces the presence of CSRF token in request header."
  value = lower(var.target_scope) == "regional" ? element(
    concat(
      aws_wafregional_rule.owasp_08_csrf_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
    ) : element(
    concat(aws_waf_rule.owasp_08_csrf_rule.*.id, ["NOT_CREATED"]),
    "0",
  )
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
output "server_side_include_rule_id_09" {
  description = "AWS WAF Rule which blocks request patterns for webroot objects that shouldn't be directly accessible."
  value = lower(var.target_scope) == "regional" ? element(
    concat(
      aws_wafregional_rule.owasp_09_server_side_include_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
    ) : element(
    concat(
      aws_waf_rule.owasp_09_server_side_include_rule.*.id,
      ["NOT_CREATED"],
    ),
    "0",
  )
}

