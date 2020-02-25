resource "aws_waf_rule_group" "owasp_top_10" {
  depends_on = [
    aws_waf_rule.detect_ssi,
    aws_waf_rule.detect_bad_auth_tokens,
    aws_waf_rule.mitigate_xss,
    aws_waf_rule.detect_rfi_lfi_traversal,
    aws_waf_rule.detect_admin_access,
    aws_waf_rule.detect_php_insecure,
    aws_waf_rule.restrict_sizes,
    aws_waf_rule.enforce_csrf,
    aws_waf_rule.detect_ssi,
    aws_waf_rule.detect_blacklisted_ips,
    aws_waf_rule.detect_vendor_access
  ]

  name        = "${var.waf_prefix}-generic-owasp-acl"
  metric_name = replace("${var.waf_prefix}genericowaspacl", "/[^0-9A-Za-z]/", "")

  activated_rule {
    action {
      type = var.rule_size_restriction_action_type
    }

    priority = "1"
    rule_id  = aws_waf_rule.restrict_sizes.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_blacklisted_ips_action_type
    }

    priority = "2"
    rule_id  = aws_waf_rule.detect_blacklisted_ips.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_auth_tokens_action
    }

    priority = "3"
    rule_id  = aws_waf_rule.detect_bad_auth_tokens.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_sqli_action
    }

    priority = "4"
    rule_id  = aws_waf_rule.mitigate_sqli.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_xss_action
    }

    priority = "5"
    rule_id  = aws_waf_rule.mitigate_xss.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_lfi_rfi_action
    }

    priority = "6"
    rule_id  = aws_waf_rule.detect_rfi_lfi_traversal.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_php_insecurities_action_type
    }

    priority = "7"
    rule_id  = aws_waf_rule.detect_php_insecure.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_csrf_action_type
    }

    priority = "8"
    rule_id  = aws_waf_rule.enforce_csrf.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_ssi_action_type
    }

    priority = "9"
    rule_id  = aws_waf_rule.detect_ssi.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_admin_access_action_type
    }

    priority = "10"
    rule_id  = aws_waf_rule.detect_admin_access.id
    type     = "REGULAR"
  }
}

resource "aws_waf_rule_group" "internal" {
  depends_on = [
    aws_waf_rule.detect_ssi,
    aws_waf_rule.detect_bad_auth_tokens,
    aws_waf_rule.mitigate_xss,
    aws_waf_rule.detect_rfi_lfi_traversal,
    aws_waf_rule.detect_admin_access,
    aws_waf_rule.detect_php_insecure,
    aws_waf_rule.restrict_sizes,
    aws_waf_rule.enforce_csrf,
    aws_waf_rule.detect_ssi,
    aws_waf_rule.detect_blacklisted_ips,
    aws_waf_rule.detect_vendor_access
  ]

  name = "${var.waf_prefix}-internal"
  metric_name = replace("${var.waf_prefix}internal", "/[^0-9A-Za-z]/", "")


  activated_rule {
    action {
      type = var.rule_vendor_access_action_type
    }

    priority = "1"
    rule_id = aws_waf_rule.detect_admin_access.id
    type = "REGULAR"
  }

  tags = var.tags
}