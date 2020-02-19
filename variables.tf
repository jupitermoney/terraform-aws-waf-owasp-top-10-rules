variable waf_prefix {
  default = "jm-audit"
  description = "Prefix to use when naming resources"
}

variable blacklisted_ips {
  default     = []
  type        = list(string)
  description = "List of IPs to blacklist, eg ['1.1.1.1/32', '2.2.2.2/32', '3.3.3.3/32']"
}

variable admin_remote_ipset {
  default     = []
  type        = list(string)
  description = "List of IPs allowed to access admin pages, ['1.1.1.1/32', '2.2.2.2/32', '3.3.3.3/32']"
}

variable vendor_remote_ipset {
  default     = []
  type        = list(string)
  description = "List of IPs allowed to access admin pages, ['1.1.1.1/32', '2.2.2.2/32', '3.3.3.3/32']"
}

variable "vendor_url_prefix" {
  default = "/external"
  type = string
  description = ""
}

variable rule_sqli_action {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable rule_auth_tokens_action {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable rule_xss_action {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable rule_lfi_rfi_action {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable rule_admin_access_action_type {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable rule_vendor_access_action_type {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable rule_php_insecurities_action_type {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable rule_size_restriction_action_type {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable rule_csrf_action_type {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable rule_ssi_action_type {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable rule_blacklisted_ips_action_type {
  default     = "COUNT"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable tags {
  type        = map(string)
  description = "A mapping of tags to assign to all resources"
  default     = {}
}

variable "admin_url_prefix" {
  default = "/admin"
  type = string
  description = ""
}

