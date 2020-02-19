## Vendor Module Access Restrictions
## Restrict access to the vendor interface to known source IPs only
## Matches the URI prefix, when the remote IP isn't in the whitelist

resource aws_waf_rule detect_vendor_access {
  name        = "${var.waf_prefix}-generic-allow-vendor-access"
  metric_name = replace("${var.waf_prefix}genericdetectvendoraccess", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_ipset.vendor_remote_ipset.id
    negated = true
    type    = "IPMatch"
  }

  predicates {
    data_id = aws_waf_byte_match_set.match_vendor_url.id
    negated = false
    type    = "ByteMatch"
  }
}

resource aws_waf_ipset vendor_remote_ipset {
  name = "${var.waf_prefix}-generic-match-vendor-remote-ip"
  dynamic ip_set_descriptors {
    for_each = var.vendor_remote_ipset

    content {
      type  = "IPV4"
      value = ip_set_descriptors.value
    }
  }
}

resource aws_waf_byte_match_set match_vendor_url {
  name = "${var.waf_prefix}-generic-match-vendor-url"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = var.vendor_url_prefix
    positional_constraint = "STARTS_WITH"

    field_to_match {
      type = "URI"
    }
  }
}

