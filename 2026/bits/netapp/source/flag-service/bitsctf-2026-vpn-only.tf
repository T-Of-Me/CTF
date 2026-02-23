provider "cloudflare" {
  # email   = "do not hardcode"
  # api_key = "do not hardcode"
}

data "cloudflare_zone" "example" {
  name = "hvijay.dev"
}

resource "cloudflare_filter" "vpn_access_filter" {
  zone_id     = data.cloudflare_zone.example.id
  description = "Filter for allowing only VPN access to bitsctf-2026.hvijay.dev"
  body        = "(http.host eq \"bitsctf-2026.hvijay.dev\") and (ip.src ne 0.0.0.0)"
}

resource "cloudflare_firewall_rule" "vpn_access_rule" {
  zone_id     = data.cloudflare_zone.example.id
  description = "Allow only VPN Access."
  action      = "block"
  priority    = 1
  filter      = cloudflare_filter.vpn_access_filter.id
}