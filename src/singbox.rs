//! Конфиг для движка sing-box: TUN-туннель, ноды из подписки, выбор ноды на
//! ходу через clash API.
//!
//! Конфиг собирается строкой, а не структурами: схема движка меняется от версии
//! к версии, и держать её зеркало в типах — работа ради работы. Проверяется
//! конфиг тем же движком (`sing-box check`), а не нашей верой в него.

use crate::json;
use crate::sub::Node;

/// Адрес встроенного API движка: через него меняется нода без перезапуска.
pub const CLASH_API: &str = "127.0.0.1:9090";

/// Тег селектора, который выбирает текущую ноду.
pub const SELECTOR: &str = "proxy";

/// Тег автоподбора по задержке.
pub const AUTO: &str = "auto";

pub fn build_config(nodes: &[Node]) -> Result<String, String> {
    if nodes.is_empty() {
        return Err("нет ни одной ноды".into());
    }
    let tags: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
    let quoted: Vec<String> = tags.iter().map(|t| json::escape(t)).collect();
    let outbounds: Vec<String> = nodes
        .iter()
        .zip(&tags)
        .map(|(node, tag)| {
            let mut node = node.clone();
            node.name = tag.clone();
            node.to_outbound()
        })
        .collect();

    let selector = format!(
        "{{\"type\": \"selector\", \"tag\": {}, \"outbounds\": [{}, {}], \"default\": {}}}",
        json::escape(SELECTOR),
        json::escape(AUTO),
        quoted.join(", "),
        json::escape(AUTO)
    );
    let urltest = format!(
        "{{\"type\": \"urltest\", \"tag\": {}, \"outbounds\": [{}], \"url\": \"https://www.gstatic.com/generate_204\", \"interval\": \"5m\", \"tolerance\": 50}}",
        json::escape(AUTO),
        quoted.join(", ")
    );

    let mut all = vec![selector, urltest];
    all.extend(outbounds);
    all.push("{\"type\": \"direct\", \"tag\": \"direct\"}".to_string());

    Ok(format!(
        r#"{{
  "log": {{"level": "warn"}},
  "dns": {{
    "servers": [
      {{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": "{selector}"}},
      {{"type": "udp", "tag": "dns-direct", "server": "77.88.8.8", "detour": "direct"}}
    ],
    "rules": [
      {{"rule_set": "geosite-ru", "server": "dns-direct"}}
    ],
    "final": "dns-remote",
    "strategy": "ipv4_only"
  }},
  "inbounds": [
    {{
      "type": "tun",
      "tag": "tun-in",
      "address": ["172.19.0.1/30"],
      "auto_route": true,
      "strict_route": false,
      "stack": "gvisor"
    }}
  ],
  "outbounds": [{outbounds}],
  "route": {{
    "rules": [
      {{"action": "sniff"}},
      {{"protocol": "dns", "action": "hijack-dns"}},
      {{"ip_is_private": true, "outbound": "direct"}},
      {{"rule_set": "geosite-ru", "outbound": "direct"}},
      {{"rule_set": "geoip-ru", "outbound": "direct"}}
    ],
    "rule_set": [
      {{
        "type": "remote",
        "tag": "geosite-ru",
        "format": "binary",
        "url": "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ru.srs",
        "download_detour": "{selector}"
      }},
      {{
        "type": "remote",
        "tag": "geoip-ru",
        "format": "binary",
        "url": "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-ru.srs",
        "download_detour": "{selector}"
      }}
    ],
    "auto_detect_interface": true,
    "default_domain_resolver": {{"server": "dns-direct"}},
    "final": "{selector}"
  }},
  "experimental": {{
    "clash_api": {{"external_controller": "{api}"}},
    "cache_file": {{"enabled": true}}
  }}
}}
"#,
        selector = SELECTOR,
        outbounds = all.join(",\n    "),
        api = CLASH_API
    ))
}
