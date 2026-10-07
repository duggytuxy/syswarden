//go:build linux

package firewall

// Exact complete literal outputs at legacyFail2banTemplateRevision. The
// dynamic portscan filter is checked separately. Generic distribution filters
// are excluded even when their bytes resemble a historical generator output.
// This catalogue is source equivalence evidence, never deletion authority.
var legacyFail2banLiteralFilters = map[string]struct {
	sha256 string
	source string
}{
	"/etc/fail2ban/filter.d/syswarden-aibots.conf":            {"e99e0b28bbe14c7dd276a72dd8473b00bcb71cfaddccc06fe6b3d7ea1ba47265", "src/jails/32-aibots.sh"},
	"/etc/fail2ban/filter.d/syswarden-apache-scanner.conf":    {"4a67d47f49a111c8d21066685098993c8274faf715d097c5939f824d559faa5e", "src/jails/05-apache.sh"},
	"/etc/fail2ban/filter.d/syswarden-apache-tls.conf":        {"59e024d7290ad47d9d18bcc0177816ada2844a25d1d77844a5568d63eeae9a22", "src/jails/53-apache-tls.sh"},
	"/etc/fail2ban/filter.d/syswarden-apimapper.conf":         {"f83376bf613bbc8ad6366fcb95ed12fa69401b7822a452a038f645e097b99d2a", "src/jails/41_5-apimapper.sh"},
	"/etc/fail2ban/filter.d/syswarden-atlassian.conf":         {"f7288083d2259dfc438b4be4eb95a434d28f8dbba2da304d13187dc365bfc946", "src/jails/50-atlassian.sh"},
	"/etc/fail2ban/filter.d/syswarden-auditd.conf":            {"19ee8900ccc66bbf784cf0cdd3f4fc1160391f58e1bb5da0a5bf44eb79eb82f5", "src/jails/30-auditd.sh"},
	"/etc/fail2ban/filter.d/syswarden-badbots.conf":           {"2e93cb705746bbbd4d32694b7d086545e200a1563d594bb2daa568754291ff6d", "src/jails/33-badbots.sh"},
	"/etc/fail2ban/filter.d/syswarden-cms-honeypot.conf":      {"8f6f7c034a7b3cd803aaaf93e4e9b258a3117bc7c23200703a596ac008070136", "src/jails/44_5-cms-honeypot.sh"},
	"/etc/fail2ban/filter.d/syswarden-cockpit-custom.conf":    {"35fd120d835cedf2b4f26bd8ead202b1d7fb173730322b3b9092cb3247c2f815", "src/jails/25-cockpit.sh"},
	"/etc/fail2ban/filter.d/syswarden-dolibarr.conf":          {"084554e83be20b9cf43eae534afacda70e03cd93a023b6859553b0797df61c22", "src/jails/51-dolibarr.sh"},
	"/etc/fail2ban/filter.d/syswarden-drupal-auth.conf":       {"94ba96e2b79893ba53245e850314dfae4b218184a361132060471e6c3ff0610c", "src/jails/10_5-drupal.sh"},
	"/etc/fail2ban/filter.d/syswarden-generic-auth.conf":      {"19469933ae983218ebdbb9db3e7d6bef0968c9b5b2a2a422c6bcd5debf40ab42", "src/jails/47-generic-auth.sh"},
	"/etc/fail2ban/filter.d/syswarden-gitea-custom.conf":      {"5fede590682c69bbd6c14a09f8011a5e2747c6d4a6e4faceab83e83eabfe4c66", "src/jails/24-gitea.sh"},
	"/etc/fail2ban/filter.d/syswarden-gitlab.conf":            {"4abce0b6759e82e7de6099a5fb939d3df88f928d6c324a8f7b8917f7a144b2b7", "src/jails/27_5-gitlab.sh"},
	"/etc/fail2ban/filter.d/syswarden-grafana-auth.conf":      {"f7287c3985ecd0afc9523faed31a0bb8017144c9594244471fed11b2b4d77880", "src/jails/18-grafana.sh"},
	"/etc/fail2ban/filter.d/syswarden-homoglyph.conf":         {"32b2b4aca9c536051440e566fea8ab3a056ef84f0769581c4871c74be0ebf41b", "src/jails/54-homoglyph.sh"},
	"/etc/fail2ban/filter.d/syswarden-idor-enum.conf":         {"d04dd5d22136bc08a3707a7a391044c62218070c8b8ef62d85498fe1176cb06e", "src/jails/42_5-idor-enum.sh"},
	"/etc/fail2ban/filter.d/syswarden-jenkins.conf":           {"b165555d93de3ecdf86efbaf1d39f318f19f8f600b62b0495e2191ad5dd11086", "src/jails/27-jenkins.sh"},
	"/etc/fail2ban/filter.d/syswarden-jndi-ssti.conf":         {"492162dc410547a20ab7af0b9d9dea72c6072697663d7da2038a154538b5f97c", "src/jails/40-jndi-ssti.sh"},
	"/etc/fail2ban/filter.d/syswarden-laravel-auth.conf":      {"c278ed55a863cdf9a27e71b3f83d9e24dc6a62de11b494f9a7bb6dfff7e23117", "src/jails/17-laravel.sh"},
	"/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf":      {"76e2c1b14a4e34e05d9900a2fab136a691422e73a070286115a653d1bfc58d56", "src/jails/41-lfi-advanced.sh"},
	"/etc/fail2ban/filter.d/syswarden-modsec.conf":            {"0042d9ef83c1f690dfa6d3a5726b84fddc98daea92f25b1bf1df7f751dde3f86", "src/jails/35-modsec.sh"},
	"/etc/fail2ban/filter.d/syswarden-mongodb-guard.conf":     {"e9cc7e731ff073749d8b6a9665c4f388a2e4e0d7d713b3de805fc29bc768e000", "src/jails/06-mongodb.sh"},
	"/etc/fail2ban/filter.d/syswarden-nextcloud.conf":         {"637223e5ad48de5494961299f6f74e68eb01bfa1b6692c3eb318058edabc8d83", "src/jails/11-nextcloud.sh"},
	"/etc/fail2ban/filter.d/syswarden-nginx-scanner.conf":     {"2f0af6433c87831058be48c203ab098ee63e7c6dfbe3b048b2b7013a0a4fe1aa", "src/jails/04-nginx.sh"},
	"/etc/fail2ban/filter.d/syswarden-odoo.conf":              {"4d5c744d036e6d500beaa609dc36f46a573c83324648cfc0da3db8eefcd370ac", "src/jails/48-odoo.sh"},
	"/etc/fail2ban/filter.d/syswarden-openvpn-custom.conf":    {"f0a90c8777cc9315a783d5b245abb1e39322898c9f3ac2e20d738455cbb44f01", "src/jails/23-openvpn.sh"},
	"/etc/fail2ban/filter.d/syswarden-phpmyadmin-custom.conf": {"187686bae543464d7e6e692b20289a48a3364c9c3c119853bf95b320a721cd98", "src/jails/16-phpmyadmin.sh"},
	"/etc/fail2ban/filter.d/syswarden-prestashop.conf":        {"9effe5bcbb8c9c8f9b73fb385e1aa2bfe1dcef124f9e9680c51acb2ee458e544", "src/jails/49-prestashop.sh"},
	"/etc/fail2ban/filter.d/syswarden-privesc.conf":           {"34fe86e37284ae82eb3339d69921763226fd94054ff6a554be71a33fb32b24eb", "src/jails/26-privesc.sh"},
	"/etc/fail2ban/filter.d/syswarden-proxmox-custom.conf":    {"b8a871f85877b01c2bfae5dde7201c7c96f9acc5aef1b987d8804c4e7e5f1882", "src/jails/22-proxmox.sh"},
	"/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf":       {"cd472ddeca704812e62edf8b99f4bc3a0262df7a8c4d770b02abb10599fc85ad", "src/jails/45-proxy-abuse.sh"},
	"/etc/fail2ban/filter.d/syswarden-rabbitmq.conf":          {"8093fdbd0ddfe8ced333e8b2f4c75c3e0cf7adf41352bf6337da1734159bd70c", "src/jails/28_5-rabbitmq.sh"},
	"/etc/fail2ban/filter.d/syswarden-recidive.conf":          {"7aba83c54640006d0fb78eb57f501351431f2c191ac657d83936c4e4d18ade7f", "src/functions/configure_fail2ban.sh"},
	"/etc/fail2ban/filter.d/syswarden-redis.conf":             {"b649e0b3410215856ea92e17f66dba00ac9cd5471d456860af4e1c9c2e633709", "src/jails/28-redis.sh"},
	"/etc/fail2ban/filter.d/syswarden-revshell.conf":          {"10689f67389cee4048f839229a66172f2ba82b827a47c8322f8a25d6e8ad9bbc", "src/jails/31-revshell.sh"},
	"/etc/fail2ban/filter.d/syswarden-secretshunter.conf":     {"ec20db9df7f9b94014d97bd1e1adbf7550348c3b541f1fcdf6c6cdfb90e2852f", "src/jails/38-secretshunter.sh"},
	"/etc/fail2ban/filter.d/syswarden-silent-scanner.conf":    {"cf97d646a5fdda0d3b1e7d09f6a5be2b38276b6768e7f6253fcfc30c71117e4e", "src/jails/44-silent-scanner.sh"},
	"/etc/fail2ban/filter.d/syswarden-slowloris.conf":         {"55b4bc84f6877908f5b3e613cc945fd1ab362ae98937a791dd6230514c95b7c8", "src/jails/55-slowloris.sh"},
	"/etc/fail2ban/filter.d/syswarden-sqli-xss.conf":          {"541fa6aaf74d58632f8bfcb9d1f20d4811b6d2708d058723fe7d899429ff6a53", "src/jails/37-sqli-xss.sh"},
	"/etc/fail2ban/filter.d/syswarden-sso.conf":               {"f8ee096747fbee1f4bfd28a0ee8076c668c7dfff868d928db4cf8db3e4ea81c0", "src/jails/43-sso.sh"},
	"/etc/fail2ban/filter.d/syswarden-ssrf.conf":              {"1d47969e6be7859fcd0e9d609db073a064c6b05165ca9a0b7ffa9bce2efa7b12", "src/jails/39-ssrf.sh"},
	"/etc/fail2ban/filter.d/syswarden-telnet.conf":            {"3b4630a76e0db236d7c5294cdcd6ceccd7b64ddc75d3cf366a74a90e58dbcc01", "src/jails/46-telnet.sh"},
	"/etc/fail2ban/filter.d/syswarden-tls-guard.conf":         {"bcd1552f0eb4ba694a725c94fb8488767dbcaa41f7c9962efe15e73adbf2bd9a", "src/jails/52-nginx-tls.sh"},
	"/etc/fail2ban/filter.d/syswarden-vaultwarden.conf":       {"b24141f4f162ca3ceab1a7ae763381ee05eddede7bcb0120759e880afd68a371", "src/jails/42-vaultwarden.sh"},
	"/etc/fail2ban/filter.d/syswarden-webshell.conf":          {"f77f0b0f9d429c967816cba278d3db7a84c0425e2921be3ad9bb24cee2707275", "src/jails/36-webshell.sh"},
	"/etc/fail2ban/filter.d/syswarden-wireguard.conf":         {"b44881545a32dd3e3820a8b7ed62c7ef5f8a3b1eaf3ec4443c34173669f5b33e", "src/jails/15-wireguard.sh"},
	"/etc/fail2ban/filter.d/syswarden-wordpress-auth.conf":    {"fabcaf9d0ef8b670dac0f92ddbdd3df08d8fd8d66f8131e5e222b3afcae48b62", "src/jails/10-wordpress.sh"},
	"/etc/fail2ban/filter.d/syswarden-zabbix-auth.conf":       {"e17759486da461a57924a8eef24cb3fa9e957d3be3e5cb29551dde90f187ae2f", "src/jails/13-zabbix.sh"},
}
