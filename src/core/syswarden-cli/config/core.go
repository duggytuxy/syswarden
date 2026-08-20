package config

type CoreConfig struct {
	ConfigDir       string `mapstructure:"config_dir" validate:"required,absolute_path"`
	EnterpriseMode  bool   `mapstructure:"enterprise_mode"`
	LogLevel        string `mapstructure:"log_level" validate:"required,oneof=DEBUG INFO WARN ERROR"`
	FirewallBackend string `mapstructure:"firewall_backend" validate:"required,oneof=nftables iptables keep"`
	Hardening       bool   `mapstructure:"hardening_enabled"`
	CISL2Hardening  bool   `mapstructure:"cis_l2_hardening"`
	SecureWipeConf  bool   `mapstructure:"secure_wipe_conf"`
	SSHPort         string `mapstructure:"ssh_port" validate:"port"`
}
