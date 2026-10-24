# Disposable native-lab fixtures only. This file is embedded by the lifecycle
# runner, never installed as a product hook or run on the operator's host.

v5_apk_removal_profile() {
    case "${SCENARIO}" in remove|purge) ;; *) return 1 ;; esac
    package_uses_apk_recovery_payload candidate
}

configure_operator_fixture_paths() {
    FIXTURE_CONFIG=/etc/syswarden/config/lifecycle-operator.conf
    FIXTURE_DATA=/var/lib/syswarden/ui/lifecycle-operator.json
    FIXTURE_CERTIFICATE=/etc/syswarden/tls/operator.pem
    if v5_apk_removal_profile; then
        FIXTURE_CONFIG=/etc/lifecycle-operator/lifecycle-operator.conf
        FIXTURE_DATA=/var/lib/lifecycle-operator/lifecycle-operator.json
        FIXTURE_CERTIFICATE=/etc/lifecycle-operator/operator.pem
    fi
}

fixture_plan_digest() {
    # A single canonical digest is required. Never select the first of multiple
    # plans or evaluate the suggested shell command in human-readable output.
    awk '/^Plan SHA-256: / { n++; value=$3 }
        END { if (n != 1 || length(value) != 64 || value ~ /[^0-9a-f]/) exit 1; print value }' "$1"
}

review_fixture_cron() {
    v5_apk_removal_profile || return 1
    /opt/syswarden/bin/syswarden-cli recover-removal --retire-legacy-cron > /results/cron-plan || return 1
    digest=$(fixture_plan_digest /results/cron-plan) || return 1
    /opt/syswarden/bin/syswarden-cli recover-removal --retire-legacy-cron --apply --plan-sha256 "${digest}" || return 1
    # Authorization covers only the exact laboratory record. Every other byte
    # must survive, including comments, whitespace and unrelated cron entries.
    awk '$0 != "17 * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1"' /tmp/syswarden-root-cron-before > /results/reviewed-cron-expected || return 1
    LC_ALL=C crontab -l > /results/reviewed-cron-actual || return 1
    cmp -s /results/reviewed-cron-expected /results/reviewed-cron-actual || return 1
    cp /results/reviewed-cron-expected /tmp/syswarden-root-cron-before || return 1
}

review_fixture_lists() {
    v5_apk_removal_profile || return 1
    /opt/syswarden/bin/syswarden-cli recover-removal --retain-legacy-lists > /results/lists-plan || return 1
    digest=$(fixture_plan_digest /results/lists-plan) || return 1
    sed '/^Plan SHA-256:/,$d' /results/lists-plan > /results/lists-plan.json || return 1
    jq -e '[.files[].path] | sort == ["/etc/syswarden/lists/.syswarden_blacklist_pair_v1", "/etc/syswarden/lists/.syswarden_whitelist_pair_v1", "/etc/syswarden/lists/syswarden_blacklist.ipv4", "/etc/syswarden/lists/syswarden_blacklist.ipv6", "/etc/syswarden/lists/syswarden_whitelist.ipv4", "/etc/syswarden/lists/syswarden_whitelist.ipv6"]' /results/lists-plan.json >/dev/null || return 1
    jq -r '.files[] | [.path, .sha256] | @tsv' /results/lists-plan.json > /results/lists-original-hashes || return 1
    /opt/syswarden/bin/syswarden-cli recover-removal --retain-legacy-lists --apply --plan-sha256 "${digest}" > /results/lists-applied || return 1
    archive=$(awk '/^Legacy data retention completed. Private backup: / {print $NF}' /results/lists-applied)
    case "${archive}" in /var/backups/syswarden-retired-v1/*) ;; *) return 1 ;; esac
    [ "$(hash_file "${archive}/syswarden_blacklist.ipv4")" = "${STATE_LIST_HASH}" ] || return 1
    [ "$(hash_file "${archive}/syswarden_blacklist.ipv6")" = "${STATE_LIST_IPV6_HASH}" ] || return 1
    while IFS="$(printf '\t')" read -r original hash; do
        [ "$(hash_file "${archive}/${original##*/}")" = "${hash}" ] || return 1
    done < /results/lists-original-hashes
    printf '%s\n' "${archive}" > /results/list-retention-directory || return 1
}

review_fixture_ui_and_config() {
    v5_apk_removal_profile || return 1
    /opt/syswarden/bin/syswarden-cli recover-removal --retain-legacy-ui > /results/ui-plan || return 1
    digest=$(fixture_plan_digest /results/ui-plan) || return 1
    sed '/^Plan SHA-256:/,$d' /results/ui-plan > /results/ui-plan.json || return 1
    jq -e '[.files[].path] | sort == ["/var/lib/syswarden/ui/data.json", "/var/lib/syswarden/ui/metrics_24h.json"]' /results/ui-plan.json >/dev/null || return 1
    /opt/syswarden/bin/syswarden-cli recover-removal --retain-legacy-ui --apply --plan-sha256 "${digest}" > /results/ui-applied || return 1
    archive=$(awk '/^Legacy data retention completed. Private backup: / {print $NF}' /results/ui-applied)
    case "${archive}" in /var/backups/syswarden-retired-v1/*) ;; *) return 1 ;; esac
    jq -r '.files[] | [.path, .sha256] | @tsv' /results/ui-plan.json > /results/ui-original-hashes || return 1
    while IFS="$(printf '\t')" read -r original hash; do
        case "${original}" in /var/lib/syswarden/ui/*.json) ;; *) return 1 ;; esac
        [ "$(hash_file "${archive}/${original##*/}")" = "${hash}" ] || return 1
    done < /results/ui-original-hashes
    printf '%s\n' "${archive}" > /results/ui-retention-directory || return 1

    /opt/syswarden/bin/syswarden-cli recover-removal --retain-operator-config > /results/operator-config-plan || return 1
    digest=$(fixture_plan_digest /results/operator-config-plan) || return 1
    sed '/^Plan SHA-256:/,$d' /results/operator-config-plan > /results/operator-config-plan.json || return 1
    # The fixture authorizes exactly its own TOML, never a discovered file.
    jq -e '.files | length == 1 and .[0].path == "/etc/syswarden/config/modules/99-user.toml"' /results/operator-config-plan.json >/dev/null || return 1
    jq -r '.files[].path' /results/operator-config-plan.json > /results/operator-config-paths || return 1
    capture_retained_config > /results/operator-config-before || return 1
    /opt/syswarden/bin/syswarden-cli recover-removal --retain-operator-config --apply --plan-sha256 "${digest}" || return 1
}

capture_retained_config() {
    while IFS= read -r retained; do
        [ -f "${retained}" ] && [ ! -L "${retained}" ] || return 1
        stat -c '%d:%i:%s:%u:%g:%a:%y:%z %n' "${retained}" || return 1
        sha256sum "${retained}" || return 1
    done < /results/operator-config-paths
}

prepare_v5_apk_removal() {
    v5_apk_removal_profile || return 0
    run_step reviewed-cron-recovery review_fixture_cron || return 1
    run_step reviewed-list-recovery review_fixture_lists || return 1
    run_step reviewed-ui-config-recovery review_fixture_ui_and_config || return 1
}

seed_operator_firewall() {
    v5_apk_removal_profile || return 0
    # This unrelated protection belongs to the disposable lab only. Its own
    # table is the only table its reload/stop operations may change.
    [ ! -e /etc/init.d/lifecycle-operator ] || return 1
    [ "$(command -v nft)" = /usr/sbin/nft ] || return 1
    apk info --who-owns /usr/sbin/nft || return 1
    cat > /etc/lifecycle-operator/firewall.nft <<'EOF'
add table inet lifecycle_operator
flush table inet lifecycle_operator
add chain inet lifecycle_operator output { type filter hook output priority -300; policy accept; }
add rule inet lifecycle_operator output ip daddr 127.0.0.2 ip protocol icmp counter drop
EOF
    cat > /etc/init.d/lifecycle-operator <<'EOF'
#!/sbin/openrc-run
description="Disposable lifecycle laboratory operator firewall"
start() { /usr/sbin/nft -f /etc/lifecycle-operator/firewall.nft; }
stop() { /usr/sbin/nft delete table inet lifecycle_operator; }
EOF
    chmod 0600 /etc/lifecycle-operator/firewall.nft || return 1
    chmod 0755 /etc/init.d/lifecycle-operator || return 1
    sha256sum /etc/lifecycle-operator/firewall.nft /etc/init.d/lifecycle-operator > /results/operator-firewall-sha256 || return 1
    rc-update add lifecycle-operator default || return 1
    rc-service lifecycle-operator start || return 1
    probe_operator_firewall
}

probe_operator_firewall() {
    sha256sum -c /results/operator-firewall-sha256 || return 1
    [ -L /etc/runlevels/default/lifecycle-operator ] || return 1
    rc-service lifecycle-operator status || return 1
    before=$(nft -j list chain inet lifecycle_operator output | jq -er '[.nftables[].rule? | select(. != null) | .expr[].counter?.packets? | select(. != null)] | if length == 1 then .[0] else error("counter inventory") end') || return 1
    if ping -n -c 1 -W 1 127.0.0.2; then return 1; fi
    after=$(nft -j list chain inet lifecycle_operator output | jq -er '[.nftables[].rule? | select(. != null) | .expr[].counter?.packets? | select(. != null)] | if length == 1 then .[0] else error("counter inventory") end') || return 1
    [ "${after}" -gt "${before}" ]
}

reload_operator_firewall() {
    rc-service lifecycle-operator restart || return 1
    probe_operator_firewall
}

finish_v5_apk_removal() {
    v5_apk_removal_profile || return 0
    run_step product-rules.removed assert_product_rules_absent || return 1
    run_step recovery-payload.removed assert_apk_recovery_payload || return 1
    run_step operator-protection.removed probe_operator_firewall || return 1
    run_step operator-protection.reload reload_operator_firewall || return 1
    run_step product-rules.reloaded assert_product_rules_absent || return 1
    assert_v5_generated_artifacts_absent || return 1
    cp /tmp/syswarden-root-cron-before /results/root-cron-retained || return 1
    printf '%s\n' restart-one > "${RESTART_STATE_FILE}"
}

scenario_v5_apk_removal_restart() {
    v5_apk_removal_profile || return 1
    load_state_contract || return 1
    configure_operator_fixture_paths
    prepare_service_runtime_fixture || return 1
    assert_package_absent restart-one candidate
    label=restart-one
    assert_dedicated_roots_absent "${label}" || return 1
    assert_v5_generated_artifacts_absent || return 1
    run_step product-rules.restart assert_product_rules_absent || return 1
    run_step recovery-payload.restart assert_apk_recovery_payload || return 1
    archive=$(cat /results/list-retention-directory) || return 1
    [ "$(hash_file "${archive}/syswarden_blacklist.ipv4")" = "${STATE_LIST_HASH}" ] || return 1
    [ "$(hash_file "${archive}/syswarden_blacklist.ipv6")" = "${STATE_LIST_IPV6_HASH}" ] || return 1
    while IFS="$(printf '\t')" read -r original hash; do
        [ "$(hash_file "${archive}/${original##*/}")" = "${hash}" ] || return 1
    done < /results/lists-original-hashes
    archive=$(cat /results/ui-retention-directory) || return 1
    while IFS="$(printf '\t')" read -r original hash; do
        [ "$(hash_file "${archive}/${original##*/}")" = "${hash}" ] || return 1
    done < /results/ui-original-hashes
    LC_ALL=C crontab -l > /results/root-cron-after-restart || return 1
    cmp -s /results/root-cron-retained /results/root-cron-after-restart || return 1
    openrc_rsyslog_runtime_snapshot >/dev/null || return 1
    run_step operator-protection.restart probe_operator_firewall || return 1
    record pass "${PREFIX}.restart-one.no_recreation" "product artifacts remain absent and unrelated cron and rsyslog remain operational after a real restart"
    printf '%s\n' complete > "${RESTART_STATE_FILE}"
}

assert_fixture_configuration_retained() {
    capture_retained_config > /results/operator-config-after || return 1
    if cmp -s /results/operator-config-before /results/operator-config-after; then
        record pass "${PREFIX}.${label}.state.operator_config_retained" "approved administrator TOML retains exact bytes and metadata"
    else
        record fail "${PREFIX}.${label}.state.operator_config_retained" "approved administrator TOML changed"
    fi
    # Empty product directories and links are residuals too. Only the retained
    # administrator file and its required ancestors may remain.
    printf '%s\n' /etc/syswarden /etc/syswarden/config /etc/syswarden/config/modules /etc/syswarden/config/modules/99-user.toml > /results/expected-config-tree || return 1
    find /etc/syswarden | LC_ALL=C sort > /results/final-config-paths || return 1
    if cmp -s /results/expected-config-tree /results/final-config-paths; then
        record pass "${PREFIX}.${label}.state.config_root" "only the explicitly retained administrator TOML remains"
    else
        record fail "${PREFIX}.${label}.state.config_root" "unexpected configuration object remains"
    fi
    assert_preserved "${label}" unrelated_config "${FIXTURE_CONFIG}" "${STATE_CONFIG_HASH}" 640
    assert_preserved "${label}" unrelated_ui "${FIXTURE_DATA}" "${STATE_OPERATOR_DATA_HASH}" 600
    assert_preserved "${label}" unrelated_certificate "${FIXTURE_CERTIFICATE}" "${STATE_CERT_HASH}" 600
}

assert_product_rules_absent() {
    nft -j list tables > /results/tables-current.json || return 1
    jq -e '[.nftables[].table?.name? | select(. != null and startswith("syswarden"))] | length == 0' /results/tables-current.json >/dev/null
}

assert_apk_recovery_payload() {
    private=/var/backups/syswarden-retired-v1
    [ -d "${private}" ] && [ ! -L "${private}" ] || return 1
    [ "$(stat -c '%u:%g:%a' "${private}")" = 0:0:700 ] || return 1
    set -- "${private}"/apk-payload-*
    [ "$#" -eq 1 ] && [ -d "$1" ] && [ ! -L "$1" ] || return 1
    saved="$1"
    suffix="${saved##*/apk-payload-}"
    [ "${#suffix}" -eq 64 ] || return 1
    case "${suffix}" in *[!0-9a-f]*) return 1 ;; esac
    for directory in "${saved}" "${saved}/bin"; do
        [ -d "${directory}" ] && [ ! -L "${directory}" ] || return 1
        [ "$(stat -c '%u:%g:%a' "${directory}")" = 0:0:750 ] || return 1
    done
    printf '%s\n' "${saved}/bin" "${saved}/bin/syswarden-cli" "${saved}/bin/syswarden-core" "${saved}/bin/syswarden-tui" "${saved}/signatures.json" > /results/expected-recovery-tree || return 1
    find "${saved}" -mindepth 1 | LC_ALL=C sort > /results/actual-recovery-tree || return 1
    cmp -s /results/expected-recovery-tree /results/actual-recovery-tree || return 1
    for relative in bin/syswarden-cli bin/syswarden-core bin/syswarden-tui signatures.json; do
        expected=$(awk -F '\t' -v path="/opt/syswarden/${relative}" '$1 == path && $2 == "file" && $4 == "0" && $5 == "0" { n++; digest=$6 } END { if (n != 1) exit 1; print digest }' "${PERSIST_ROOT}/inventory-candidate") || return 1
        mode=750
        [ "${relative}" != signatures.json ] || mode=640
        [ -f "${saved}/${relative}" ] && [ ! -L "${saved}/${relative}" ] || return 1
        [ "$(stat -c '%u:%g:%a:%h' "${saved}/${relative}")" = "0:0:${mode}:1" ] || return 1
        [ "$(hash_file "${saved}/${relative}")" = "${expected}" ] || return 1
    done
    # The retained CLI must also remain executable after dependency erasure.
    "${saved}/bin/syswarden-cli" --help >/dev/null
}

assert_v5_generated_artifacts_absent() {
    while IFS= read -r artifact; do
        [ ! -e "${artifact}" ] && [ ! -L "${artifact}" ] || return 1
    done <<'EOF'
/etc/systemd/system/syswarden-core.service
/etc/systemd/system/syswarden-firewall.service
/etc/systemd/system/syswarden-webtui.service
/etc/init.d/syswarden-core
/etc/init.d/syswarden-firewall
/etc/init.d/syswarden-webtui
/etc/systemd/system/multi-user.target.wants/syswarden-core.service
/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service
/etc/runlevels/default/syswarden-core
/etc/runlevels/default/syswarden-firewall
/run/syswarden.sock
/run/syswarden-firewall.lock
/etc/modprobe.d/syswarden-cis-fs.conf
/etc/modprobe.d/.syswarden-cis-fs.conf.syswarden-removal-v1
/etc/modprobe.d/syswarden-cis-net.conf
/etc/modprobe.d/.syswarden-cis-net.conf.syswarden-removal-v1
/etc/security/limits.d/99-syswarden-cis.conf
/etc/security/limits.d/.99-syswarden-cis.conf.syswarden-removal-v1
/etc/sysctl.d/99-syswarden-cis-level2.conf
/etc/sysctl.d/.99-syswarden-cis-level2.conf.syswarden-removal-v1
/etc/systemd/coredump.conf.d/99-syswarden.conf
/etc/systemd/coredump.conf.d/.99-syswarden.conf.syswarden-removal-v1
/etc/rsyslog.d/99-syswarden-antiforging.conf
/etc/rsyslog.d/.syswarden-rsyslog-selinux-provenance-v1
/etc/rsyslog.d/99-syswarden-siem.conf
/etc/rsyslog.d/99-syswarden-waf-bridge.conf
/etc/rsyslog.d/.syswarden-rsyslog-provenance-v1
/etc/bash_completion.d/syswarden
/etc/cron.d/syswarden
/etc/cron.d/.syswarden.pending-v1
EOF
}
