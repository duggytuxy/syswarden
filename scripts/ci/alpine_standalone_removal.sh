# Prepared standalone-removal fixture only. Embedded by the explicit native
# runner after the common lifecycle function definitions, never shipped.
[ "${SCENARIO}" = standalone-uninstall ] || exit 93
[ "${PACKAGE_FAMILY}" = apk ] || exit 93
# Create this fixture's synthetic historical roots with the private modes that
# package preparation normally supplies. Do not chmod existing operator data.
umask 027

# Reuse reviewed preservation assertions, without changing the native runner's
# profile or event contract. No package installation or erasure is permitted.
v5_apk_removal_profile() { [ "${SCENARIO}" = standalone-uninstall ]; }
install_package() { return 93; }
remove_package() { return 93; }
purge_package() { return 93; }

# Shared helpers emit detailed checks, including failures that do not change
# their exit status. A required step fails if either channel reports failure.
record() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> /results/details.tsv
    if [ "$1" = fail ]; then FAILURES=$((FAILURES + 1)); fi
}
required_step() {
    required_name="$1"
    shift
    required_before="${FAILURES}"
    printf 'COMMAND standalone-uninstall.%s\n' "${required_name}" >> "${COMMAND_LOG}"
    if "$@" >> "${COMMAND_LOG}" 2>&1 && [ "${FAILURES}" -eq "${required_before}" ]; then
        printf 'pass\tstandalone-uninstall.%s\tcommand and all nested checks passed\n' "${required_name}" >> "${RESULT_FILE}"
    else
        printf 'fail\tstandalone-uninstall.%s\tcommand or nested assertion failed\n' "${required_name}" >> "${RESULT_FILE}"
        return 1
    fi
}

assert_unregistered() {
    if LC_ALL=C apk info --quiet -e syswarden > /results/registration-query 2>&1; then
        return 1
    else
        [ "$?" -eq 1 ] && [ ! -s /results/registration-query ] || return 1
    fi
}
native_inventory() {
    for path in /lib/apk/db/installed /etc/apk/world; do
        [ -f "${path}" ] && [ ! -L "${path}" ] || return 1
        stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z %n' "${path}" || return 1
        sha256sum "${path}" || return 1
    done
}
snapshot_native_inventory() {
    assert_unregistered || return 1
    native_inventory > /results/native-before
}
assert_native_unchanged() {
    assert_unregistered || return 1
    native_inventory > /results/native-after || return 1
    cmp -s /results/native-before /results/native-after
}

stage_standalone_payload() {
    for path in /opt/syswarden /usr/local/bin/syswarden /usr/local/bin/syswarden-tui \
        /usr/share/bash-completion/completions/syswarden /etc/apk/commit_hooks.d/syswarden-recovery; do
        [ ! -e "${path}" ] && [ ! -L "${path}" ] || return 1
    done
    (cd /candidate/payload && sha256sum -c ../payload.sha256) || return 1
    mkdir -p /opt/syswarden/bin /usr/local/bin /usr/share/bash-completion/completions || return 1
    chmod 0750 /opt/syswarden /opt/syswarden/bin || return 1
    for binary in syswarden-cli syswarden-core syswarden-tui; do
        install -m 0750 "/candidate/payload/opt/syswarden/bin/${binary}" "/opt/syswarden/bin/${binary}" || return 1
    done
    install -m 0640 /candidate/payload/opt/syswarden/signatures.json /opt/syswarden/signatures.json || return 1
    install -m 0644 /candidate/payload/usr/share/bash-completion/completions/syswarden /usr/share/bash-completion/completions/syswarden || return 1
    ln -s /opt/syswarden/bin/syswarden-cli /usr/local/bin/syswarden || return 1
    ln -s /opt/syswarden/bin/syswarden-tui /usr/local/bin/syswarden-tui || return 1
    cp /candidate/inventory-candidate "${PERSIST_ROOT}/inventory-candidate" || return 1
    /opt/syswarden/bin/syswarden-cli completion bash > /results/completion-rendered || return 1
    cmp -s /results/completion-rendered /usr/share/bash-completion/completions/syswarden || return 1
    assert_native_unchanged
}

write_seeded_operator_token() {
    cat > "$1" <<'EOF'
[network]
interfaces = "lo"
[network.blocklists]
list_choice = "4"
custom_url = ""
custom_url_ipv6 = ""
custom_hash = ""
custom_hash_ipv6 = ""
use_spamhaus = false
[integrations.siem]
enabled = true
ip = "127.0.0.1"
port = "5514"
protocol = "udp"
tls_ca = ""
[user]
profile_name = "lifecycle-operator"
EOF
}
activate_prepared_fixture() {
    # These existing initialization opt-ins avoid package acquisition and feed
    # downloads. They do not register the payload, and are never inherited by
    # uninstall. This is not standalone installation qualification.
    env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        LANG=C LC_ALL=C SYSWARDEN_PKG_INSTALL=1 SYSWARDEN_OFFLINE_QUALIFICATION=activate \
        /opt/syswarden/bin/syswarden-cli install || return 1
    assert_native_unchanged
}
assert_active_product() {
    prepare_service_runtime_fixture || return 1
    rc-service syswarden-core status || return 1
    rc-service syswarden-firewall status || return 1
    nft -j list tables > /results/tables-installed.json || return 1
    jq -e '[.nftables[].table?.name? | select(. != null and startswith("syswarden"))] | length > 0' /results/tables-installed.json >/dev/null || return 1
    wait_for_standalone_telemetry
}
wait_for_standalone_telemetry() {
    standalone_telemetry_contract="$(live_telemetry_contract_for_version "${EXPECTED_CANDIDATE_VERSION}")" || return 1
    [ "${standalone_telemetry_contract}" = kpi-feed-v1 ] || return 1
    attest_installed_core_process || return 1
    : "${core_runtime_pid:?}" "${core_runtime_identity:?}" "${core_runtime_sha256:?}"
    standalone_core_identity="${core_runtime_pid}:${core_runtime_identity}:${core_runtime_sha256}"
    standalone_expected_core=$(awk -F '\t' '$1 == "/opt/syswarden/bin/syswarden-core" && $2 == "file" { n++; digest=$6 } END { if (n != 1) exit 1; print digest }' "${PERSIST_ROOT}/inventory-candidate") || return 1
    [ "${core_runtime_sha256}" = "${standalone_expected_core}" ] || return 1
    standalone_wait=0
    while [ "${standalone_wait}" -lt 45 ]; do
        attest_installed_core_process || return 1
        [ "${core_runtime_pid}:${core_runtime_identity}:${core_runtime_sha256}" = "${standalone_core_identity}" ] || return 1
        if live_telemetry_schema_valid /var/lib/syswarden/ui/data.json "${standalone_telemetry_contract}"; then
            attest_installed_core_process || return 1
            [ "${core_runtime_pid}:${core_runtime_identity}:${core_runtime_sha256}" = "${standalone_core_identity}" ] || return 1
            return 0
        fi
        standalone_wait=$((standalone_wait + 1))
        sleep 1 || return 1
    done
    return 1
}
uninstall_standalone() {
    assert_native_unchanged || return 1
    env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        LANG=C LC_ALL=C /opt/syswarden/bin/syswarden-cli uninstall
}

assert_standalone_recovery() {
    private=/var/backups/syswarden-retired-v1
    [ -d "${private}" ] && [ ! -L "${private}" ] || return 1
    [ "$(stat -c '%u:%g:%a' "${private}")" = 0:0:700 ] || return 1
    set -- "${private}"/standalone-payload-*
    [ "$#" -eq 1 ] && [ -d "$1" ] && [ ! -L "$1" ] || return 1
    saved="$1"
    for directory in "${saved}" "${saved}/bin"; do
        [ -d "${directory}" ] && [ ! -L "${directory}" ] || return 1
        [ "$(stat -c '%u:%g:%a' "${directory}")" = 0:0:750 ] || return 1
    done
    printf '%s\n' "${saved}/bin" "${saved}/bin/syswarden-cli" "${saved}/bin/syswarden-core" "${saved}/bin/syswarden-tui" "${saved}/signatures.json" > /results/expected-recovery-tree || return 1
    find "${saved}" -mindepth 1 | LC_ALL=C sort > /results/actual-recovery-tree || return 1
    cmp -s /results/expected-recovery-tree /results/actual-recovery-tree || return 1
    : > /results/recovery-digest-input
    for relative in bin/syswarden-cli bin/syswarden-core bin/syswarden-tui signatures.json; do
        expected=$(awk -F '\t' -v path="/opt/syswarden/${relative}" '$1 == path && $2 == "file" && $4 == "0" && $5 == "0" { n++; digest=$6 } END { if (n != 1) exit 1; print digest }' "${PERSIST_ROOT}/inventory-candidate") || return 1
        [ "${#expected}" -eq 64 ] || return 1
        case "${expected}" in *[!0-9a-f]*) return 1 ;; esac
        mode=750
        [ "${relative}" != signatures.json ] || mode=640
        [ -f "${saved}/${relative}" ] && [ ! -L "${saved}/${relative}" ] || return 1
        [ "$(stat -c '%u:%g:%a:%h' "${saved}/${relative}")" = "0:0:${mode}:1" ] || return 1
        [ "$(hash_file "${saved}/${relative}")" = "${expected}" ] || return 1
        printf '%s\000%s\n' "${relative}" "${expected}" >> /results/recovery-digest-input || return 1
    done
    expected_name="standalone-payload-$(hash_file /results/recovery-digest-input)-$(printf '%x' "$(stat -c '%d' "${saved}")")-$(printf '%x' "$(stat -c '%i' "${saved}")")" || return 1
    [ "${saved##*/}" = "${expected_name}" ] || return 1
    "${saved}/bin/syswarden-cli" --help >/dev/null
}
assert_retained_data() {
    for kind in lists ui; do
        archive=$(cat "/results/${kind%s}-retention-directory") || return 1
        : > /results/expected-retained-tree
        while IFS="$(printf '\t')" read -r original hash; do
            [ -f "${archive}/${original##*/}" ] && [ ! -L "${archive}/${original##*/}" ] || return 1
            [ "$(hash_file "${archive}/${original##*/}")" = "${hash}" ] || return 1
            printf '%s\n' "${archive}/${original##*/}" >> /results/expected-retained-tree || return 1
        done < "/results/${kind}-original-hashes"
        LC_ALL=C sort -o /results/expected-retained-tree /results/expected-retained-tree || return 1
        find "${archive}" -mindepth 1 | LC_ALL=C sort > /results/actual-retained-tree || return 1
        cmp -s /results/expected-retained-tree /results/actual-retained-tree || return 1
    done
}
assert_standalone_absent() {
    assert_dedicated_roots_absent "${checkpoint}" || return 1
    assert_v5_generated_artifacts_absent || return 1
    for path in /usr/local/bin/syswarden /usr/local/bin/syswarden-tui \
        /usr/share/bash-completion/completions/syswarden /etc/apk/commit_hooks.d/syswarden-recovery; do
        [ ! -e "${path}" ] && [ ! -L "${path}" ] || return 1
    done
    assert_product_rules_absent || return 1
    assert_standalone_recovery || return 1
    assert_retained_data || return 1
    LC_ALL=C crontab -l > /results/root-cron-current || return 1
    cmp -s /results/root-cron-retained /results/root-cron-current || return 1
    openrc_rsyslog_runtime_snapshot >/dev/null || return 1
    assert_native_unchanged
}

standalone_initial() {
    required_step architecture probe_execution_architecture || return 1
    required_step unregistered.before snapshot_native_inventory || return 1
    required_step payload.stage stage_standalone_payload || return 1
    required_step policy.seed seed_complete_removal_configuration || return 1
    required_step state.seed seed_state || return 1
    required_step operator.before seed_operator_firewall || return 1
    required_step fixture.activate activate_prepared_fixture || return 1
    required_step product.active assert_active_product || return 1
    required_step operator.installed probe_operator_firewall || return 1
    required_step runtime.seed seed_generated_runtime_artifacts exact-rsyslog uninstall || return 1
    required_step recovery.review prepare_v5_apk_removal || return 1
    cp /tmp/syswarden-root-cron-before /results/root-cron-retained || return 1
    required_step uninstall uninstall_standalone || return 1
    required_step generated.removed assert_generated_runtime_artifact_contract uninstall exact-rsyslog || return 1
    checkpoint=removed
    required_step absent.removed assert_standalone_absent || return 1
    required_step operator.removed probe_operator_firewall || return 1
    required_step operator.reload reload_operator_firewall || return 1
    checkpoint=reloaded
    required_step absent.reloaded assert_standalone_absent || return 1
    printf '%s\n' restart-one > "${RESTART_STATE_FILE}"
}
standalone_restart() {
    load_state_contract || return 1
    configure_operator_fixture_paths
    required_step runtime.restart prepare_service_runtime_fixture || return 1
    checkpoint=restart
    required_step absent.restart assert_standalone_absent || return 1
    required_step operator.restart probe_operator_firewall || return 1
    printf '%s\n' complete > "${RESTART_STATE_FILE}"
}

case "${INVOCATION}" in
    initial) standalone_initial || exit 1 ;;
    restart-one) standalone_restart || exit 1 ;;
    *) exit 1 ;;
esac
[ "${FAILURES}" -eq 0 ] || exit 1
