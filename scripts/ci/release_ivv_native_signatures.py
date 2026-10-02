"""Recheck the four current package signatures in isolated offline runtimes."""
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys

try:
    from scripts.ci import release_ivv_current as current
except ModuleNotFoundError:
    import release_ivv_current as current


def verify(repository: Path, native: Path, output: Path, current=current) -> dict:
    release = current.load_plan()['release']
    version = release.removeprefix('v')
    frozen = current.frozen
    require = frozen.require
    current.verify_package_inputs(native)
    frozen.bundle.verify_bundle(native, release, current.PRODUCT)
    require(output.is_absolute() and output.parent == output.parent.resolve(strict=True) and
            not output.exists(), 'native verification output must be new')
    output.mkdir(mode=0o700)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONOPTIMIZE='0', LC_ALL='C', TZ='UTC')
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONHOME', None)
    env.pop('SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY', None)
    policy = repository / 'scripts/ci/native_package_signature_policy_v4100.json'
    policy_doc = frozen.strict_json(frozen.bundle.regular_bytes(policy, frozen.MAX_JSON, 'native policy'))
    shim = output / 'runtime-bin'; shim.mkdir(mode=0o700)
    docker = shim / 'docker'
    frozen.bundle.write_exclusive(docker, b'#!/bin/sh\nset -eu\nexec /usr/bin/podman "$@"\n')
    docker.chmod(0o700)
    env['PATH'] = str(shim) + ':' + env['PATH']
    env['SYSWARDEN_APK_SIGNER_IMAGE'] = policy_doc['apk']['signer_image']
    observations = []

    def run(name, argv):
        result = subprocess.run(argv, cwd=repository, env=env, capture_output=True, timeout=180)
        frozen.bundle.write_exclusive(output / (name + '.stdout'), result.stdout)
        frozen.bundle.write_exclusive(output / (name + '.stderr'), result.stderr)
        require(result.returncode == 0, 'native signature verification rejected: ' + name)
        observations.append(dict(name=name, returncode=0,
                                 stdout_sha256=frozen.digest(result.stdout),
                                 stderr_sha256=frozen.digest(result.stderr)))

    provenance = frozen.strict_json((native / 'evidence/NATIVE_SIGNING_PROVENANCE.json').read_bytes())
    frozen.write_new(output / 'standard-inventory.json', dict(schema_version=1, release=release,
                                                            artifacts=provenance['packages']['signed']))
    run('rhel-inventory', [sys.executable, '-E', '-s', '-B',
        str(repository / 'scripts/ci/native_package_signing_bundle.py'), 'rhel-package-owned-inventory',
        '--packages', str(native / 'rhel-package-owned/packages'), '--release', release,
        '--output', str(output / 'rhel-inventory.json')])
    # Validate revocation/expiry as of this new verification, not a supplied historical date.
    as_of = datetime.now(timezone.utc).date().isoformat()
    base = [sys.executable, '-E', '-s', '-B', str(repository / 'scripts/ci/native_package_signature_gate.py'),
            '--rpmkeys', str(repository / 'scripts/ci/ivv_native_rpmkeys.py')]
    common = ['--policy', str(policy), '--release', release, '--as-of', as_of, '--purpose', 'publishing']
    for name, folder, package, inventory, extra in (
        ('rpm', 'packages', f'syswarden-{version}-1.x86_64.rpm', 'standard-inventory.json', []),
        ('rhel-rpm', 'rhel-package-owned/packages', f'syswarden-{version}-1.rhelpo.x86_64.rpm',
         'rhel-inventory.json', ['--package-role', 'rhel-package-owned'])):
        run(name, base + ['rpm', '--inventory', str(output / inventory), '--package', str(native / folder / package),
                         '--key-id', 'rpm-prod-2026-01', '--evidence-output', str(output / (name + '.json'))] + extra + common)
    run('deb', base + ['deb', '--inventory', str(output / 'standard-inventory.json'),
        '--package', str(native / f'packages/syswarden_{version}_amd64.deb'),
        '--signature', str(native / f'packages/syswarden_{version}_amd64.deb.asc'), '--key-id', 'deb-prod-2026-01',
        '--evidence-output', str(output / 'deb.json'), '--gpgv-status-output', str(output / 'deb-gpgv-status.txt'),
        '--gpgv-logger-output', str(output / 'deb-gpgv-logger.txt')] + common)
    run('apk', base + ['apk', '--inventory', str(output / 'standard-inventory.json'),
        '--package', str(native / f'packages/syswarden_{version}_x86_64.apk'), '--key-id', 'apk-prod-2026-01',
        '--apk', str(repository / 'scripts/ci/ivv_native_apk.py'), '--evidence-output', str(output / 'apk.json')] + common)
    current.verify_package_inputs(native)
    frozen.bundle.verify_bundle(native, release, current.PRODUCT)
    return dict(schema='syswarden-current-native-signature-revalidation/v1',
                product_candidate=current.PRODUCT, as_of=as_of, purpose='publishing',
                four_native_signatures_verified=True, offline_verification=True,
                runtime='rootless-podman-pinned-images-stdin-without-host-mounts',
                checks=observations, publication_authorized=False)
