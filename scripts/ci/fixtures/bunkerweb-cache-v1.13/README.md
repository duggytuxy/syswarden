# BunkerWeb list-cache regression fixture

These are unchanged public source bytes from `bunkerity/bunkerweb-plugins`,
commit `45c1f989ca558f47a49046098de5586b06fd9ba7`, plugin version 1.13.
The `.txt` extension prevents accidental module discovery. `provenance.json`
records upstream paths, Git blob identities and SHA-256 digests. The upstream
AGPL-3.0 license is retained verbatim in `LICENSE.md.txt`. Original punctuation
in these external fixtures is preserved for integrity.

The offline test executes the pinned download job with fake HTTP, logger and
cache dependencies, and only the reviewed pure helper functions. It performs
no network requests and starts no BunkerWeb worker. The fixture is test data,
not installed plugin code, a new compatibility promise or native acceptance.
The existing plugin 1.11 API snapshot remains unchanged.

Updating this fixture requires review of the new upstream bytes and license,
new digests and explicit regression expectations. Do not fetch moving source
during CI. See [the v5 withdrawal contract](../../../../docs/v5/BUNKERWEB_WITHDRAWAL.md).
