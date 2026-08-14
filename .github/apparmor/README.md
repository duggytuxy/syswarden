# Bubblewrap policy for GitHub-hosted CI

`bwrap-userns-restrict` is vendored byte for byte from the upstream AppArmor
repository at commit
`7f35adef41d3d1646755df1ade0ef46354c39785`. Its expected SHA-256 is
`a964037f6cf0df1099f14226b037eaedde6237c86e715188e93eb460b30be859`.
The pinned upstream source is
<https://gitlab.com/apparmor/apparmor/-/raw/7f35adef41d3d1646755df1ade0ef46354c39785/profiles/apparmor/profiles/extras/bwrap-userns-restrict>.
The upstream policy is licensed under GPL-2.0-or-later.

Ubuntu 24.04 restricts unprivileged user namespaces. The policy allows
Bubblewrap to acquire the capabilities needed to construct its sandbox, then
stacks every executed child with `unpriv_bwrap`, which denies capabilities.
The Security Audit workflow loads this policy only on the disposable
GitHub-hosted runner. Act continues to use its verified container isolation
path and does not load a host AppArmor policy.

Updating this file requires review of the upstream commit, a new exact digest,
and successful execution of the fail-closed Bubblewrap probe and firewall
golden test.
