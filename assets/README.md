# SysWarden visual assets

The repository and syswarden.io share a graphite, teal and pale neutral identity.
Keep content readable on both light and dark publication surfaces.

- `syswarden_logo.svg` is the unchanged official logo source. Do not redraw the
  shield, terminal prompt, wordmark or official tagline.
- `syswarden_hero.svg` embeds the official vector geometry on the website's
  graphite background (`#080d13`). Its fixed high-contrast treatment works in
  both GitHub themes without a remote font or script.
- `syswarden-defense-flow.png` is the maintainer-approved transparent illustration
  also used by syswarden.io. It is a conceptual illustration, not a replacement
  logo, packet-flow specification or claim of release qualification. The original
  image was generated with OpenAI image generation and approved by the maintainer
  before integration. Preserve its transparency when preparing derivatives.
- `syswarden-social.png` is a 1200x630 PNG composed from the website identity and
  approved illustration. It is ready for repository social previews. Adding the
  file does not change GitHub's repository social-preview setting.
- Existing architecture and BunkerWeb SVGs retain their technical labels and
  version-specific scope. They are not replaced by the conceptual illustration.

The shared PNG files match website pull request 5:
https://github.com/duggytuxy/syswarden.io/pull/5

Keep release version numbers out of decorative assets. Put version status in
accessible text alongside the image so stable releases, source candidates and
future plans stay distinct. Do not add remote resources, scripts or tracking to
published SVGs.
