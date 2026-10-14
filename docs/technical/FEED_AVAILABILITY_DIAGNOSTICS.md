# Feed Availability Diagnostics

Applies to: published v4.10.4 after signed native testing, protected Patch IVV
and independent public asset verification. The
[publication record](../releases/v4.10.4/README.md) defines the accepted scope.

Older installers displayed a generic mirror latency check before downloading
network intelligence. That check sent an HTTP HEAD request to provider root
URLs. The GitHub raw-content root redirects to the GitHub website, while a
specific raw feed URL can return HTTP 200. Because the probe refused redirects
and accepted only HTTP 200, it could print `FAIL` even when the feed was
available. Its selected-mirror result was already unused by installation.

v4.10.4 removes this obsolete installation probe. It retains actual
feed downloads and their security checks. It does not start following
redirects, choose a single source instead of a quorum, or hide download errors.

For built-in Data-Shield lists, assess the downloader's independent HTTPS
source quorum and provenance result. A successful homepage request does not
validate a feed, and a failed homepage request does not prove a feed outage.
The built-in source inventory, canonical content validation and publication
requirements remain unchanged. Custom feed URLs retain their existing hash
and transport requirements. Offline verification continues to attest existing
feeds without making network requests.

If the downloader itself fails, retain its exact error for private diagnosis.
Differentiate transport or HTTP failures from missing source agreement,
malformed content or failed provenance. A latency message alone cannot
establish which of those occurred. Do not disable TLS validation, redirect
restrictions, feed integrity checks or the source quorum to make a download
appear successful.

The regression checks prohibit pre-download network probes, preserve the
configured feed selection, propagate an actual downloader failure and retain
the offline path. The completed signed-package IVV is recorded in the
publication record. It does not guarantee future availability of external feeds.
