=== Flak Jacket ===
Contributors: donvoorhies
Tags: security, hardening, login protection, security headers, wordpress security
Requires at least: 5.9
Tested up to: 6.5
Requires PHP: 8.0
Stable tag: 1.0.0
License: GPL-2.0+

Lightweight WordPress protection. No bloat, no cloud, no monthly fee.

== Description ==

Flak Jacket is a manual WordPress hardening plugin for personal sites and
portfolios. It does not apply any changes automatically — every protection
is a conscious decision by the site owner.

The dashboard shows the current state of every hardening item in plain English,
colour-coded green, amber, or red. You decide what to enable. Flak Jacket
just makes sure you know what's protected and what isn't.

No SaaS. No telemetry. No cloud dashboard. No upsell.

Designed to run alongside OAP, CCCP, and critical-path-css-v2 without conflicts.

== Why manual? ==

Because you should know what's protecting your site.
Silent auto-hardening is how you end up locked out of your own admin panel.
Flak Jacket shows you the threats — you decide how to respond.

== Installation ==

1. Upload the `flak-jacket` folder to `/wp-content/plugins/`.
2. Activate the plugin through the Plugins screen.
3. Open **Flak Jacket** in wp-admin.
4. Review each protection and enable only what you want.

== What it includes ==

- Hardening score dashboard with status indicators
- Login attempt limiting with lockout telemetry
- Rename login URL with admin IP fallback support
- User-level TOTP 2FA and backup codes
- Individually toggleable security headers
- Managed `.htaccess` hardening block
- WordPress exposure controls with OAP overlap awareness

== Compatibility ==

Flak Jacket checks for:

- OAP (Optimization Anthology Plugin)
- CCCP (Clean Cookie Consent)
- critical-path-css-v2

When OAP is active, overlapping controls are marked as handled externally.

== Developer hook ==

To trust proxy/CDN headers for client IP detection, supply trusted reverse
proxy addresses via the `fj_trusted_proxy_ips` filter.

Example:

`add_filter('fj_trusted_proxy_ips', function () { return ['203.0.113.10', '203.0.113.0/24', '2001:db8::/32']; });`

== Changelog ==

= 1.0.0 =
- Initial stable release.
- Hardened client IP detection to trust forwarded headers only from trusted proxies, with `fj_trusted_proxy_ips` support for IP and CIDR entries.
