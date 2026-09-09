# MMDF Android Client

Custom Android client implementing the **MITM + DomainFronting** method — no server, no relay account, no worker. Inspired by [patterniha/MITM-DomainFronting](https://github.com/patterniha/MITM-DomainFronting) (method) and [MasterHttpRelayVPN-RUST](https://github.com/therealaleph/MasterHttpRelayVPN-RUST) (Android plumbing patterns: VpnService + tun2proxy + JNI + per-ABI APKs).

## How it works

```
browser/app → local proxy (HTTP 127.0.0.1:8080 / SOCKS5 127.0.0.1:1081)
                    │
        ┌───────────┴────────────┐
        │ target in a front group │
        ▼                         ▼ (no)
  1. MITM: TLS-terminate locally   direct TCP to the real host
     with YOUR on-device CA
  2. Re-send plaintext inside a NEW
     TLS connection to connect_ip:443
     with SNI = benign front domain
        │
        ▼
  censor sees: "TLS to www.google.com"
  edge routes by HTTP Host → real site
```

Concretely (same idea as the reference Xray config):

1. **MITM leg** — the proxy answers `CONNECT example.com:443`, presents a
   freshly-minted leaf cert for that hostname signed by your own CA
   (you trust it once in Android Settings). The browser then speaks
   plaintext to us.
2. **Fronted leg** — we open TCP to `connect_ip:443` (a Google edge IP)
   and TLS-handshake with `SNI = www.google.com` (or the group's SNI).
   Inside, normal HTTP with `Host: <real site>` flows. The censor only
   sees the outer SNI.

Working groups ship by default: **Google/YouTube**, **Meta/Instagram/
WhatsApp**, **Fastly/Reddit/GitHub-assets**, **DNS providers** — plus any
custom domains you add in the app (they ride the default front leg).

## Setup (phone)

1. Install the APK from [Releases](../../releases/latest)
   (`mmdf-android-universal-v*.apk`, or the per-ABI file for your device).
2. Open the app → **Install MITM certificate** → confirm in Settings
   (install `mmdf-ca.crt` as a **CA certificate**, needs a screen lock).
3. Check `connect_ip` / front SNIs (defaults work in most regions;
   use **Test all** to verify each SNI handshakes).
4. **Connect** → accept the VPN prompt. All device traffic now routes
   through the TUN → tun2proxy → local proxy.

> The CA private key never leaves your phone. Never share `mmdf-ca.crt`
> with anyone, and never install someone else's.

## Desktop use (same crate)

```bash
./mmdf-client --gen-config > mmdf.toml   # edit connect_ip / groups
./mmdf-client --config mmdf.toml
# then point your browser proxy at 127.0.0.1:8080
```

## Releases

Push a tag `vX.Y.Z` (e.g. `git tag v1.0.0 && git push origin v1.0.0`)
and the `release` workflow builds the universal + per-ABI APKs, bumps
`Cargo.toml` / `versionName` / `versionCode` from the tag, and publishes
everything to the GitHub Release page. Every successful build therefore
ships a new version automatically.
