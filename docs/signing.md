# Verifying a keychain-auth release

Every release publishes `checksums.txt` and a Sigstore Keyless signature bundle
named `checksums.txt.sigstore.json`. The signature covers the checksum file,
which in turn covers every published archive.

Verify the signature before installing or upgrading:

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/The-17/keychain-auth/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Then verify the archive you downloaded:

```bash
grep '  keychain-auth_4.0.2_linux_amd64.tar.gz$' checksums.txt | sha256sum -c -
```

## What this does and does not prove

The signature proves the checksum file was produced by this repository's
release workflow with a GitHub-issued identity. It does not replace a platform
code-signing certificate. Microsoft SmartScreen reputation and Windows
Authenticode trust require a certificate from a trusted CA and an established
reputation. Sigstore gives cryptographic provenance, which integrators can
check without trusting a blob store.
