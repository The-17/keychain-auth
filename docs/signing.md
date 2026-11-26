# Verifying a keychain-auth release

Every release publishes `checksums.txt`, a Sigstore Keyless signature bundle for
the checksum file, and a Sigstore bundle for each published archive. The
signature on the checksum file binds the whole release. The per-archive bundle
lets a client verify the exact file it downloaded.

Verify the checksum file before using it:

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/The-17/keychain-auth/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Verify an archive directly:

```bash
cosign verify-blob \
  --bundle keychain-auth_4.0.2_linux_amd64.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/The-17/keychain-auth/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  keychain-auth_4.0.2_linux_amd64.tar.gz
```

Then check the archive against the signed checksum file:

```bash
grep '  keychain-auth_4.0.2_linux_amd64.tar.gz$' checksums.txt | sha256sum -c -
```

## Scope

Sigstore proves that a release artifact was produced by this repository's
release workflow. It is not Microsoft Authenticode and does not create Windows
SmartScreen reputation. It is the signature format this project uses.
