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

## Windows Authenticode signatures

The release workflow also signs the Windows executable inside each archive
with `osslsigncode`, an open-source Authenticode signer. The signed archives
are published separately with a `_signed` suffix. `checksums-signed.txt`
contains their digests. Install the `_signed` archive on Windows.

Signing requires two repository secrets.

- `AUTHENTICODE_P12_BASE64`: base64 of a PKCS#12 bundle containing a code-signing
  certificate from a trusted CA and its private key.
- `AUTHENTICODE_P12_PASSWORD`: password for that bundle.

When either is missing, the Authenticode job skips and the release publishes
only unsigned Windows archives. Cosign signing and the rest of the release are
unaffected.

An OV certificate reduces warnings. An EV certificate plus an established
reputation is what builds SmartScreen trust. Neither is issued by Sigstore.
