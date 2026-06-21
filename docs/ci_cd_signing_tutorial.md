# CI/CD Binary Signing & Verification Tutorial

This tutorial guides you through generating Ed25519 signing keys, configuring the `keychain-auth` daemon, and integrating code signing into your CI/CD pipeline (e.g., GitHub Actions) to achieve silent, secure binary updates.

---

## 1. How Code Signature Verification Works

Normally, `keychain-auth` validates calling binaries by matching their SHA-256 hash against `/etc/keychain-auth/config.json`. When you compile a new version of the binary, its hash changes, forcing the user to re-register it via UAC/sudo elevation prompts.

With **Code Signature Verification**:
1. At build/release time in your CI/CD, the binary is hashed and signed with your **Developer Private Key**.
2. The 64-byte signature and a 4-byte magic sequence (`KCAS`) are appended to the tail of the binary.
3. The `keychain-auth` daemon is configured with your **Developer Public Key** in its `trusted_signers` list.
4. When the binary connects, the daemon verifies its cryptographic signature.
5. If valid, the connection is approved **silently and automatically**, updating the registered hash in `config.json` without any prompt.

---

## 2. Step 1: Generate your Ed25519 Keypair

You can generate the keys using OpenSSL (version 1.1.1 or higher) or a quick Go script.

### Using OpenSSL
Run the following commands on your development machine:

```bash
# Generate the private key
openssl genpkey -algorithm ed25519 -out dev_private.pem

# Extract the public key in standard PEM format
openssl pkey -in dev_private.pem -pubout -out dev_public.pem
```

To extract the clean, raw keys needed:
- **Private Key:** Keep the file `dev_private.pem` secure. It will be added to your CI/CD repository secrets.
- **Public Key:** Run this to get the base64 string:
  ```bash
  grep -v -- "-----" dev_public.pem | tr -d '\n'
  ```
  *Example Output:* `3e9rp68cVGW1W3gyplepwuVcQ16QX5mHE/r8QnbH7rg=`

---

## 3. Step 2: Configure the Daemon

Add the developer public key to the daemon's configuration file `/etc/keychain-auth/config.json` (or `~/.config/keychain-auth/config.json` if running in user space).

Open the configuration file and add the `"trusted_signers"` array:

```json
{
  "registered_binaries": [],
  "protocol_version": "1",
  "trusted_signers": [
    {
      "service": "agentsecrets",
      "public_key": "YOUR_BASE64_PUBLIC_KEY_HERE"
    }
  ]
}
```

Replace `YOUR_BASE64_PUBLIC_KEY_HERE` with the base64 public key string generated in Step 1.

---

## 4. Step 3: Integrate Signing into GitHub Actions

Add the private key to your GitHub repository secrets as `DEV_PRIVATE_KEY` under `Settings -> Secrets and variables -> Actions`.

Add this step to your GitHub Actions workflow configuration (e.g., `.github/workflows/release.yml`) after building the binary:

```yaml
      - name: Sign Executable
        env:
          SIGNING_KEY: ${{ secrets.DEV_PRIVATE_KEY }}
        run: |
          # 1. Write the private key to a temporary file
          echo "$SIGNING_KEY" > private.pem
          
          # 2. Sign the binary using OpenSSL pkeyutl (PureEdDSA mode)
          openssl pkeyutl -sign -inkey private.pem -rawin -in agentsecrets -out signature.sig
          
          # 3. Append the 64-byte signature and the 4-byte magic "KCAS"
          cat agentsecrets signature.sig <(echo -n "KCAS") > agentsecrets.signed
          mv agentsecrets.signed agentsecrets
          
          # 4. Clean up key files
          rm private.pem signature.sig
```

---

## 5. Verification Commands (Manual Testing)

To verify the entire setup locally, follow these steps:

### A. Setup local test directory & config
Create a temporary directory for configuration:
```bash
mkdir -p /tmp/kctest
export XDG_CONFIG_HOME=/tmp/kctest
```

### B. Generate a test signing keypair
```bash
openssl genpkey -algorithm ed25519 -out /tmp/kctest/test_private.pem
openssl pkey -in /tmp/kctest/test_private.pem -pubout -out /tmp/kctest/test_public.pem

# Extract base64 public key
PUB_KEY_B64=$(grep -v -- "-----" /tmp/kctest/test_public.pem | tr -d '\n')
```

### C. Create config.json with the public key
Write the config containing the trusted signer:
```bash
cat <<EOF > /tmp/kctest/keychain-auth/config.json
{
  "registered_binaries": [],
  "protocol_version": "1",
  "trusted_signers": [
    {
      "service": "agentsecrets",
      "public_key": "${PUB_KEY_B64}"
    }
  ]
}
EOF
```

### D. Compile and sign a test client binary
We will use a simple Go file (or any executable) and sign it:
```bash
# Compile client binary
go build -o /tmp/kctest/agentsecrets ./cmd/keychain-auth

# Sign it
openssl pkeyutl -sign -inkey /tmp/kctest/test_private.pem -rawin -in /tmp/kctest/agentsecrets -out /tmp/kctest/signature.sig
cat /tmp/kctest/agentsecrets /tmp/kctest/signature.sig <(echo -n "KCAS") > /tmp/kctest/agentsecrets.signed
chmod +x /tmp/kctest/agentsecrets.signed
```

### E. Run the daemon
Start the daemon using the temporary config:
```bash
# In one terminal:
export ConfigPathOverride=/tmp/kctest/keychain-auth/config.json
/home/theapiartist/work/keychain-auth/bin/keychain-auth start
```

### F. Verify connection of the signed binary
Execute the signed binary to connect/request. Since it is signed by the trusted signer key configured for `"agentsecrets"` service, the daemon will automatically approve it and add it to `config.json` without prompts!
