# mkcert.py — Simple Local CA & TLS Certificate Generator

A single self-contained Python script to build and manage your own local certificate authority (CA) and issue TLS certificates for servers, clients, or internal services.

---

## 🧩 Features

- Create a **Root CA** (self-signed) with optional passphrase
- Issue **Intermediate CAs**
- Issue **Server / Client certificates**
- Choose the **issuer** for leaf certs (`root`, an existing `intermediate`, or explicit `--issuer-key`/`--issuer-cert`)
- Generate **self-signed** leaf certificates (no CA needed)
- Build proper certificate chains automatically
- Use modern cryptography (RSA 2048–4096 or EC P-256)
- All in one Python file — no external tools required

### Output naming convention

Each certificate set uses a common *theme* (or “basename”), producing:
```
<name>_key.key       # Private key
<name>_cert.crt      # Certificate
<name>_fullchain.crt # Certificate + Issuer chain
```

### Example chains

| Type | Fullchain Contents |
|------|--------------------|
| Intermediate | Intermediate + Root |
| Leaf (from Intermediate) | Leaf + Intermediate |
| Leaf (from Root) | Leaf + Root |
| Self-Signed | Leaf only |

> ⚠️ This tool is for **local development, labs, or internal PKI** only — not for public web certificate issuance.

---

## 🧰 Requirements

- Python **3.9+**
- [`cryptography`](https://cryptography.io/) library

```bash
pip install cryptography
```

---

## 🚀 Quick Start

Create a **Root CA** (if missing) and issue a **server certificate**:

```bash
python mkcert.py   --out certs   --cn "example.local"   --dns example.local   --ips 127.0.0.1   --name example
```

Outputs (in `certs/`):
```
example_key.key
example_cert.crt
example_fullchain.crt  # leaf + root
```

You can now use `example_fullchain.crt` and `example_key.key` in your web server.

---

## 🏗️ Hierarchy Overview

A typical local PKI hierarchy you can build with `mkcert.py`:

```
Root CA
 └── Intermediate CA
      ├── webserver.example.local
      ├── api.internal.lan
      └── client01.internal.lan
```

---

## 🔧 Usage Examples

### 1. Create a Root CA

```bash
python mkcert.py --out certs --intermediate --force-new-root --cn "Local Root CA"
```
This generates:
```
certs/root_ca_key.pem
certs/root_ca_cert.pem
```

### 2. Create an Intermediate CA (signed by Root)

```bash
python mkcert.py --out certs   --intermediate   --cn "Local Intermediate CA"   --name intermediate
```

Outputs:
```
intermediate_key.key
intermediate_cert.crt
intermediate_fullchain.crt  # intermediate + root
```

### 3. Issue a Server Certificate (signed by Intermediate)

```bash
python mkcert.py --out certs   --cn "example.local"   --dns example.local   --ips 127.0.0.1   --issuer intermediate   --inter-name intermediate   --name example
```

Outputs:
```
example_key.key
example_cert.crt
example_fullchain.crt  # leaf + intermediate
```

### 4. Issue a Certificate Directly from Root

```bash
python mkcert.py --out certs   --cn "direct.local"   --dns direct.local   --issuer root   --name direct
```

### 5. Issue a Certificate with Explicit Issuer (Custom Chain)

You can bypass all CA lookup logic and provide any issuer directly:

```bash
python mkcert.py --out certs   --cn "custom.local"   --dns custom.local   --issuer-key certs/intermediate_key.key   --issuer-cert certs/intermediate_cert.crt   --name custom
```

### 6. Generate a Self-Signed Certificate

```bash
python mkcert.py --out certs   --cn "standalone.local"   --dns standalone.local   --ips 127.0.0.1   --self-signed   --name standalone
```

Outputs:
```
standalone_key.key
standalone_cert.crt
standalone_fullchain.crt  # identical to cert
```

---

## 🔍 Verification

Verify a certificate chain using `openssl`:

```bash
# Leaf signed by intermediate
openssl verify -CAfile certs/root_ca_cert.pem -untrusted certs/intermediate_cert.crt certs/example_cert.crt
```

---

## 🖥️ Trust Installation

### On Linux (system-wide)
```bash
sudo cp certs/root_ca_cert.pem /usr/local/share/ca-certificates/root_ca.crt
sudo update-ca-certificates
```

### On macOS
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/root_ca_cert.pem
```

### On Windows PowerShell
```powershell
Import-Certificate -FilePath ".\certs\root_ca_cert.pem" -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath ".\certs\intermediate_cert.crt" -CertStoreLocation Cert:\LocalMachine\CA
```

---

## 🌐 Using with NGINX

Example server block:

```nginx
server {
    listen 443 ssl http2;
    server_name example.local;

    ssl_certificate     /etc/ssl/example_fullchain.crt;
    ssl_certificate_key /etc/ssl/example_key.key;

    root /var/www/html;
}
```

---

## 🧠 Tips & Advanced Options

- `--key-alg ec` uses Elliptic Curve (P-256) instead of RSA
- `--key-bits 4096` increases RSA strength (default 2048)
- `--key-pass mypass` encrypts private key with a password
- `--clientauth` adds the *Client Authentication* EKU for mTLS
- `--no-serverauth` removes the *Server Authentication* EKU
- `--days <n>` changes certificate validity period (default 825 days)
- `--force-new-root` recreates the root CA even if one already exists

---

## 🧾 License

**MIT License** — free for personal and commercial use.  
Authored for developers, sysadmins, and homelab enthusiasts.

