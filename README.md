# mkcert.py — Simple local CA & TLS cert generator

A single Python script to:

- Create a **Root CA** (with interactive CN + passphrase)
- Issue an **Intermediate CA**
- Issue **server/client leaf** certificates
- Choose the **issuer** for leaf certs (`root` or an existing **intermediate**)
- Generate **self-signed** leaf certs (no CA)
- Output themed filenames:  
  `<name>_key.key`, `<name>_cert.crt`, `<name>_fullchain.crt`
- Build proper chains:
  - Intermediate: `intermediate + root`
  - Leaf (from intermediate): `leaf + intermediate`
  - Leaf (from root): `cert + root`
  - Self-signed: `cert` only (fullchain = same as cert)

> Uses the excellent [`cryptography`](https://cryptography.io/) library.  
> Intended for lab/dev/internal usage—**not** a public CA.

---

## Requirements

- Python 3.9+
- `cryptography` library

```bash
pip install cryptography
```

---

## Quick Start

```bash
# Create root (if missing) and issue a server cert
python mkcert.py \
  --out certs \
  --cn "<Common Name>" \
  --dns <DOMAIN> \
  --ips <IP_ADDRESS> \
  --name n8n
```

Outputs (in `certs/`):
```
n8n_key.key
n8n_cert.crt
n8n_fullchain.crt  # leaf + root
```

---

## Usage

### Create Intermediate CA

```bash
python mkcert.py --out certs --cn "Intermediate CA" --intermediate --name intermediate
```

### Issue Leaf from Intermediate

```bash
python mkcert.py --out certs \
  --cn "<Common Name>" \
  --dns <DOMAIN> \
  --ips <IP_ADDRESS> \
  --issuer intermediate \
  --inter-name intermediate \
  --name n8n
```

### Create Self-Signed Leaf

```bash
python mkcert.py --out certs --cn "local.dev" --dns local.dev --ips 127.0.0.1 --self-signed --name localdev
```

---

## Verification

```bash
openssl verify -CAfile certs/root_ca_cert.pem -untrusted certs/intermediate_cert.crt certs/n8n_cert.crt
```

---

## Trusting on Windows

```powershell
Import-Certificate -FilePath ".\certs\root_ca_cert.pem" -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath ".\certs\intermediate_cert.crt" -CertStoreLocation Cert:\LocalMachine\CA
```

---

## Using with NGINX

```nginx
ssl_certificate     /etc/ssl/fullchain.crt;
ssl_certificate_key /etc/ssl/key.key;
```

---

## License

MIT — free to use and share.
