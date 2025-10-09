# mkcert.py — Local CA & TLS Certificate Generator

A single Python script to build and manage your internal PKI hierarchy for secure HTTPS, VPN, and service communication inside your infrastructure.

---

## 🧩 Features

- Create **Root CA** and **Intermediate CA**
- Issue **Server**, **Client**, or **Self-signed** certificates
- Choose **Issuer** (`root`, `intermediate`, or custom via `--issuer-key`/`--issuer-cert`)
- Build correct certificate chains automatically
- Works with **RSA** and **ECDSA (P-256)** keys
- Output themed files: `<name>_key.key`, `<name>_cert.crt`, `<name>_fullchain.crt`
- Supports **SANs**, **ClientAuth**, and **ServerAuth**
- Perfect for **homelab**, **AD/ADFS**, **Synology NAS**, **FortiGate**, or **vCenter**

> Built with the [`cryptography`](https://cryptography.io/) library — intended for internal/lab use, not public CAs.

---

## 🧰 Requirements

- Python **3.9+**
- `cryptography` library

```bash
pip install cryptography
```

---

## 🚀 Quick Start

Issue a single HTTPS cert (auto-creates CA if missing):

```bash
python mkcert.py --out certs   --cn "example.local"   --dns example.local   --ips 127.0.0.1   --name example
```

Outputs:
```
certs/example_key.key
certs/example_cert.crt
certs/example_fullchain.crt  # leaf + root
```

---

## 🏗️ Hierarchy Overview

```
Root CA
 └── Intermediate CA
      ├── webserver.example.local
      ├── vcenter.example.local
      ├── fortigate.internal
      ├── nas.internal
      ├── ad.domain.local
      ├── adfs.domain.local
      └── dc1.domain.local
```

---

## 🔧 Common Usage

### Create Intermediate CA

```bash
python mkcert.py --out certs --intermediate --cn "Internal Intermediate CA" --name intermediate
```

### Issue Leaf Certificate (Signed by Intermediate)

```bash
python mkcert.py --out certs   --cn "webserver.internal"   --dns webserver.internal   --ips 192.168.1.10   --issuer intermediate   --inter-name intermediate   --name webserver
```

### Self-signed (No CA)

```bash
python mkcert.py --out certs   --cn "standalone.local"   --dns standalone.local   --ips 127.0.0.1   --self-signed   --name standalone
```

---

## 🖥️ vCenter Integration

**Goal:** Replace the default machine SSL certificate in VMware vCenter (VAMI).

1. Generate the certificate:

```bash
python mkcert.py --out certs   --cn "vcenter.internal"   --dns vcenter.internal vcenter   --ips 192.168.10.5   --issuer intermediate   --inter-name intermediate   --name vcenter
```

2. Combine chain:
```bash
cat certs/intermediate_cert.crt certs/root_ca_cert.pem > certs/root_chain.crt
```

3. Upload to VAMI (https://vcenter.internal:5480):
   - Certificate: `vcenter_cert.crt`
   - Private Key: `vcenter_key.key`
   - Chain: `root_chain.crt`

4. Reboot appliance and verify via:
```bash
openssl s_client -connect vcenter.internal:443 -showcerts
```

---

## 🔒 FortiGate Integration

**Goal:** Replace FortiGate GUI/SSL-VPN cert with your internal CA-signed one.

1. Generate the certificate:

```bash
python mkcert.py --out certs   --cn "fortigate.internal"   --dns fortigate.internal fw01   --ips 192.168.1.1   --issuer intermediate   --inter-name intermediate   --name fortigate
```

2. Create chain:
```bash
cat certs/intermediate_cert.crt certs/root_ca_cert.pem > certs/root_chain.crt
```

3. Convert to PKCS#12 if needed:
```bash
openssl pkcs12 -export   -inkey certs/fortigate_key.key   -in certs/fortigate_cert.crt   -certfile certs/root_chain.crt   -out certs/fortigate.p12   -name "fortigate.internal"
```

4. Import in FortiGate:
   - **GUI:** System → Certificates → Import → Local Certificate  
     Upload `fortigate_cert.crt`, `fortigate_key.key`, and `root_chain.crt`
   - **CLI (optional):**
     ```bash
     execute vpn certificate local import p12 FortiGate-SSL fortigate.p12 <password>
     config system global
         set admin-server-cert "FortiGate-SSL"
     end
     config vpn ssl settings
         set servercert "FortiGate-SSL"
     end
     ```

5. Reboot or restart HTTPS admin service.

---

## 🗄️ Synology NAS Integration

**Goal:** Use your internal CA for DSM’s HTTPS and services.

1. Generate NAS certificate:

```bash
python mkcert.py --out certs   --cn "nas.internal"   --dns nas.internal nas.local   --ips 10.0.1.6   --issuer intermediate   --inter-name intermediate   --name synology
```

2. Build chain:
```bash
cat certs/intermediate_cert.crt certs/root_ca_cert.pem > certs/root_chain.crt
```

3. In DSM:
   - **Control Panel → Security → Certificate → Add → Import**
   - Upload:
     - Certificate → `synology_cert.crt`
     - Private key → `synology_key.key`
     - Intermediate cert → `root_chain.crt`
   - Set as **Default Certificate**

4. Verify via browser or:
```bash
openssl s_client -connect nas.internal:5001 -showcerts
```

---

## 🧠 Active Directory (AD) Integration

**Goal:** Automatically distribute trust for your internal CA across the domain.

1. Copy your CA certs to a Domain Controller:
   ```powershell
   C:\CA\root_ca_cert.pem
   C:\CA\intermediate_cert.crt
   ```

2. Publish Root CA:
   ```powershell
   certutil -dspublish -f C:\CA\root_ca_cert.pem RootCA
   ```

3. Publish Intermediate CA:
   ```powershell
   certutil -dspublish -f C:\CA\intermediate_cert.crt SubCA
   ```

4. Verify:
   ```powershell
   certutil -viewstore -enterprise Root
   certutil -viewstore -enterprise CA
   ```

5. Update Group Policy on clients:
   ```powershell
   gpupdate /force
   ```

All domain-joined systems now trust your internal CA automatically.

---

## 🪪 Active Directory Federation Services (AD FS)

**Goal:** Replace AD FS HTTPS (Service Communications) certificate with one signed by your CA.

1. Generate ADFS cert:
   ```bash
   python mkcert.py --out certs      --cn "adfs.domain.local"      --dns adfs.domain.local adfs      --ips 10.0.1.20      --issuer intermediate      --inter-name intermediate      --name adfs
   ```

2. Export as PFX:
   ```bash
   openssl pkcs12 -export      -inkey certs/adfs_key.key      -in certs/adfs_cert.crt      -certfile certs/intermediate_cert.crt      -out certs/adfs.pfx      -name "adfs.domain.local"
   ```

3. Import to Windows Store:
   ```powershell
   Import-PfxCertificate -FilePath C:\certs\adfs.pfx -CertStoreLocation Cert:\LocalMachine\My
   ```

4. Assign to AD FS:
   ```powershell
   Set-AdfsSslCertificate -Thumbprint "<thumbprint>"
   Restart-Service adfssrv
   ```

5. Test:
   Visit `https://adfs.domain.local/adfs/ls/idpinitiatedsignon.aspx`  
   → should show a valid trusted certificate chain.

---

## 🧾 Verification Commands

```bash
openssl verify -CAfile certs/root_ca_cert.pem -untrusted certs/intermediate_cert.crt certs/example_cert.crt
openssl s_client -connect example.local:443 -showcerts
```

---

## 🧠 Active Directory LDAPS Integration

**Goal:** Secure LDAP (LDAPS on port 636) using your internal CA.

1. Generate Domain Controller certificate:
   ```bash
   python mkcert.py --out certs      --cn "dc1.domain.local"      --dns dc1.domain.local dc1      --issuer intermediate      --inter-name intermediate      --name dc1-ldaps
   ```

2. Export as PFX:
   ```bash
   openssl pkcs12 -export      -inkey certs/dc1-ldaps_key.key      -in certs/dc1-ldaps_cert.crt      -certfile certs/intermediate_cert.crt      -out certs/dc1-ldaps.pfx      -name "dc1.domain.local"
   ```

3. Import on the Domain Controller:
   ```powershell
   Import-PfxCertificate -FilePath C:\certs\dc1-ldaps.pfx -CertStoreLocation Cert:\LocalMachine\My
   ```

4. Restart AD DS:
   ```powershell
   Restart-Service NTDS
   ```

5. Test LDAPS:
   ```bash
   openssl s_client -connect dc1.domain.local:636 -showcerts
   ```

Expected output:
```
subject=CN = dc1.domain.local
issuer=CN = Internal CA
```

✅ Once your CA is trusted (automatically via AD GPO), LDAPS connections are secure.

---

## 🖥️ Trust Distribution (Manual)

| OS | How to trust Root CA |
|----|----------------------|
| **Windows** | Import Root CA into “Trusted Root Certification Authorities” via `certmgr.msc` |
| **Linux** | `sudo cp root_ca_cert.pem /usr/local/share/ca-certificates/root.crt && sudo update-ca-certificates` |
| **macOS** | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root_ca_cert.pem` |
| **Firefox** | Preferences → Privacy & Security → Certificates → View → Authorities → Import |

---

## 🧾 License

**MIT License** — free for personal and commercial use.  
Created for sysadmins, DevOps, and homelab builders who want full control of their PKI.
