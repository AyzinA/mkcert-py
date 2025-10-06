#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from getpass import getpass

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption


# ---------- Helpers ----------

def parse_sans(dns_list, ip_list):
    sans = []
    for d in dns_list or []:
        d = d.strip()
        if d:
            sans.append(x509.DNSName(d))
    for i in ip_list or []:
        i = i.strip()
        if i:
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(i)))
            except ValueError:
                raise SystemExit(f"Invalid IP in --ips: {i}")
    return sans

def maybe_encrypt(passphrase: str | None):
    if passphrase:
        return BestAvailableEncryption(passphrase.encode("utf-8"))
    return NoEncryption()

def write_pem(path: Path, data: bytes, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    try:
        os.chmod(path, mode)
    except Exception:
        pass  # Windows/others may ignore chmod

def new_private_key(alg: str, bits: int):
    if alg == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)
    if alg == "ec":
        return ec.generate_private_key(ec.SECP256R1())  # P-256
    raise SystemExit("--key-alg must be rsa or ec")

def subject_from_args(cn, o=None, ou=None, c=None, st=None, l=None):
    name_attributes = []
    if c:  name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
    if st: name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st))
    if l:  name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, l))
    if o:  name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
    if ou: name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(name_attributes)

def sane_serial():
    return x509.random_serial_number()


# ---------- Builders ----------

def build_self_signed_ca(ca_key, subject: x509.Name, days: int, pathlen: int | None):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(sane_serial())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=isinstance(ca_key, rsa.RSAPrivateKey),
                content_commitment=False,
                key_cert_sign=True,
                crl_sign=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
    )
    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

def build_signed_cert(
    issuer_key, issuer_cert, subject_key, subject_name, days, is_ca, sans, serverauth=True, clientauth=False
):
    now = datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(sane_serial())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )

    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=isinstance(subject_key, rsa.RSAPrivateKey),
                content_commitment=False,
                key_cert_sign=True,
                crl_sign=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=isinstance(subject_key, rsa.RSAPrivateKey),
                content_commitment=False,
                key_cert_sign=False,
                crl_sign=False,
                data_encipherment=True,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        eku = []
        if serverauth:
            eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if clientauth:
            eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        if eku:
            builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)

        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())

def build_self_signed_leaf(subject_key, subject_name, days, sans, serverauth=True, clientauth=False):
    """Self-signed end-entity (not a CA)."""
    now = datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(subject_key.public_key())
        .serial_number(sane_serial())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(subject_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=isinstance(subject_key, rsa.RSAPrivateKey),
                content_commitment=False,
                key_cert_sign=False,
                crl_sign=False,
                data_encipherment=True,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    eku = []
    if serverauth:
        eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if clientauth:
        eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

    return builder.sign(private_key=subject_key, algorithm=hashes.SHA256())


# ---------- Main ----------

def main():
    p = argparse.ArgumentParser(
        description="Create a Root CA (if needed) and issue a server or intermediate certificate."
    )
    p.add_argument("--out", default="certs", help="Output directory (default: certs)")

    # Root options
    p.add_argument("--root-cn", default="Local Dev Root CA", help="Root CA Common Name")
    p.add_argument("--root-o", help="Root CA Organization")
    p.add_argument("--root-days", type=int, default=3650, help="Root validity days (default: 3650)")
    p.add_argument("--root-key-alg", choices=["rsa", "ec"], default="rsa", help="Root key algorithm (rsa|ec)")
    p.add_argument("--root-key-bits", type=int, default=4096, help="Root RSA bits (ignored for EC)")
    p.add_argument("--root-pass", help="Root key passphrase (prompted if needed)")
    p.add_argument("--force-new-root", action="store_true", help="Overwrite existing root with a new one")

    # Issued subject
    p.add_argument("--cn", required=True, help="End-entity or Intermediate CA Common Name")
    p.add_argument("--o", help="Organization")
    p.add_argument("--ou", help="Organizational Unit")
    p.add_argument("--c", help="Country (2 letters)")
    p.add_argument("--st", help="State/Province")
    p.add_argument("--l", help="Locality/City")

    # SANs / validity / keys for issued
    p.add_argument("--dns", nargs="*", help="DNS SAN entries (space-separated)")
    p.add_argument("--ips", nargs="*", help="IP SAN entries (space-separated)")
    p.add_argument("--days", type=int, default=825, help="Issued cert validity days (default: 825)")
    p.add_argument("--key-alg", choices=["rsa", "ec"], default="rsa", help="Issued key algorithm (rsa|ec)")
    p.add_argument("--key-bits", type=int, default=2048, help="Issued RSA bits (ignored for EC)")
    p.add_argument("--key-pass", help="Encrypt issued key with this passphrase")

    # Modes
    p.add_argument("--intermediate", action="store_true", help="Issue an Intermediate CA instead of a server cert")
    p.add_argument("--self-signed", action="store_true", help="Create a self-signed leaf certificate (no Root CA)")

    # EKUs toggles for leaf
    p.add_argument("--clientauth", action="store_true", help="Add ClientAuth EKU to server cert")
    p.add_argument("--no-serverauth", action="store_true", help="Remove ServerAuth EKU from server cert")

    # Issuer selection for leafs
    p.add_argument("--issuer", choices=["root", "intermediate"], default="root",
                   help="Who signs non-CA certs (default: root)")
    p.add_argument("--inter-name", default="intermediate",
                   help="Intermediate theme/prefix to load (default: intermediate)")
    p.add_argument("--inter-pass", help="Intermediate key passphrase (if encrypted)")

    # Optional non-interactive theme
    p.add_argument("--name", help="Theme/basename for output files (skip prompt)")

    args = p.parse_args()
    outdir = Path(args.out)

    # ---- Self-signed LEAF (no Root CA at all) ----
    if args.self_signed:
        print("[+] Creating a self-signed certificate (no Root CA) ...")
        theme = args.name or input("Enter a name/theme for the self-signed certificate files (default: selfsigned): ").strip() or "selfsigned"

        issued_key_path = outdir / f"{theme}_key.key"
        issued_crt_path = outdir / f"{theme}_cert.crt"
        issued_chain_path = outdir / f"{theme}_fullchain.crt"

        issued_key = new_private_key(args.key_alg, args.key_bits)
        subject = subject_from_args(cn=args.cn, o=args.o, ou=args.ou, c=args.c, st=args.st, l=args.l)
        sans = parse_sans(args.dns, args.ips)
        cert = build_self_signed_leaf(
            subject_key=issued_key,
            subject_name=subject,
            days=args.days,
            sans=sans,
            serverauth=not args.no_serverauth,
            clientauth=args.clientauth,
        )

        write_pem(
            issued_key_path,
            issued_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=maybe_encrypt(args.key_pass),
            ),
        )
        write_pem(issued_crt_path, cert.public_bytes(serialization.Encoding.PEM))
        write_pem(issued_chain_path, cert.public_bytes(serialization.Encoding.PEM))  # same as cert
        print(f"[+] Wrote {issued_key_path}")
        print(f"[+] Wrote {issued_crt_path}")
        print(f"[+] Wrote {issued_chain_path} (self-signed)")
        return

    # ---- Root CA: load or create ----
    root_key_path = outdir / "root_ca_key.pem"
    root_crt_path = outdir / "root_ca_cert.pem"

    if root_key_path.exists() and root_crt_path.exists() and not args.force_new_root:
        print(f"[+] Using existing Root CA: {root_crt_path}")
        root_pass = args.root_pass
        if root_pass is None:
            rp = getpass("Enter Root CA key passphrase (empty if unencrypted): ")
            root_pass = rp if rp else None
        with open(root_key_path, "rb") as f:
            root_key = serialization.load_pem_private_key(
                f.read(),
                password=root_pass.encode("utf-8") if root_pass else None
            )
        with open(root_crt_path, "rb") as f:
            root_crt = x509.load_pem_x509_certificate(f.read())
    else:
        print("[+] Creating new Root CA ...")
        default_root_cn = args.root_cn or "Local Dev Root CA"
        entered_cn = input(f"Root CA Common Name [{default_root_cn}]: ").strip()
        root_cn = entered_cn or default_root_cn

        root_pass = args.root_pass
        if root_pass is None:
            print("(Leave passphrase empty for an unencrypted key)")
            while True:
                p1 = getpass("Root CA key passphrase: ")
                if not p1:
                    root_pass = None
                    break
                p2 = getpass("Confirm passphrase: ")
                if p1 == p2:
                    root_pass = p1
                    break
                print("Passphrases do not match, try again.")

        root_key = new_private_key(args.root_key_alg, args.root_key_bits)
        root_subject = subject_from_args(cn=root_cn, o=args.root_o)
        root_crt = build_self_signed_ca(root_key, root_subject, args.root_days, pathlen=1)

        write_pem(
            root_key_path,
            root_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=maybe_encrypt(root_pass),
            ),
        )
        write_pem(root_crt_path, root_crt.public_bytes(serialization.Encoding.PEM))
        print(f"[+] Wrote {root_key_path}")
        print(f"[+] Wrote {root_crt_path}")

    # ---- Issue Intermediate or Leaf ----
    is_ca = args.intermediate
    default_theme = "intermediate" if is_ca else "server"
    theme = args.name or input(f"Enter a name/theme for the certificate files (default: {default_theme}): ").strip() or default_theme

    issued_key_path   = outdir / f"{theme}_key.key"
    issued_crt_path   = outdir / f"{theme}_cert.crt"
    issued_chain_path = outdir / f"{theme}_fullchain.crt"

    print(f"[+] Creating {'Intermediate CA' if is_ca else 'server certificate'} ...")
    issued_key = new_private_key(args.key_alg, args.key_bits)
    subject = subject_from_args(cn=args.cn, o=args.o, ou=args.ou, c=args.c, st=args.st, l=args.l)
    sans = parse_sans(args.dns, args.ips) if not is_ca else []

    # Determine issuer
    issuer_key = root_key
    issuer_crt = root_crt

    # If leaf and user requested intermediate issuer, load it
    if not is_ca and args.issuer == "intermediate":
        inter_prefix = args.inter_name
        inter_key_path = outdir / f"{inter_prefix}_key.key"
        inter_crt_path = outdir / f"{inter_prefix}_cert.crt"
        if not inter_key_path.exists() or not inter_crt_path.exists():
            raise SystemExit(
                f"Intermediate not found: {inter_key_path} / {inter_crt_path}\n"
                f"Create it first with: --intermediate and --name {inter_prefix}"
            )
        with open(inter_key_path, "rb") as f:
            issuer_key = serialization.load_pem_private_key(
                f.read(),
                password=args.inter_pass.encode("utf-8") if args.inter_pass else None
            )
        with open(inter_crt_path, "rb") as f:
            issuer_crt = x509.load_pem_x509_certificate(f.read())

    cert = build_signed_cert(
        issuer_key=issuer_key,
        issuer_cert=issuer_crt,
        subject_key=issued_key,
        subject_name=subject,
        days=args.days,
        is_ca=is_ca,
        sans=sans,
        serverauth=not args.no_serverauth,
        clientauth=args.clientauth,
    )

    # Write outputs
    write_pem(
        issued_key_path,
        issued_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=maybe_encrypt(args.key_pass),
        ),
    )
    write_pem(issued_crt_path, cert.public_bytes(serialization.Encoding.PEM))

    if is_ca:
        # intermediate full chain = intermediate + root
        chain_bytes = cert.public_bytes(serialization.Encoding.PEM) + root_crt.public_bytes(serialization.Encoding.PEM)
        chain_note = "cert + root"
    else:
        # leaf full chain
        chain_bytes = cert.public_bytes(serialization.Encoding.PEM) + issuer_crt.public_bytes(serialization.Encoding.PEM)
        chain_note = "leaf + intermediate" if args.issuer == "intermediate" else "leaf + root"

    write_pem(issued_chain_path, chain_bytes)

    print(f"[+] Wrote {issued_key_path}")
    print(f"[+] Wrote {issued_crt_path}")
    print(f"[+] Wrote {issued_chain_path} ({chain_note})")

    if not is_ca and not sans:
        print("[!] Note: You created a server cert without SANs. Most clients require SAN; pass --dns/--ips.", file=sys.stderr)


if __name__ == "__main__":
    main()
