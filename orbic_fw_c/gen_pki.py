"""Generate a 2-Tier PKI (Root CA -> Leaf) for iOS Compatibility"""
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import ipaddress

def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def save_der(data, filename):
    with open(filename, 'wb') as f:
        f.write(data)
    print(f"Saved: {filename}")

def save_key_der(key, filename):
    with open(filename, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL, # PKCS#1
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Saved: {filename}")

# --- 1. Root CA ---
print("Generating Root CA...")
root_key = generate_key()
root_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'DagShell Root CA'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'DagShell'),
])

root_cert = (
    x509.CertificateBuilder()
    .subject_name(root_subject)
    .issuer_name(root_subject) # Self-signed
    .public_key(root_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    .add_extension(
        x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                      content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False,
                      encipher_only=False, decipher_only=False),
        critical=True,
    )
    .sign(root_key, hashes.SHA256(), default_backend())
)

save_der(root_cert.public_bytes(serialization.Encoding.DER), "root.der")
# We don't save root private key to device, not needed.

# --- 2. Leaf Certificate ---
print("Generating Leaf Certificate...")
server_key = generate_key()
server_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'192.168.1.1'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'DagShell'),
])

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_subject)
    .issuer_name(root_subject) # Signed by Root
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    .add_extension(
        x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.ip_address('192.168.1.1')),
            x509.DNSName('localhost'),
        ]),
        critical=False,
    )
    .add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    )
    .sign(root_key, hashes.SHA256(), default_backend()) # Sign with ROOT KEY
)

save_der(server_cert.public_bytes(serialization.Encoding.DER), "server.der")
save_key_der(server_key, "server.key.der")

print("\nPKI Generation Complete.")
print("Root CA: root.der")
print("Leaf Cert: server.der")
print("Leaf Key: server.key.der")
