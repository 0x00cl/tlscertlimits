import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# CA Certificate

ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=16384,
)

with Path.open("certs/myCA.key", "wb") as f:
    f.write(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )

ca_subject = ca_issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "WW"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "W" * 128),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "W" * 128),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "W" * 64),
        x509.NameAttribute(NameOID.COMMON_NAME, "0x00.cl CA root"),
    ]
)

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_subject)
    .issuer_name(ca_issuer)
    .public_key(ca_key.public_key())
    .serial_number(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0)
    .not_valid_before(datetime.datetime.fromisoformat("1950-01-01 00:00:00.000+00:00"))
    .not_valid_after(datetime.datetime.fromisoformat("9999-12-31 23:59:59.000+00:00"))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
        critical=False,
    )
    .sign(ca_key, hashes.SHA3_512())
)

with Path.open("certs/myCA.pem", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))


# Intermediate certificate

int_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=16384,
)

with Path.open("certs/myCAinter.key", "wb") as f:
    f.write(
        int_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


inter_subject = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "WW"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "W" * 128),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "W" * 128),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "W" * 64),
        x509.NameAttribute(NameOID.COMMON_NAME, "0x00.cl CA Intermediate"),
    ]
)


inter_cert = (
    x509.CertificateBuilder()
    .subject_name(inter_subject)
    .issuer_name(ca_cert.subject)
    .public_key(int_key.public_key())
    .serial_number(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1)
    .not_valid_before(datetime.datetime.fromisoformat("1950-01-01 00:00:00.000+00:00"))
    .not_valid_after(datetime.datetime.fromisoformat("9999-12-31 23:59:59.000+00:00"))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        ),
        critical=False,
    )
    .sign(ca_key, hashes.SHA3_512())
)

with Path.open("certs/myCAinter.pem", "wb") as f:
    f.write(inter_cert.public_bytes(serialization.Encoding.PEM))


# Web certificate

web_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=16384,
)

with Path.open("certs/myCAweb.key", "wb") as f:
    f.write(
        web_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


web_subject = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "WW"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "W" * 128),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "W" * 128),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "W" * 64),
        x509.NameAttribute(NameOID.COMMON_NAME, "0x00.cl Web"),
    ]
    * 221  # curl - 221 (102404 bytes)  firefox - 111 (~59061 bytes)
)


web_cert = (
    x509.CertificateBuilder()
    .subject_name(web_subject)
    .issuer_name(inter_cert.subject)
    .public_key(web_key.public_key())
    .serial_number(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF2)
    .not_valid_before(datetime.datetime.fromisoformat("1950-01-01 00:00:00.000+00:00"))
    .not_valid_after(datetime.datetime.fromisoformat("9999-12-31 23:59:59.000+00:00"))
    .add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName("localhost")] * 33
        ),  # curl - 33  firefox - tested 1000
        critical=False,
    )
    .sign(int_key, hashes.SHA3_512())
)

with Path.open("certs/myCAweb.pem", "wb") as f:
    f.write(web_cert.public_bytes(serialization.Encoding.PEM))

with Path.open("certs/myCABundle.pem", "wb") as f:
    f.write(
        web_cert.public_bytes(serialization.Encoding.PEM)
        + inter_cert.public_bytes(serialization.Encoding.PEM)
        + ca_cert.public_bytes(serialization.Encoding.PEM)
    )
