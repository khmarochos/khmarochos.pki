# khmarochos.pki API Reference

This document provides a comprehensive API reference for the module utilities in the khmarochos.pki collection. These utilities can be used to build custom modules or extend the collection's functionality.

## Table of Contents

1. [Core Classes](#core-classes)
2. [Builder Classes](#builder-classes)
3. [PKI Object Classes](#pki-object-classes)
4. [Utility Classes](#utility-classes)
5. [Enums and Constants](#enums-and-constants)
6. [Error Handling](#error-handling)

## Core Classes

### PKICA

The main class for managing Certificate Authority operations.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.pki import PKICA

class PKICA:
    """Public Key Infrastructure Certificate Authority management class."""
    
    def __init__(self, nickname, parameters=None, parent=None):
        """
        Initialize a PKI Certificate Authority.
        
        Args:
            nickname (str): Unique identifier for the CA
            parameters (dict): CA configuration parameters
            parent (PKICA): Parent CA instance for hierarchical structures
        """
```

#### Key Methods

##### initialize()
```python
def initialize(self, nickname=None, load_if_exists=True, save_if_needed=True, save_forced=False):
    """
    Initialize the CA with all necessary components.
    
    Args:
        nickname (str): Override CA nickname
        load_if_exists (bool): Load existing PKI components
        save_if_needed (bool): Save new components to disk
        save_forced (bool): Force regeneration of all components
        
    Returns:
        ChangeTracker: Object tracking all changes made
    """
```

##### issue_certificate()
```python
def issue_certificate(self, parameters, load_if_exists=True, save_if_needed=True, save_forced=False):
    """
    Issue a certificate from this CA.
    
    Args:
        parameters (dict): Certificate parameters including:
            - nickname (str): Certificate identifier
            - certificate_type (str): SERVER, CLIENT, SERVER_CLIENT, or NONE
            - certificate_subject_common_name (str): Certificate CN
            - certificate_subject_alternative_names (list): SANs
            - certificate_term (int): Validity in days
            - private_key_encrypted (bool): Encrypt private key
            - private_key_size (int): Key size in bits
            
    Returns:
        dict: Certificate details including paths and metadata
    """
```

##### get_certificate_chain()
```python
def get_certificate_chain(self):
    """
    Get the complete certificate chain from this CA to root.
    
    Returns:
        list: Certificate objects from this CA to root
    """
```

#### Example Usage

```python
# Create a CA instance
ca = PKICA(
    nickname="intermediate",
    parameters={
        "name": "Intermediate CA",
        "private_key_encrypted": True,
        "certificate_term": 3650
    },
    parent=root_ca
)

# Initialize the CA
changes = ca.initialize()

# Issue a certificate
cert_info = ca.issue_certificate({
    "nickname": "web-server",
    "certificate_type": "SERVER",
    "certificate_subject_common_name": "www.example.com",
    "certificate_term": 365
})
```

### PKICascade

Manages hierarchical CA structures and certificate chains.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade import PKICascade

class PKICascade:
    """Manages PKI CA cascade structures."""
    
    def __init__(self, parameters=None):
        """
        Initialize PKI cascade.
        
        Args:
            parameters (dict): Global cascade parameters
        """
```

#### Key Methods

##### process_parameters()
```python
def process_parameters(self, parameters=None):
    """
    Process and validate cascade parameters.
    
    Args:
        parameters (dict): Cascade configuration with __propagated section
        
    Returns:
        dict: Processed parameters with inheritance applied
    """
```

##### add_ca()
```python
def add_ca(self, nickname, parameters=None, parent_nickname=None):
    """
    Add a CA to the cascade.
    
    Args:
        nickname (str): CA identifier (e.g., "root/intermediate")
        parameters (dict): CA-specific parameters
        parent_nickname (str): Parent CA nickname
        
    Returns:
        PKICA: The created CA instance
    """
```

##### get_all_cas()
```python
def get_all_cas(self):
    """
    Get all CAs in the cascade.
    
    Returns:
        dict: Mapping of nicknames to CA instances
    """
```

## Builder Classes

### CertificateBuilder

Builds X.509 certificates with proper validation.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_builder import CertificateBuilder

class CertificateBuilder:
    """Builder for creating X.509 certificates."""
    
    def __init__(self):
        """Initialize certificate builder."""
```

#### Key Methods

##### set_subject()
```python
def set_subject(self, subject_dict):
    """
    Set certificate subject.
    
    Args:
        subject_dict (dict): Subject fields including:
            - common_name (str): Required CN
            - country_name (str): 2-letter country code
            - state_or_province_name (str): State/province
            - locality_name (str): City/locality
            - organization_name (str): Organization
            - organizational_unit_name (str): Department/OU
            - email_address (str): Email address
            
    Returns:
        self: For method chaining
    """
```

##### set_extensions()
```python
def set_extensions(self, certificate_type, sans=None, ca=False):
    """
    Set certificate extensions based on type.
    
    Args:
        certificate_type (CertificateType): Certificate usage type
        sans (list): Subject Alternative Names
        ca (bool): Whether this is a CA certificate
        
    Returns:
        self: For method chaining
    """
```

##### build()
```python
def build(self, private_key, issuer_cert=None, issuer_key=None, validity_days=365):
    """
    Build the certificate.
    
    Args:
        private_key: Certificate's private key
        issuer_cert: Issuer's certificate (None for self-signed)
        issuer_key: Issuer's private key
        validity_days (int): Certificate validity period
        
    Returns:
        Certificate: The built certificate instance
    """
```

### PrivateKeyBuilder

Builds private keys with encryption support.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key_builder import PrivateKeyBuilder

class PrivateKeyBuilder:
    """Builder for creating private keys."""
    
    def __init__(self):
        """Initialize private key builder."""
```

#### Key Methods

##### set_algorithm()
```python
def set_algorithm(self, algorithm, key_size=None):
    """
    Set key algorithm and size.
    
    Args:
        algorithm (str): "RSA" or "ECDSA"
        key_size (int): Key size in bits (RSA) or curve name (ECDSA)
        
    Returns:
        self: For method chaining
    """
```

##### set_encryption()
```python
def set_encryption(self, encrypted=True, passphrase=None):
    """
    Set key encryption parameters.
    
    Args:
        encrypted (bool): Whether to encrypt the key
        passphrase (str): Encryption passphrase
        
    Returns:
        self: For method chaining
    """
```

##### build()
```python
def build(self):
    """
    Build the private key.
    
    Returns:
        PrivateKey: The built private key instance
    """
```

### PassphraseBuilder

Generates secure passphrases.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase_builder import PassphraseBuilder

class PassphraseBuilder:
    """Builder for generating secure passphrases."""
    
    def __init__(self):
        """Initialize passphrase builder."""
```

#### Key Methods

##### set_random()
```python
def set_random(self, length=32, charset=None):
    """
    Configure random passphrase generation.
    
    Args:
        length (int): Passphrase length
        charset (str): Character set to use
        
    Returns:
        self: For method chaining
    """
```

##### build()
```python
def build(self):
    """
    Build the passphrase.
    
    Returns:
        Passphrase: The generated passphrase instance
    """
```

## PKI Object Classes

### Certificate

Represents an X.509 certificate.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate import Certificate

class Certificate:
    """Represents an X.509 certificate."""
    
    def __init__(self, certificate_object=None, file=None, path=None):
        """
        Initialize certificate.
        
        Args:
            certificate_object: cryptography certificate object
            file (str): Certificate filename
            path (str): Full path to certificate file
        """
```

#### Key Properties

```python
@property
def subject(self):
    """Get certificate subject as dict."""

@property
def issuer(self):
    """Get certificate issuer as dict."""

@property
def serial_number(self):
    """Get certificate serial number."""

@property
def not_before(self):
    """Get certificate start date."""

@property
def not_after(self):
    """Get certificate expiration date."""

@property
def subject_alternative_names(self):
    """Get SANs as list."""

@property
def is_ca(self):
    """Check if this is a CA certificate."""
```

#### Key Methods

##### verify()
```python
def verify(self, issuer_certificate):
    """
    Verify certificate signature.
    
    Args:
        issuer_certificate (Certificate): Issuer's certificate
        
    Returns:
        bool: True if signature is valid
    """
```

##### export_pem()
```python
def export_pem(self):
    """
    Export certificate in PEM format.
    
    Returns:
        str: PEM-encoded certificate
    """
```

### PrivateKey

Represents a private key.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey

class PrivateKey:
    """Represents a private key."""
    
    def __init__(self, key_object=None, file=None, path=None, encrypted=False):
        """
        Initialize private key.
        
        Args:
            key_object: cryptography key object
            file (str): Key filename
            path (str): Full path to key file
            encrypted (bool): Whether key is encrypted
        """
```

#### Key Properties

```python
@property
def algorithm(self):
    """Get key algorithm (RSA or ECDSA)."""

@property
def key_size(self):
    """Get key size in bits."""

@property
def public_key(self):
    """Get corresponding public key."""
```

#### Key Methods

##### export_pem()
```python
def export_pem(self, passphrase=None):
    """
    Export key in PEM format.
    
    Args:
        passphrase (str): Passphrase for encryption
        
    Returns:
        str: PEM-encoded private key
    """
```

### CertificateSigningRequest

Represents a CSR.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import CertificateSigningRequest

class CertificateSigningRequest:
    """Represents a certificate signing request."""
    
    def __init__(self, csr_object=None, file=None, path=None):
        """
        Initialize CSR.
        
        Args:
            csr_object: cryptography CSR object
            file (str): CSR filename
            path (str): Full path to CSR file
        """
```

## Utility Classes

### FlexiClass

Provides dynamic property management with interpolation.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass

class FlexiClass:
    """Flexible class with dynamic properties and string interpolation."""
    
    def __init__(self, **kwargs):
        """
        Initialize with keyword arguments.
        
        Args:
            **kwargs: Initial properties
        """
```

#### Key Features

- Dynamic property access via dot notation
- String interpolation with `${variable}` syntax
- Nested property support
- Type preservation

#### Example Usage

```python
config = FlexiClass(
    domain="example.com",
    email="admin@${domain}",
    paths={
        "root": "/opt/pki",
        "ca": "${paths.root}/ca"
    }
)

print(config.email)  # "admin@example.com"
print(config.paths.ca)  # "/opt/pki/ca"
```

### ChangeTracker

Tracks changes during PKI operations.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangeTracker

class ChangeTracker:
    """Tracks changes for Ansible integration."""
    
    def __init__(self):
        """Initialize change tracker."""
```

#### Key Methods

##### add_change()
```python
def add_change(self, component, action, details=None):
    """
    Record a change.
    
    Args:
        component (str): Component that changed
        action (str): Action performed
        details (dict): Additional details
    """
```

##### get_summary()
```python
def get_summary(self):
    """
    Get change summary.
    
    Returns:
        dict: Summary with 'changed' boolean and 'changes' list
    """
```

## Enums and Constants

### CertificateTypes

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_types import CertificateTypes

class CertificateTypes(Enum):
    """Certificate type enumeration."""
    
    SERVER = "SERVER"           # TLS server authentication
    CLIENT = "CLIENT"           # TLS client authentication  
    SERVER_CLIENT = "SERVER_CLIENT"  # Both server and client
    CA = "CA"                   # Certificate Authority
    NONE = "NONE"              # No specific type
```

### KeyUsage

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.key_usage import KeyUsage

# Common key usage combinations
SERVER_KEY_USAGE = [
    "digitalSignature",
    "keyEncipherment"
]

CLIENT_KEY_USAGE = [
    "digitalSignature"
]

CA_KEY_USAGE = [
    "keyCertSign",
    "cRLSign"
]
```

### Default Values

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.defaults import (
    DEFAULT_KEY_SIZE,           # 2048
    DEFAULT_KEY_ALGORITHM,      # "RSA"
    DEFAULT_DIGEST_ALGORITHM,   # "sha256"
    DEFAULT_VALIDITY_DAYS,      # 365
    DEFAULT_CA_VALIDITY_DAYS,   # 3650
)
```

## Error Handling

### PKIError

Base exception for all PKI-related errors.

```python
from ansible_collections.khmarochos.pki.plugins.module_utils.errors import PKIError

class PKIError(Exception):
    """Base exception for PKI operations."""
    pass
```

### Common Exception Types

```python
class PKIInitializationError(PKIError):
    """Raised when PKI initialization fails."""
    pass

class PKICertificateError(PKIError):
    """Raised when certificate operations fail."""
    pass

class PKIKeyError(PKIError):
    """Raised when key operations fail."""
    pass

class PKIValidationError(PKIError):
    """Raised when validation fails."""
    pass
```

### Error Handling Best Practices

```python
try:
    # PKI operation
    ca = PKICA(nickname="test")
    ca.initialize()
except PKIInitializationError as e:
    # Handle initialization errors
    module.fail_json(msg=f"Failed to initialize CA: {str(e)}")
except PKIValidationError as e:
    # Handle validation errors
    module.fail_json(msg=f"Invalid configuration: {str(e)}")
except PKIError as e:
    # Handle other PKI errors
    module.fail_json(msg=f"PKI error: {str(e)}")
except Exception as e:
    # Handle unexpected errors
    module.fail_json(msg=f"Unexpected error: {str(e)}")
```

## Advanced Usage Examples

### Custom Certificate Extensions

```python
# Create a certificate with custom extensions
builder = CertificateBuilder()
builder.set_subject({
    "common_name": "custom.example.com",
    "organization_name": "Example Corp"
})

# Add custom extensions
builder.add_extension(
    x509.SubjectKeyIdentifier.from_public_key(public_key),
    critical=False
)
builder.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key),
    critical=False
)
builder.add_extension(
    x509.ExtendedKeyUsage([
        x509.oid.ExtensionOID.SERVER_AUTH,
        x509.oid.ExtensionOID.CLIENT_AUTH
    ]),
    critical=True
)

certificate = builder.build(
    private_key=private_key,
    issuer_cert=issuer_cert,
    issuer_key=issuer_key
)
```

### Programmatic CA Management

```python
# Create a complete PKI hierarchy programmatically
def create_pki_hierarchy(base_path="/opt/pki"):
    # Create root CA
    root_ca = PKICA(
        nickname="root",
        parameters={
            "name": "Root Certificate Authority",
            "private_key_encrypted": True,
            "private_key_size": 4096,
            "certificate_term": 7300,
            "paths": {"base": f"{base_path}/root"}
        }
    )
    root_ca.initialize()
    
    # Create intermediate CA
    intermediate_ca = PKICA(
        nickname="intermediate",
        parameters={
            "name": "Intermediate Certificate Authority",
            "private_key_encrypted": True,
            "certificate_term": 3650,
            "paths": {"base": f"{base_path}/intermediate"}
        },
        parent=root_ca
    )
    intermediate_ca.initialize()
    
    # Create specialized CAs
    for ca_type in ["web", "client", "vpn"]:
        specialized_ca = PKICA(
            nickname=ca_type,
            parameters={
                "name": f"{ca_type.title()} Services CA",
                "certificate_term": 1825,
                "paths": {"base": f"{base_path}/intermediate/{ca_type}"}
            },
            parent=intermediate_ca
        )
        specialized_ca.initialize()
    
    return root_ca, intermediate_ca
```

### Integration with External Systems

```python
# Export certificates for external systems
def export_for_external_system(ca, nickname):
    """Export certificate and key in various formats."""
    
    cert_path = f"{ca.paths.base}/certs/{nickname}.crt"
    key_path = f"{ca.paths.base}/private/{nickname}.key"
    
    # Load certificate and key
    cert = Certificate(path=cert_path)
    key = PrivateKey(path=key_path)
    
    # Export in different formats
    exports = {
        "pem": {
            "certificate": cert.export_pem(),
            "private_key": key.export_pem(),
            "chain": ca.get_certificate_chain_pem()
        },
        "der": {
            "certificate": cert.export_der(),
            "private_key": key.export_der()
        },
        "pkcs12": create_pkcs12_bundle(cert, key, ca.get_certificate_chain()),
        "java_keystore": create_jks_bundle(cert, key, ca.get_certificate_chain())
    }
    
    return exports
```

---

For more examples and the latest API updates, visit the [khmarochos.pki GitHub repository](https://github.com/khmarochos/khmarochos.pki).