import string
import enum


class CertificateTypes(enum.Enum):
    CA_STUBBY = 'ca_stubby'
    CA_INTERMEDIATE = 'ca_intermediate'
    SERVER = 'server'
    CLIENT = 'client'


class Constants:
    DEFAULT_CERTIFICATE_TERM = 300
    DEFAULT_KEY_SIZE = 4096
    DEFAULT_KEY_PUBLIC_EXPONENT = 65537
    DEFAULT_KEY_ENCRYPTED = False
    DEFAULT_PASSPHRASE_LENGTH = 32
    DEFAULT_PASSPHRASE_CHARACTER_SET = string.ascii_letters + string.digits + string.punctuation
    DEFAULT_PASSPHRASE_RANDOM = False

