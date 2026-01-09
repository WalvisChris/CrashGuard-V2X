from pyasn1.type import univ, namedtype, constraint, namedval

class HashedId8(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(8, 8)

class PreSharedKeyRecipientInfo(HashedId8):
    pass

# CHOICE > SEQUENCE
class RecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pskRecipInfo', PreSharedKeyRecipientInfo()),
    )
"""
- pskRecipInfo: The data was encrypted directly using a pre-shared symmetric key.

- symmRecipInfo: The data was encrypted with a data encryption key, and the data encryption key was encrypted using a symmetric key.

- certRecipInfo: The data was encrypted with a data encryption key, the data encryption key was encrypted using a public key encryption
scheme, where the public encryption key was obtained from a certificate. In this case, the parameter P1 to ECIES as defined in 5.3.5 is
the hash of the certificate, calculated with the whole-certificate hash algorithm, determined as described in 6.4.3, applied to the
COER-encoded certificate, canonicalized as defined in the definition of Certificate.

NOTE: If the encryption algorithm is SM2, there is no equivalent of the parameter P1 and so no input to the encryption process that
uses the hash of the certificate.

- signedDataRecipInfo: The data was encrypted with a data encryption key, the data encryption key was encrypted using a public key
encryption scheme, where the public encryption key was obtained as the public response encryption key from a SignedData. In this case,
if ECIES is the encryption algorithm, then the parameter P1 to ECIES as defined in 5.3.5 is the SHA256 hash of the Ieee1609Dot2Data of
type SignedData containing the response encryption key, canonicalized as defined in the definition of Ieee1609Dot2Data.

NOTE: If the encryption algorithm is SM2, there is no equivalent of the parameter P1 and so no input to the encryption process that
uses the hash of the Ieee1609Dot2Data.

- rekRecipInfo: The data was encrypted with a data encryption key, the data encryption key was encrypted using a public key encryption
scheme, where the public encryption key was not obtained from a SignedData or a certificate. In this case, the SDEE specification is
expected to specify how the public key is obtained, and if ECIES is the encryption algorithm, then the parameter P1 to ECIES as defined
in 5.3.5 is the hash of the empty string.
"""

class SequenceOfRecipientInfo(univ.SequenceOf):
    componentType = RecipientInfo()

class Opaque(univ.OctetString):
    pass

class One28BitCcmCiphertext(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('nonce', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(12, 12))),
        namedtype.NamedType('ccmCiphertext', Opaque())
    )

class SymmetricCiphertext(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('aes128ccm', One28BitCcmCiphertext()),
    )

class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipients', SequenceOfRecipientInfo()),
        namedtype.NamedType('ciphertext', SymmetricCiphertext())
    )

# CHOICE > SEQUENCE
class Ieee1609Dot2Content(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('encryptedData', EncryptedData()),
    )

class Uint8(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 255)

class ContentType(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('unsecureData', 0),
        ('signedData', 1),
        ('encryptedData', 2),
        ('envelopedData', 3)
    )

class Ieee1609Dot2Data(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('protocolVersion', Uint8()),
        namedtype.NamedType('contentType', ContentType()),
        namedtype.NamedType('content', Ieee1609Dot2Content())
    )