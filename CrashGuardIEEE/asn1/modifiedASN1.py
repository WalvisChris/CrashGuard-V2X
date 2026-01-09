from pyasn1.type import univ, namedtype, constraint, namedval, char

class SignedDataPayload(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('data', univ.OctetString()),
    )

class Psid(univ.Integer):
    pass

class Uint64(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 18446744073709551615)

class Time64(Uint64):
    pass

class HeaderInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('psid', Psid()),
        namedtype.NamedType('generationTime', Time64()),
        namedtype.NamedType('expiryTime', Time64()),
    )

class ToBeSignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('payload', SignedDataPayload()),
        namedtype.NamedType('headerInfo', HeaderInfo())
    )

class UncompressedP256(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('x', univ.OctetString()),
        namedtype.NamedType('y', univ.OctetString())
    )

# CHOICE > SEQUENCE
class EccP256CurvePoint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('uncompressed', UncompressedP256())
    )

class VerificationKeyIndicator(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ecdsaNistP256', EccP256CurvePoint())
    )

class Hostname(char.UTF8String):
    subtypeSpec = constraint.ValueSizeConstraint(0, 255)

class CertificateId(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', Hostname())
    )

class HashedId3(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(3, 3)

class Uint16(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 65535)

class CrlSeries(Uint16):
    pass

class Uint32(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 4294967295)

class Time32(Uint32):
    pass

# CHOICE > SEQUENCE
class Duration(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hours', Uint16())
    )

class ValidityPeriod(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('start', Time32()),
        namedtype.NamedType('duration', Duration())
    )

class ToBeSignedCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', CertificateId()),
        namedtype.NamedType('cracaId', HashedId3()),
        namedtype.NamedType('crlSeries', CrlSeries()),
        namedtype.NamedType('validityPeriod', ValidityPeriod()),
        namedtype.NamedType('verifyKeyIndicator', VerificationKeyIndicator())
    )

class Uint8(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 255)

class CertificateType(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('explicit', 0),
        ('implicit', 1)
    )

class HashedId8(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(8, 8)

class IssuerIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('sha256AndDigest', HashedId8())
    )

# CUSTOM CERTIFICATE CLASS (EXPLICIT)
class Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Uint8()),
        namedtype.NamedType('type', CertificateType()),
        namedtype.NamedType('issuer', IssuerIdentifier()),
        namedtype.NamedType('toBeSignedCert', ToBeSignedCertificate()),
        namedtype.NamedType('signature', univ.Any())
    )

# CHOICE > SEQUENCE
class SignerIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificate', Certificate())
    )

class EcdsaP256Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32))),
        namedtype.NamedType('s', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32)))
    )

# CHOICE > SEQUENCE
class Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ecdsaNistP256Signature', EcdsaP256Signature())
    )

class HashAlgorithm(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('sha256', 0),
        ('sha384', 1),
        ('sm3', 2)
    )

class SignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashId', HashAlgorithm()),
        namedtype.NamedType('tbsData', ToBeSignedData()),
        namedtype.NamedType('signer', SignerIdentifier()),
        namedtype.NamedType('signature', Signature())
    )

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

class PreSharedKeyRecipientInfo(HashedId8):
    pass

# CHOICE > SEQUENCE
class RecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pskRecipInfo', PreSharedKeyRecipientInfo()),
    )

class SequenceOfRecipientInfo(univ.SequenceOf):
    componentType = RecipientInfo()

class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipients', SequenceOfRecipientInfo()),
        namedtype.NamedType('ciphertext', SymmetricCiphertext())
    )

class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipients', SequenceOfRecipientInfo()),
        namedtype.NamedType('ciphertext', SymmetricCiphertext())
    )

"""
# CHOICE > SEQUENCE
class Ieee1609Dot2Content(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('encryptedData', EncryptedData()),
    )
"""

# TESTING
class Ieee1609Dot2Content(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('unsecureData', Opaque()),
        namedtype.OptionalNamedType('signedData', SignedData()),
        namedtype.OptionalNamedType('encryptedData', EncryptedData()),
    )

class Ieee1609Dot2Data(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('protocolVersion', Uint8()),
        namedtype.NamedType('content', Ieee1609Dot2Content())
    )