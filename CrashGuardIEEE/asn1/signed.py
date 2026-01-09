from pyasn1.type import univ, namedtype, constraint, namedval, char

class HashedId32(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(32, 32)

class HashedId48(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(48, 48)

# CHOICE > SEQUENCE
class HashedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('sha256HashedData', HashedId32())
    )

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

# CHOICE > SEQUENCE
"""
class EccP256CurvePoint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('x-only', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32)))
    )
"""
    
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

class HashedId8(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(8, 8)

class HashedId3(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(3, 3)

class Hostname(char.UTF8String):
    subtypeSpec = constraint.ValueSizeConstraint(0, 255)

# CHOICE > SEQUENCE
class CertificateId(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', Hostname())
    )

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

# CHOICE > SEQUENCE
class VerificationKeyIndicator(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ecdsaNistP256', EccP256CurvePoint())
    )

class ToBeSignedCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', CertificateId()),
        namedtype.NamedType('cracaId', HashedId3()),
        namedtype.NamedType('crlSeries', CrlSeries()),
        namedtype.NamedType('validityPeriod', ValidityPeriod()),
        namedtype.NamedType('verifyKeyIndicator', VerificationKeyIndicator())
    )

class CertificateType(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('explicit', 0),
        ('implicit', 1)
    )

class Uint8(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 255)

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

# CHOICE > SEQUENCE
class Ieee1609Dot2Content(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('signedData', SignedData())
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