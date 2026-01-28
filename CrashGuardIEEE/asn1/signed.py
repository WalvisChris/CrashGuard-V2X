"""dit script bevat alle ASN.1 definities die nodig zijn voor het opbouwen van een signed bericht"""

# als eerst importeren we de ASN.1 standaard
from pyasn1.type import univ, namedtype, constraint, namedval, char

class HashedId32(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(32, 32)

class HashedId48(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(48, 48)

# aangepast van univ.Choice naar univ.Sequence, meerdere opties mogelijk volgens IEEE 1609.2 standaard
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

# HeaderInfo is aan te vullen met veel meer velden, zoals ThreeDLocation, snelweg naam, afrit...
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

# Deze class hebben wij zelf toegevoegd
class UncompressedP256(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('x', univ.OctetString()),
        namedtype.NamedType('y', univ.OctetString())
    )

# aangepast van univ.Choice naar univ.Sequence, meerdere opties mogelijk volgens IEEE 1609.2 standaard
class EccP256CurvePoint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('uncompressed', UncompressedP256())
    )
    
class EcdsaP256Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32))),
        namedtype.NamedType('s', univ.OctetString(subtypeSpec=constraint.ValueSizeConstraint(32, 32)))
    )

# aangepast van univ.Choice naar univ.Sequence, meerdere opties mogelijk volgens IEEE 1609.2 standaard
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

# aangepast van univ.Choice naar univ.Sequence, meerdere opties mogelijk volgens IEEE 1609.2 standaard
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

# aangepast van univ.Choice naar univ.Sequence, meerdere opties mogelijk volgens IEEE 1609.2 standaard
class Duration(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hours', Uint16())
    )

class ValidityPeriod(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('start', Time32()),
        namedtype.NamedType('duration', Duration())
    )

# aangepast van univ.Choice naar univ.Sequence, meerdere opties mogelijk volgens IEEE 1609.2 standaard
class VerificationKeyIndicator(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ecdsaNistP256', EccP256CurvePoint())
    )

# ToBeSignecCertificate is aante vullen met nog veel meer velden die de IEEE 1609.2 standaard definieerd
class ToBeSignedCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', CertificateId()),
        namedtype.NamedType('cracaId', HashedId3()),
        namedtype.NamedType('crlSeries', CrlSeries()),
        namedtype.NamedType('validityPeriod', ValidityPeriod()),
        namedtype.NamedType('verifyKeyIndicator', VerificationKeyIndicator())
    )

# Wij maken bij de simulatie alleen gebruik van Explicit Certificates
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

# Deze class hebben wij zelf toegevoegd
class Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Uint8()),
        namedtype.NamedType('type', CertificateType()),
        namedtype.NamedType('issuer', IssuerIdentifier()),
        namedtype.NamedType('toBeSignedCert', ToBeSignedCertificate()),
        namedtype.NamedType('signature', univ.Any())
    )

# aangepast van univ.Choice naar univ.Sequence, meerdere opties mogelijk volgens IEEE 1609.2 standaard
class SignerIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificate', Certificate())
    )

# Koppelt getallen aan algoritmes, meerdere algoritmes zijn toe te voegen
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

# aangepast van univ.Choice naar univ.Sequence, meerdere opties mogelijk volgens IEEE 1609.2 standaard
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