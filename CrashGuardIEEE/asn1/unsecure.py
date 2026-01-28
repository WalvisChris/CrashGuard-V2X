"""dit script bevat alle ASN.1 definities die nodig zijn voor het opbouwen van een unsecure bericht"""

# als eerst importeren we de ASN.1 standaard
from pyasn1.type import univ, namedtype, constraint, namedval

class Opaque(univ.OctetString):
    pass

class Ieee1609Dot2Content(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('unsecureData', Opaque()),
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