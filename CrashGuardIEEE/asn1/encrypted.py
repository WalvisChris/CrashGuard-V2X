"""dit script bevat alle ASN.1 definities die nodig zijn voor het opbouwen van een encrypted bericht"""

# als eerst importeren we de ASN.1 standaard
from pyasn1.type import univ, namedtype, constraint, namedval

class HashedId8(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(8, 8)

class PreSharedKeyRecipientInfo(HashedId8):
    pass

# aangepast van univ.Choice naar univ.Sequence, meerdere opties mogelijk volgens IEEE 1609.2 standaard
class RecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pskRecipInfo', PreSharedKeyRecipientInfo()),
    )

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

# aangepast van univ.Choice naar univ.Sequence, meerdere opties mogelijk volgens IEEE 1609.2 standaard
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