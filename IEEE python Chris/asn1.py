from pyasn1.type import univ, char, namedtype, namedval, constraint

# --- Basic types ---
class Uint8(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 255)

class Uint16(univ.Integer):
    constraint.ValueRangeConstraint(0, 65535)

class Uint32(univ.Integer):
    constraint.ValueRangeConstraint(0, 2**32-1)

class Uint256(univ.Integer):
    constraint.ValueRangeConstraint(0, 2**256-1)

# --- HashedData (Simplified) ---
class HashedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashAlgorithm', univ.ObjectIdentifier()),
        namedtype.NamedType('hashedData', univ.OctetString())
    )

# --- HeaderInfo ---
class HeaderInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('psid', Uint32()),
        namedtype.NamedType('generationTime', univ.Integer()),
        namedtype.OptionalNamedType('expiryTime', univ.Integer())
        # TODO other optional fields
    )

# --- ToBeSignedData ---
class ToBeSignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('payload', univ.OctetString()),
        namedtype.NamedType('headerInfo', HeaderInfo()),
        namedtype.OptionalNamedType('extDataHash', HashedData())
    )

# --- EcdsaP256Signature ---
class EcdsaP256Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', Uint256()),
        namedtype.NamedType('s', Uint256())
    )

# --- SignatureChoice (Choice) ---
class Signature(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ecdsaNistP256Signature', EcdsaP256Signature())
        # TODO other curves
    )

# --- SignerIdentifier CHOICE ---
class SignerIdentifier(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificate', univ.OctetString()),  # actual certificate bytes
        namedtype.NamedType('digest', HashedData()),
        namedtype.NamedType('self', univ.Null())
    )

# --- SignerInfo ---
class SignerInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('signer', SignerIdentifier()),
        namedtype.NamedType('signature', Signature()),
        namedtype.OptionalNamedType('extDataHash', HashedData())
    )

# --- SignedData ---
class SignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsData', ToBeSignedData()),
        namedtype.NamedType('signerInfo', SignerInfo()),
        namedtype.OptionalNamedType('hashId', univ.Integer())
    )

# --- RecipientInfo ---
class RecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipientID', char.UTF8String())
    )

# --- EncryptedData ---
class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipients', univ.SequenceOf(componentType=RecipientInfo())),
        namedtype.NamedType('ciphertext', univ.OctetString()),
        namedtype.NamedType('icv', univ.OctetString()),
        namedtype.NamedType('symmAlgorithm', univ.ObjectIdentifier())
    )

# --- EnvelopedData ---
class EnvelopedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipients', univ.SequenceOf(componentType=RecipientInfo())),
        namedtype.NamedType('encryptedContent', univ.OctetString()),
        namedtype.NamedType('icv', univ.OctetString()),
        namedtype.NamedType('symmAlgorithm', univ.ObjectIdentifier())
    )

# --- Ieee1609Dot2Content CHOICE ---
class Ieee1609Dot2Content(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('unsecuredData', univ.OctetString()),
        namedtype.NamedType('signedData', SignedData()),
        namedtype.NamedType('encryptedData', EncryptedData()),
        namedtype.NamedType('envelopedData', EnvelopedData())
    )

# --- Ieee1609Dot2Data ---
class Ieee1609Dot2Data(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('protocolVersion', Uint8()),
        namedtype.NamedType('contentType', univ.Enumerated(
            namedValues=namedval.NamedValues(
                ('unsecuredData', 0),
                ('signedData', 1),
                ('encryptedData', 2),
                ('envelopedData', 3)
            )
        )),
        namedtype.NamedType('content', Ieee1609Dot2Content())
    )