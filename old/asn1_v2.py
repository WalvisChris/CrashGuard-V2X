from pyasn1.type import univ, char, namedtype, namedval, constraint, tag

# --- Basic types ---
class Uint8(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 255)

class Uint16(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 65535)

class Uint32(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 2**32-1)

class Uint256(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 2**256-1)

# --- HashedData ---
class HashedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashAlgorithm',
            univ.ObjectIdentifier().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.NamedType('hashedData',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        )
    )

# --- HeaderInfo ---
class HeaderInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('psid', Uint32()),
        namedtype.NamedType('generationTime', univ.Integer()),
        namedtype.OptionalNamedType('expiryTime', univ.Integer())
    )

# --- ToBeSignedData ---
class ToBeSignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('payload', univ.OctetString()),
        namedtype.NamedType('headerInfo', HeaderInfo()),
        namedtype.OptionalNamedType('extDataHash',
            HashedData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )
        )
    )

# --- ECDSA signature (r,s) ---
class EcdsaP256Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', Uint256()),
        namedtype.NamedType('s', Uint256())
    )

# --- Signature CHOICE ---
class Signature(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ecdsaNistP256Signature',
            EcdsaP256Signature().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )
        )
    )

# --- SignerIdentifier CHOICE ---
class SignerIdentifier(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificate',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.NamedType('digest',
            HashedData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            )
        ),
        namedtype.NamedType('self',
            univ.Null().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )
        )
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
        namedtype.OptionalNamedType('hashId',
            univ.Integer().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        )
    )

# --- RecipientInfo ---
class RecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipientID',
            char.UTF8String().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        )
    )

# --- EncryptedData ---
class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipients',
            univ.SequenceOf(componentType=RecipientInfo()).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )
        ),
        namedtype.NamedType('ciphertext',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        ),
        namedtype.NamedType('icv',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )
        ),
        namedtype.NamedType('symmAlgorithm',
            univ.Integer().subtype(                     # FIX: NOT OID
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            )
        )
    )

# --- EnvelopedData ---
class EnvelopedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('recipients',
            univ.SequenceOf(componentType=RecipientInfo()).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )
        ),
        namedtype.NamedType('encryptedContent',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        ),
        namedtype.NamedType('icv',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )
        ),
        namedtype.NamedType('symmAlgorithm',
            univ.Integer().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            )
        )
    )

# --- 1609.2 Content CHOICE ---
class Ieee1609Dot2Content(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('unsecuredData',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.NamedType('signedData',
            SignedData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            )
        ),
        namedtype.NamedType('encryptedData',
            EncryptedData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
            )
        ),
        namedtype.NamedType('envelopedData',
            EnvelopedData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
            )
        )
    )

# --- Top-level 1609.2 message ---
class Ieee1609Dot2Data(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('protocolVersion', Uint8()),
        namedtype.NamedType('contentType',
            univ.Enumerated(
                namedValues=namedval.NamedValues(
                    ('unsecuredData', 0),
                    ('signedData', 1),
                    ('encryptedData', 2),
                    ('envelopedData', 3)
                )
            ).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.NamedType('content',
            Ieee1609Dot2Content().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            )
        )
    )