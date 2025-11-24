from pyasn1.type import univ, namedtype, constraint, namedval, tag

# --- Unsigned Integers ---
class Uint8(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 255)

class Uint16(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 65535)

class Uint32(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 4294967295)

# --- Time ---
class Time32(Uint32):
    pass

class Time64(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 2^64-1)

class Duration(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('microseconds', univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        namedtype.NamedType('milliseconds', univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )),
        namedtype.NamedType('seconds', Uint32().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )),
        namedtype.NamedType('minutes', Uint32().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
        )),
        namedtype.NamedType('hours', Uint32().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
        )),
        namedtype.NamedType('sixtyHours', Uint32().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
        )),
        namedtype.NamedType('years', Uint32().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
        ))
    )

class ValidityPeriod(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('start', Time32()),
        namedtype.NamedType('duration', Duration())
    )

# --- Hashed ID ---
class HashedId8(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(8, 8)

class HashedId32(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(32, 32)

class HashedId48(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(6, 6) # 48 bits = 6 bytes

class Psid(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 255) # Max 255 for IEEE 1609.2

class PsidSsp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('psid', Psid()),
        namedtype.OptionalNamedType('ssp', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, 32)
        ))
    )

# --- Public Key & Signature ---
# ECDSA P-256 is the standard curve
class EccP256Curve(univ.Integer):
    namedValues = namedval.NamedValues(
        ('prime256v1', 0)
    )

class EccP256PublicKey(univ.Sequence):
    # Represents the uncompressed public key point (x, y)
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('x', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(32, 32) # 256 bits = 32 bytes
        )),
        namedtype.NamedType('y', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(32, 32)
        ))
    )

class EccP256Signature(univ.Sequence):
    # Represents the signature (r, s) values
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(32, 32)
        )),
        namedtype.NamedType('s', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(32, 32)
        ))
    )

class PublicVerificationKey(univ.Choice):
    # Wrapper for supported public key types
    componentType = namedtype.NamedTypes(
        # Other key types omitted for brevity, focusing on mandatory P256
        namedtype.NamedType('ecdsaNistP256', EccP256PublicKey().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        ))
    )

class Signature(univ.Choice):
    # Wrapper for supported signature types
    componentType = namedtype.NamedTypes(
        # Other signature types omitted for brevity, focusing on mandatory P256
        namedtype.NamedType('ecdsaNistP256Signature', EccP256Signature().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        ))
    )

# --- Signed Data ---
class HeaderInfo(univ.Sequence):
    # Context-specific header information for the message
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('psid', Psid().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        # Other optional fields like generationTime, expiryTime, etc., omitted for brevity
    )

class ToBeSignedData(univ.Sequence):
    # The message content and security metadata that is signed
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('payload', univ.OctetString()), # The actual application data
        namedtype.NamedType('headerInfo', HeaderInfo())
    )

class Certificate(univ.OctetString):
    # The actual certificate structure is complex, but often referred to as an OCTET STRING
    # within the SignedData context.
    pass

class SignerIdentifier(univ.Choice):
    # Identifies the entity that signed the message
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('digest', HashedId8().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        namedtype.NamedType('certificate', Certificate().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )),
        # Other types like enrollmentCertificate etc. omitted
    )

class SignedData(univ.Sequence):
    # Contains the data to be signed and the signature structure
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashId', univ.Integer(namedValues=namedval.NamedValues(('sha256', 0)))), # Hash Algorithm
        namedtype.NamedType('tbsData', ToBeSignedData()), # The data that was hashed and signed
        namedtype.NamedType('signer', SignerIdentifier()),
        namedtype.NamedType('signature', Signature())
    )

class Ieee1609Dot2Data(univ.Sequence):
    # The outer wrapper for all 1609.2 security messages.
    # Defines the protocol version and the secured content (the payload).
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Uint8()), # Must be 3 for the current standard
        namedtype.NamedType('content', univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('unsecuredData', univ.OctetString().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                )),
                namedtype.NamedType('signedData', SignedData().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
                )),
                # Other choices like encryptedData, signedCertificateRequest omitted
            )
        ))
    )