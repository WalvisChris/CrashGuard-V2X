from TerminalInterface import *
from pyasn1.codec.der import encoder
from asn1 import *

def _clone_tagged_value(asn1_container, component_name, value):
    """
    Clones the specific type from the container's schema (which holds the tag)
    and sets its value. Necessary for implicitly tagged components in Choices/Sequences.
    """
    component_spec = asn1_container.getComponentByName(component_name)
    # Check if the component is an inner type definition (like in a Sequence) or the final schema (like in a Choice)
    if hasattr(component_spec, 'getComponentType'):
        component_schema = component_spec.getComponentType()
    else:
        component_schema = component_spec
        
    return component_schema.clone(value)

def unsecure(payload: bytes) -> bytes:
    """
    Encodes raw application data (payload) into a DER-encoded,
    unsecured Ieee1609Dot2Data message.
    """
    ieee1609_data = Ieee1609Dot2Data()
    ieee1609_data.setComponentByName('version', Uint8(3))

    unsecured_content = ieee1609_data.getComponentByName('content')
    
    # Use the utility to create the correctly tagged unsecuredData value [0]
    unsecured_data_value = _clone_tagged_value(unsecured_content, 'unsecuredData', payload)

    unsecured_content.setComponentByName(
        'unsecuredData',
        unsecured_data_value
    )

    der_bytes = encoder.encode(ieee1609_data)
    return der_bytes

def signed(payload: bytes, psid: int, signer_id_digest: bytes, signature_r_s: bytes) -> bytes:
    """
    Encodes raw application data and security inputs into a DER-encoded,
    signed Ieee1609Dot2Data message.

    NOTE: This function assumes the signature_r_s input (R || S) is already
    calculated based on the hash of the ToBeSignedData structure.
    """
    if len(signer_id_digest) != 8:
        raise ValueError("Signer ID Digest must be exactly 8 bytes (HashedId8).")
    if len(signature_r_s) != 64:
        raise ValueError("Signature R || S must be exactly 64 bytes (32 for R, 32 for S).")

    # --- 1. Construct HeaderInfo (Part of TBS) ---
    header_info = HeaderInfo()
    # The 'psid' component is optional and implicitly tagged [0] in HeaderInfo
    psid_value = _clone_tagged_value(header_info, 'psid', Psid(psid))
    header_info.setComponentByName('psid', psid_value)

    # --- 2. Construct ToBeSignedData (TBS) ---
    tbs_data = ToBeSignedData()
    tbs_data.setComponentByName('payload', univ.OctetString(payload))
    tbs_data.setComponentByName('headerInfo', header_info)
    
    # --- 3. Construct Signature ---
    r_component = signature_r_s[:32]
    s_component = signature_r_s[32:]

    ecc_sig = EccP256Signature()
    ecc_sig.setComponentByName('r', univ.OctetString(r_component))
    ecc_sig.setComponentByName('s', univ.OctetString(s_component))
    
    # The 'ecdsaNistP256Signature' component is implicitly tagged [0] in Signature Choice
    signature_choice = Signature()
    signature_value = _clone_tagged_value(signature_choice, 'ecdsaNistP256Signature', ecc_sig)
    signature_choice.setComponentByName('ecdsaNistP256Signature', signature_value)

    # --- 4. Construct SignerIdentifier ---
    # The 'digest' component is implicitly tagged [0] in SignerIdentifier Choice
    signer_id_choice = SignerIdentifier()
    signer_id_value = _clone_tagged_value(signer_id_choice, 'digest', HashedId8(signer_id_digest))
    signer_id_choice.setComponentByName('digest', signer_id_value)

    # --- 5. Construct SignedData ---
    signed_data = SignedData()
    signed_data.setComponentByName('hashId', 0) # Assumes SHA256 as per 1609.2
    signed_data.setComponentByName('tbsData', tbs_data)
    signed_data.setComponentByName('signer', signer_id_choice)
    signed_data.setComponentByName('signature', signature_choice)
    
    # --- 6. Wrap in Ieee1609Dot2Data ---
    ieee1609_data = Ieee1609Dot2Data()
    ieee1609_data.setComponentByName('version', Uint8(3))

    content_choice = ieee1609_data.getComponentByName('content')
    # The 'signedData' component is implicitly tagged [1] in content Choice
    signed_data_value = _clone_tagged_value(content_choice, 'signedData', signed_data)
    content_choice.setComponentByName('signedData', signed_data_value)

    # 7. Encode the complete structure using DER
    der_bytes = encoder.encode(ieee1609_data)
    return der_bytes

def encrypted() -> bytes:
    pass

def enveloped() -> bytes:
    pass

if __name__ == "__main__":
    screen = TerminalInterface()
    screen.clear()

    payload = screen.input(prompt="enter payload: ")
    payload_bytes = payload.encode()

    screen.clear()
    screen.text(text=payload)
    content_types = ["unsecured", "signed", "encrypted", "enveloped"]
    screen.textbox(title="select type:", items=content_types, numbered=True)
    content_type = int(screen.input("> "))

    screen.clear()

    # --- Starting data ---
    PSID = 32

    # --- Encode data type ---
    if content_type == 1:

        msg = unsecure(payload=payload_bytes)
        screen.demoLog(title="Unsecure", text=msg, title_color="cyan")

    elif content_type == 2:

        msg = signed(payload=payload_bytes)
        screen.demoLog(title="Signed", text=msg, title_color="cyan")

    elif content_type == 3:

        msg = encrypted()
        screen.demoLog(title="Encrypted", text=msg, title_color="cyan")

    elif content_type == 4:

        msg = enveloped()
        screen.demoLog(title="Enveloped", text=msg, title_color="cyan")

    else:
        screen.text(text="invalid content type!", color="bright_red")