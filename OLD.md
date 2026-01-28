# CrashGuard V2X  
Research about IEEE 1609.2 for V2X applications.  

### Features  
- Custom Libary (CrashGuardIEEE)  
- ASN.1 (IEEE 1609.2)  
- Root CA  
- PKI  
- Encoding:  
    - unsecure data  
    - signed data  
    - encrypted data  
    - enveloped data  
- Decoding:  
    - unsecure data  
    - signed data  
    - encrypted data  
    - enveloped data  
- Visualization  

### Validtion  
- Message time  
- Certificate time  
- Message signature  
- Certificate signature  
- PskId matching  
- Encryption  

### Testing  
- MITM:  
    - Protocol Version  
    - Content Type  
    - Payload  
    - PSID (signed)  
    - Generation Time (signed)  
    - Expiry Time (signed)  
    - Signer name (signed)  
    - Validity period – start (signed)  
    - Validity period – duration (signed)  
    - PskId (encrypted & enveloped)  
    - Nonce (encrypted & enveloped)  
- Replay:  
    - TODO  
- Keys:  
    - change ROOT_CA keys  
    - change SENDER keys  
    - change PSK (pre shared key)  

### TODO  
- testing.py:
    - Replay > oud `enveloped` bericht oproepen.  
    - Visualizer  
    - Real GPS headerdata  