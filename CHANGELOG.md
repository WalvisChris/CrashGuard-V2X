## [2.2] - 2025/11/13  
- added corrected ASN.1 classes. updated encode.py accordingly.  

## [2.1] - 2025/11/23
- added GenerationTime check and signature verification on receiver side.  
- added real private and public keys to the demo.  

## [2.0] - 2025/11/19  
- added "EnvelopedData" ASN.1 structure which combines "SignedData" and "EncryptedData".  
- removed Public Key Infrasturcture and added GROUP_KEY for scalability.  
- code cleanup.  

## [1.1] - 2025/11/15  
- added WAVE message decoding.  

## [1.0] - 2025/11/14  
- added WAVE message encoding  
    - added Public Key Infrastructure to encrypt data.  
    - added neccessary ASN.1 structures: HeaderInfo, ToBeSignedData, SignerInfo, SignedData, RecipientInfo, EncryptedData, Ieee1609Dot2Data.  
- first release.  