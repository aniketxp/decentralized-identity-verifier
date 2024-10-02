# First, let's install the required libraries
!pip install py-multibase pyjwt cryptography requests

import requests
import jwt
import multibase
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import json
from datetime import datetime, timedelta

class DecentralizedIdentityVerifier:
    def __init__(self):
        # Generate a key pair for demonstration purposes
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def resolve_did(self, did):
        """Simulate resolving a DID to its DID document"""
        # This is a mock implementation
        return {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did,
            "verificationMethod": [{
                "id": f"{did}#keys-1",
                "type": "RsaVerificationKey2018",
                "controller": did,
                "publicKeyMultibase": self.public_key_to_multibase()
            }]
        }

    def public_key_to_multibase(self):
        """Convert public key to multibase format"""
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return multibase.encode('base58btc', public_key_bytes).decode()

    def verify_credential(self, credential):
        """Verify a Verifiable Credential"""
        try:
            # Extract the signature from the credential
            signature = credential.pop('proof')['jws']
            # Verify the signature
            jwt.decode(signature, self.public_key, algorithms=['RS256'])
            return True
        except Exception as e:
            print(f"Verification failed: {str(e)}")
            return False

    def issue_credential(self, issuer_did, subject_did, claims):
        """Issue a new Verifiable Credential"""
        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": issuer_did,
            "issuanceDate": datetime.utcnow().isoformat() + "Z",
            "expirationDate": (datetime.utcnow() + timedelta(days=365)).isoformat() + "Z",
            "credentialSubject": {
                "id": subject_did,
                **claims
            }
        }
        
        # Sign the credential
        token = jwt.encode(
            credential,
            self.private_key,
            algorithm='RS256'
        )
        
        # Add the proof
        credential['proof'] = {
            "type": "RsaSignature2018",
            "created": datetime.utcnow().isoformat() + "Z",
            "jws": token
        }
        
        return credential

# Usage example
verifier = DecentralizedIdentityVerifier()

# Resolve a DID
did = "did:example:123456789abcdefghi"
did_document = verifier.resolve_did(did)
print(f"DID Document: {json.dumps(did_document, indent=2)}")

# Issue a new credential
new_credential = verifier.issue_credential(
    "did:example:issuer",
    "did:example:subject",
    {"name": "Alice", "age": 30}
)
print(f"\nNew credential: {json.dumps(new_credential, indent=2)}")

# Verify the credential
is_valid = verifier.verify_credential(new_credential)
print(f"\nCredential is valid: {is_valid}")
