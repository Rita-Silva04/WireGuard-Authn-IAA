import os
import sys
import time
import struct
from typing import Optional, Tuple
import cbor2
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from hashing import *

# CTAP HID Commands
CMD_PING = 0x81
CMD_MSG = 0x83
CMD_INIT = 0x86
CMD_WINK = 0x88
CMD_CBOR = 0x90
CMD_CANCEL = 0x91
CMD_BUSY = 0xBB

# CTAP2 Commands
CTAP2_GET_INFO = 0x04
CTAP2_CLIENT_PIN = 0x06
CTAP2_MAKE_CREDENTIAL = 0x01
CTAP2_GET_ASSERTION = 0x02
CTAP2_RESET = 0x07
CTAP2_CREDENTIAL_MANAGEMENT_PREVIEW = 0x41

# Constants
BROADCAST_CID = 0xFFFFFFFF
PACKET_SIZE = 64


class FIDOClient:
 
 REAL_PIN = b"1234"
 error_codes = {
 0x01: "CTAP1_ERR_INVALID_COMMAND",
 0x02: "CTAP1_ERR_INVALID_PARAMETER", 
 0x03: "CTAP1_ERR_INVALID_LENGTH",
 0x11: "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
 0X30: "CTAP2_ERR_NOT_ALLOWED",
 0x31: "CTAP2_ERR_PIN_INVALID",
 0x32: "CTAP2_ERR_PIN_BLOCKED",
 0x33: "CTAP2_ERR_PIN_AUTH_INVALID",
 0x34: "CTAP2_ERR_PIN_AUTH_BLOCKED",
 0x35: "CTAP2_ERR_PIN_NOT_SET",
 0x36: "CTAP2_ERR_PUAT_REQUIRED",
 0xBB: "CTAP2_ERR_REQUEST_TOO_LARGE / BUSY",
 0X7F: "CTAP1_ERR_OTHER"
 }
 
 def __init__(self, device_path="", real_fd=None):
 self.device_path = device_path
 self.fd = real_fd
 self.cid = BROADCAST_CID
 self.current_pin_token = None
 self.tokens_pub = None
 self.users = {}

 def parse_auth_data(self, auth_data: bytes):
 offset = 0

 rp_id_hash = auth_data[offset:offset+32]
 offset += 32

 flags = auth_data[offset]
 offset += 1

 sign_count = int.from_bytes(auth_data[offset:offset+4], "big")
 offset += 4

 # Attested Credential Data
 aaguid = auth_data[offset:offset+16]
 offset += 16

 cred_id_len = int.from_bytes(auth_data[offset:offset+2], "big")
 offset += 2

 credential_id = auth_data[offset:offset+cred_id_len]
 offset += cred_id_len

 # Public key is CBOR — decode it
 cose_key = cbor2.loads(auth_data[offset:])

 return {
 "credentialId": credential_id,
 "publicKey": cose_key,
 "signCount": sign_count
 }

 def cose_key_to_ec_public_key(self, cose_key: dict):
 """
 Converts a COSE EC2 key (ES256) into a cryptography EC public key.

 Expected COSE structure:
 1: kty (2 = EC2)
 3: alg (-7 = ES256)
 -1: crv (1 = P-256)
 -2: x coordinate (bytes)
 -3: y coordinate (bytes)
 """

 # Required COSE labels
 kty = cose_key.get(1)
 alg = cose_key.get(3)
 crv = cose_key.get(-1)
 x = cose_key.get(-2)
 y = cose_key.get(-3)

 if kty != 2:
 raise ValueError(f"Unsupported kty (expected 2/EC2): {kty}")
 if alg != -7:
 raise ValueError(f"Unsupported alg (expected -7/ES256): {alg}")
 if crv != 1:
 raise ValueError(f"Unsupported curve (expected 1/P-256): {crv}")

 # Build EC public numbers
 numbers = ec.EllipticCurvePublicNumbers(
 int.from_bytes(x, "big"),
 int.from_bytes(y, "big"),
 ec.SECP256R1()
 )

 return numbers.public_key()

 def open(self):
 """Open the FIDO device"""
 try:
 self.fd = os.open(self.device_path, os.O_RDWR)
 print(f" Opened device: {self.device_path}")
 except Exception as e:
 print(f" Failed to open device: {e}")
 sys.exit(1)
 
 def close(self):
 """Close the FIDO device"""
 if self.fd:
 os.close(self.fd)
 print(" Device closed")
 
 def send_packet(self, data: bytes):
 """Send a raw HID packet (64 bytes)"""
 # Prepend the report ID (0x00) as required by UHID
 if len(data) != PACKET_SIZE:
 data = data.ljust(PACKET_SIZE, b'\x00')
 packet = b'\x00' + data # Report ID + 64 bytes
 os.write(self.fd, packet)
 print(f" Sent: {data[:16].hex()}...")
 
 def recv_packet(self, timeout: float = 5.0) -> Optional[bytes]:
 """Receive a raw HID packet"""
 import select
 rlist, _, _ = select.select([self.fd], [], [], timeout)
 if not rlist:
 print("⏱ Timeout waiting for response")
 return None
 data = os.read(self.fd, PACKET_SIZE + 1) # +1 for report ID
 # Strip report ID if present
 if len(data) == PACKET_SIZE + 1:
 data = data[1:]
 print(f" Recv: {data[:16].hex()}...")
 return data
 
 def send_message(self, cmd: int, data: bytes = b''):
 """Send a CTAPHID message (handles fragmentation)"""
 # Initial packet
 payload_len = len(data)
 header = struct.pack('>IBH', self.cid, cmd, payload_len)
 
 first_packet = header + data[:PACKET_SIZE - len(header)]
 self.send_packet(first_packet)
 
 # Continuation packets
 offset = PACKET_SIZE - len(header)
 seq = 0
 while offset < len(data):
 cont_header = struct.pack('>IB', self.cid, seq)
 chunk = data[offset:offset + PACKET_SIZE - len(cont_header)]
 cont_packet = cont_header + chunk
 self.send_packet(cont_packet)
 offset += len(chunk)
 seq += 1
 
 def recv_message(self, expect_cmd=None, expect_nonce=None) -> Optional[Tuple[int, bytes]]:
 """
 Receive a CTAPHID message.
 - Handles fragmentation
 - Filters browser CTAPHID_INIT (0x86) safely
 - If expect_cmd is set, ignores other messages
 """

 while True: # loop until we get a usable message
 packet = self.recv_packet()
 if not packet:
 return None
 
 cid, cmd, payload_len = struct.unpack('>IBH', packet[:7])
 data = packet[7:]

 if self.cid != BROADCAST_CID and cid != self.cid and cid != BROADCAST_CID:
 print(f" CID changed: {self.cid:08x} → {cid:08x}")
 self.cid = cid

 # Collect continuation packets
 seq = 0
 while len(data) < payload_len:
 next_packet = self.recv_packet()
 if not next_packet:
 break

 recv_cid, recv_seq = struct.unpack('>IB', next_packet[:5])
 if recv_cid != cid or recv_seq != seq:
 print(f" Sequence error: expected {seq}, got {recv_seq}")
 break

 data += next_packet[5:]
 seq += 1

 if cmd == 0xbb:
 print(" Device BUSY, waiting 200ms...")
 time.sleep(0.2)
 continue 

 if cmd == CMD_INIT and expect_nonce is not None:
 if len(data) >= 8:
 recv_nonce = data[:8]
 if recv_nonce != expect_nonce:
 print(f" INIT nonce mismatch (expected {expect_nonce.hex()[:16]}, got {recv_nonce.hex()[:16]})")
 print(" Ignoring - this INIT response is for browser, not us")
 continue # Keep waiting for OUR INIT response
 else:
 print(f" INIT nonce matches!")

 # Filter by expected command if specified
 if expect_cmd is not None and cmd != expect_cmd:
 print(f" Ignoring unexpected cmd {hex(cmd)}, waiting for {hex(expect_cmd)}")
 continue

 return cmd, data[:payload_len]

 
 def init_device(self):
 print("\n Initializing device...")
 nonce = secrets.token_bytes(8)

 # Always send INIT on broadcast CID
 self.cid = BROADCAST_CID
 self.send_message(CMD_INIT, nonce)

 # Collect full INIT response (may be multiple packets)
 msg = self.recv_message(expect_cmd=CMD_INIT, expect_nonce=nonce)
 if msg is None:
 print(" No INIT response")
 return False

 cmd, data = msg

 # INIT response must begin with nonce(8) + CID(4)
 if len(data) < 12:
 print(" INIT too short")
 return False

 recv_nonce = data[:8]
 new_cid = int.from_bytes(data[8:12], "big")

 # if recv_nonce != nonce:
 # # Device is responding on an already-initialized channel
 # # Accept the existing CID
 # print(f" INIT nonce mismatch – device already initialized with CID {new_cid:08x}")
 # self.cid = new_cid
 # return True

 self.cid = new_cid
 print(f" Device initialized, CID: {self.cid:08x}")
 return True

 def get_info(self):
 """Get authenticator info (CTAP2 GetInfo)"""
 print("\n Getting device info...")
 cbor_data = bytes([CTAP2_GET_INFO])
 self.send_message(CMD_CBOR, cbor_data)
 
 result = self.recv_message()
 if result is None:
 print(" No response from device")
 return None
 
 cmd, data = result
 
 # Check for error responses
 if cmd == CMD_CBOR and len(data) > 0:
 status = data[0]
 
 
 
 if status == 0x00: # Success
 info = cbor2.loads(data[1:])
 print("\n Device Info:")
 print(f" Versions: {info.get(1, [])}")
 print(f" Extensions: {info.get(2, [])}")
 print(f" AAGUID: {info.get(3, b'').hex()}")
 print(f" Options: {info.get(4, {})}")
 print(f" Max Message Size: {info.get(5, 'N/A')}")
 print(f" PIN Protocols: {info.get(6, [])}")
 return info
 else:
 error_name = self.error_codes.get(status, f"UNKNOWN_ERROR")
 print(f" GetInfo failed: 0x{status:02x} ({error_name})")
 
 elif cmd == CMD_BUSY: 
 print(" Device busy, retrying in 200ms...")
 time.sleep(0.2)
 return None#self.get_info()
 else:
 print(f" Unexpected response: cmd={cmd:02x}")
 return None
 
 def make_credential(self, rp, user, client_data_hash="", auth=True):
 """Create a new credential (simplified, no PIN)"""
 print(f"\n Making credential for {rp}...")
 
 if client_data_hash == "":
 client_data_hash = hash_data( hashes.sha256(), b'test_client_data' )
 
 params = {
 1: client_data_hash, # clientDataHash
 2: rp,
 3: user, # user
 4: [ # pubKeyCredParams
 {'alg': -7, 'type': 'public-key'}, # ES256
 {'alg': -257, 'type': 'public-key'}, # RS256
 ],
 6: {'credProtect': 2},
 }

 if auth:
 if self.current_pin_token is None:
 print("Need to make the PIN auth")
 return
 
 pin_auth = hmac_data( self.current_pin_token, hashes.SHA256(), client_data_hash )[:16]

 params[8] = pin_auth
 params[9] = 1

 cbor_data = bytes([CTAP2_MAKE_CREDENTIAL]) + cbor2.dumps(params)
 self.send_message(CMD_CBOR, cbor_data)
 
 print("⏳ Waiting for user presence (touch the device)...")
 result = self.recv_message()
 if result is None:
 print(" No response from device")
 return None
 
 cmd, data = result

 if cmd == CMD_CBOR and len(data) > 0 and data[0] == 0x00:
 result = cbor2.loads(data[1:])
 print("\n Credential created!")

 print(result)
 parsed = self.parse_auth_data(result[2])
 print(parsed)

 self.users[user["name"]] = {
 "id": parsed["credentialId"],
 "publicKey": parsed["publicKey"],
 "signCount": parsed["signCount"]
 }
 
 return result
 else:

 status = data[0] if len(data) > 0 else 0xFF
 error_name = self.error_codes.get(status, f"UNKNOWN_ERROR")
 print(f" MakeCredential failed: status {hex(status)} : {error_name}")
 
 return None
 
 def get_assertion(self, rp_id: str, credential, client_data_hash="", auth=True):
 """Create a new credential (simplified, no PIN)"""
 print(f"\n Get Assert credential for {rp_id}...")
 if client_data_hash == "":
 client_data_hash = hash_data( hashes.SHA256(), b'test_client_data' )
 
 params = {
 1: rp_id, # rpId (string)
 2: client_data_hash, # clientDataHash
 3: [{ # allowCredentials
 "id": credential["id"],
 "type": "public-key"
 }],
 }

 if rp_id != ".dummy" and auth:
 if self.current_pin_token is None:
 print("Need to make the PIN auth")
 return

 if self.current_pin_token is None:
 print("Need to make the PIN auth")
 return
 
 pin_auth = hmac_data( self.current_pin_token, hashes.SHA256(), client_data_hash )[:16]

 params[6] = pin_auth
 params[7] = 1

 cbor_data = bytes([CTAP2_GET_ASSERTION]) + cbor2.dumps(params)
 self.send_message(CMD_CBOR, cbor_data)
 
 print("⏳ Waiting for user presence (touch the device)...")
 result = self.recv_message(expect_cmd=CMD_CBOR)
 if result is None:
 print(" No response from device")
 return None
 
 cmd, data = result

 if cmd == CMD_CBOR and len(data) > 0 and data[0] == 0x00:
 result = cbor2.loads(data[1:])
 
 # cred = result.get(1)
 # auth_data = result.get(2)
 # signature = result.get(3)

 # if not isinstance(auth_data, bytes):
 # return None

 # signed_data = auth_data + client_data_hash
 # pubkey = self.cose_key_to_ec_public_key(credential["publicKey"])

 # try:
 # pubkey.verify(
 # signature,
 # signed_data,
 # ec.ECDSA(hashes.SHA256())
 # )
 # print("\nYou are authenticated!!")
 # except InvalidSignature:
 # print(" INVALID SIGNATURE")

 return result
 else:

 status = data[0] if len(data) > 0 else 0xFF
 error_name = self.error_codes.get(status, f"UNKNOWN_ERROR")
 print(f" MakeCredential failed: status {hex(status)} : {error_name}")
 
 return None
 
 def ping(self, message: bytes = b'Hello FIDO!'):
 """Send a ping to the device"""
 print(f"\n Pinging device with: {message.decode('utf-8', errors='ignore')}")
 self.send_message(CMD_PING, message)
 
 result = self.recv_message()
 if result is None:
 print(" No response from device")
 return False
 
 cmd, data = result
 if cmd == CMD_PING:
 print(f" Pong received: {data.decode('utf-8', errors='ignore')}")
 return True
 return False
 
 def wink(self):
 """Make the device wink (if supported)"""
 print("\n Sending wink command...")
 self.send_message(CMD_WINK, b'')
 
 result = self.recv_message()
 if result is None:
 print(" No response from device")
 return False
 
 cmd, data = result
 if cmd == CMD_WINK:
 print(" Device winked!")
 return True
 print(" Wink not supported or failed")
 return False

 def get_retries(self):
 
 params = {
 1: 1, 
 2: 1
 }
 
 cbor_data = bytes([CTAP2_CLIENT_PIN]) + cbor2.dumps(params)
 self.send_message(CMD_CBOR, cbor_data)
 
 print("⏳ Waiting for user presence (touch the device)...")
 result = self.recv_message()
 if result is None:
 print(" No response from device")
 return None
 
 cmd, data = result

 if cmd == CMD_CBOR and len(data) > 0 and data[0] == 0x00:
 result = cbor2.loads(data[1:])

 print(result)
 
 return result
 else:
 status = data[0] if len(data) > 0 else 0xFF
 error_name = self.error_codes.get(status, f"UNKNOWN_ERROR")
 print(f" Failed: status {hex(status)} : {error_name}")
 
 return None

 def reset_token(self):
 
 cbor_data = bytes([CTAP2_RESET])
 self.send_message(CMD_CBOR, cbor_data)
 
 print("⏳ Waiting for user presence (touch the device)...")
 result = self.recv_message()
 if result is None:
 print(" No response from device")
 return None
 
 cmd, data = result

 if cmd == CMD_CBOR and len(data) > 0 and data[0] == 0x00:

 print(result)
 print("RESET Sucessfully!!")
 return result
 else:
 status = data[0] if len(data) > 0 else 0xFF
 error_name = self.error_codes.get(status, f"UNKNOWN_ERROR")
 print(f" Failed: status {hex(status)} : {error_name}")
 
 return None
 
 def get_creds_metadata(self):
 
 if not self.current_pin_token:
 print(" No PIN token available")
 return None
 
 sub_command_byte = bytes([0x01]) # getCredsMetadata subCommand
 
 pin_uv_auth_param = hmac_data( self.current_pin_token, hashes.SHA256(), sub_command_byte )[:16] # Just 0x01!
 
 params = {
 1: 0x01, 
 3: 1, # pinUvAuthProtocol
 4: pin_uv_auth_param,
 }
 
 cbor_data = bytes([CTAP2_CREDENTIAL_MANAGEMENT_PREVIEW]) + cbor2.dumps(params)
 
 self.send_message(CMD_CBOR, cbor_data)
 
 print("⏳ Touch the device...")
 result = self.recv_message()
 
 if result is None:
 return None
 
 cmd, data = result

 if cmd == CMD_CBOR and len(data) > 0:
 if data[0] == 0x00:
 result = cbor2.loads(data[1:])
 print("\n Credentials metadata:")
 if 1 in result:
 print(f" Existing credentials: {result[1]}")
 if 2 in result:
 print(f" Max remaining: {result[2]}")
 if 3 in result:
 print(f" Additional info: {result[3]}")
 print(f"\n Raw response: {result}")
 return result
 else:
 print(f" Failed: status 0x{data[0]:x}")
 if data[0] == 0x33:
 print(" CTAP2_ERR_PIN_AUTH_INVALID")
 elif data[0] == 0x2E:
 print(" CTAP2_ERR_NO_CREDENTIALS")
 return None
 
 return None

 def enumerate_rps_begin(self):
 """
 Start enumerating Relying Parties (step 1 of getting credentials)
 SubCommand 0x02
 """
 if not self.current_pin_token:
 print(" No PIN token available")
 return None
 
 # Authenticate over just the subCommand byte (0x02)
 sub_command_byte = bytes([0x02])
 
 pin_uv_auth_param = hmac_data( self.current_pin_token, hashes.SHA256(), sub_command_byte )[:16]
 
 params = {
 1: 0x02, # subCommand: enumerateRPsBegin
 3: 1, # pinUvAuthProtocol
 4: pin_uv_auth_param,
 }
 
 cbor_data = bytes([CTAP2_CREDENTIAL_MANAGEMENT_PREVIEW]) + cbor2.dumps(params)
 self.send_message(CMD_CBOR, cbor_data)
 
 print("⏳ Enumerating RPs...")
 result = self.recv_message()
 
 if result is None:
 return None
 
 cmd, data = result

 if cmd == CMD_CBOR and len(data) > 0:
 if data[0] == 0x00:
 result = cbor2.loads(data[1:])
 print("\n First RP found:")
 
 if 3 in result: # rp
 rp = result[3]
 print(f" RP ID: {rp.get('id', 'N/A')}")
 print(f" RP Name: {rp.get('name', 'N/A')}")
 
 if 4 in result: # rpIDHash
 rp_id_hash = result[4]
 print(f" RP ID Hash: {rp_id_hash.hex()}")
 # Store this for enumerating credentials
 self.current_rp_id_hash = rp_id_hash
 
 if 5 in result: # totalRPs
 print(f" Total RPs: {result[5]}")
 
 print(f"\n Raw response: {result}")
 return result
 else:
 print(f" Failed: status 0x{data[0]:x}")
 if data[0] == 0x2E:
 print(" CTAP2_ERR_NO_CREDENTIALS - No credentials stored")
 return None
 
 return None

 def enumerate_credentials_begin(self, rp_id_hash):
 
 if not self.current_pin_token:
 print(" No PIN token available")
 return None
 
 # Build subCommandParams
 sub_command_params = {
 1: rp_id_hash # rpIDHash
 }
 
 sub_command_params_cbor = cbor2.dumps(sub_command_params)
 
 # Authenticate over: subCommand byte (0x04) + serialized params
 message = bytes([0x04]) + sub_command_params_cbor
 
 pin_uv_auth_param = hmac_data( self.current_pin_token, hashes.SHA256(), message )[:16]
 
 params = {
 1: 0x04, # subCommand: enumerateCredentialsBegin
 2: sub_command_params, # subCommandParams
 3: 1, # pinUvAuthProtocol
 4: pin_uv_auth_param,
 }
 
 cbor_data = bytes([CTAP2_CREDENTIAL_MANAGEMENT_PREVIEW]) + cbor2.dumps(params)
 
 self.send_message(CMD_CBOR, cbor_data)
 
 print("⏳ Enumerating credentials...")
 result = self.recv_message()
 
 if result is None:
 return None
 
 cmd, data = result

 if cmd == CMD_CBOR and len(data) > 0:
 if data[0] == 0x00:
 result = cbor2.loads(data[1:])
 print("\n First credential found:")
 
 if 6 in result: # user
 user = result[6]
 print(f" User ID: {user.get('id', b'').hex()}")
 print(f" User Name: {user.get('name', 'N/A')}")
 print(f" Display Name: {user.get('displayName', 'N/A')}")
 
 if 7 in result: # credentialID
 cred_id = result[7]
 print(f" Credential ID: {cred_id.get('id', b'').hex()}")
 print(f" Type: {cred_id.get('type', 'N/A')}")
 
 if 8 in result: # publicKey
 public_key = result[8]
 print(f" Public Key (COSE): {public_key}")
 # Parse the COSE key
 if isinstance(public_key, dict):
 if 1 in public_key:
 print(f" Key Type: {public_key[1]}")
 if 3 in public_key:
 print(f" Algorithm: {public_key[3]}")
 if -2 in public_key:
 print(f" x coordinate: {public_key[-2].hex()}")
 if -3 in public_key:
 print(f" y coordinate: {public_key[-3].hex()}")
 
 if 9 in result: # totalCredentials
 print(f" Total Credentials: {result[9]}")
 
 if 10 in result: # credProtect
 print(f" Cred Protect: {result[10]}")
 
 if 11 in result: # largeBlobKey
 print(f" Large Blob Key: {result[11].hex()}")
 
 print(f"\n Raw response: {result}")
 return result
 else:
 print(f" Failed: status 0x{data[0]:x}")
 return None
 
 return None

 def get_all_credentials(self):
 """
 Complete workflow to get all credentials with public keys
 """
 print(" Getting all credentials...")
 print("=" * 50)
 
 # Step 1: Get metadata
 print("\n1⃣ Getting credentials metadata...")
 metadata = self.get_creds_metadata()
 if not metadata:
 return None
 
 # Step 2: Enumerate RPs
 print("\n2⃣ Enumerating Relying Parties...")
 rp_info = self.enumerate_rps_begin()
 if not rp_info:
 return None
 
 # Step 3: Enumerate credentials for the RP
 if hasattr(self, 'current_rp_id_hash'):
 print("\n3⃣ Enumerating credentials for RP...")
 cred_info = self.enumerate_credentials_begin(self.current_rp_id_hash)
 return cred_info
 else:
 print(" No RP ID hash available")
 return None
 
 def get_key_agreement(self):
 
 params = {
 1: 1, 
 2: 2
 }
 
 cbor_data = bytes([CTAP2_CLIENT_PIN]) + cbor2.dumps(params)
 self.send_message(CMD_CBOR, cbor_data)
 
 print("⏳ Waiting for user presence (touch the device)...")
 result = self.recv_message()
 if result is None:
 print(" No response from device")
 return None
 
 cmd, data = result

 if cmd == CMD_CBOR and len(data) > 0 and data[0] == 0x00:
 result = cbor2.loads(data[1:])

 print(result)
 public = result.get(0x01)

 token_x = public.get(-2)
 token_y = public.get(-3)

 token_x_int = int.from_bytes(token_x, "big")
 token_y_int = int.from_bytes(token_y, "big")

 tokens_pub_numbers = ec.EllipticCurvePublicNumbers(token_x_int, token_y_int, ec.SECP256R1())
 
 self.tokens_pub = tokens_pub_numbers.public_key(default_backend())
 print("\nStored the tokens public diffie helman!!")
 return result
 else:
 status = data[0] if len(data) > 0 else 0xFF
 error_name = self.error_codes.get(status, f"UNKNOWN_ERROR")
 print(f" Failed: status {hex(status)} : {error_name}")
 
 return None
 
 def get_pin_token(self, guess):
 priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
 pub = priv.public_key()
 pub_numbers = pub.public_numbers()
 x_int = pub_numbers.x
 y_int = pub_numbers.y

 x_bytes = x_int.to_bytes(32, byteorder='big')
 y_bytes = y_int.to_bytes(32, byteorder='big')


 if self.tokens_pub is None:
 print("Do the key agreement")
 return

 shared = priv.exchange(ec.ECDH(), self.tokens_pub)
 shared_key = hash_data( hashes.SHA256(), shared )

 pin_hash_prefix = hash_data( hashes.SHA256(), guess )[:16]
 
 cipher = Cipher(algorithms.AES(shared_key), modes.ECB(), backend=default_backend())

 encryptor = cipher.encryptor()
 enc_pin_blob = encryptor.update(pin_hash_prefix) + encryptor.finalize()

 params = {
 1: 1, 
 2: 5,
 3: 
 {
 1: 2, 
 3: -25,
 -1: 1,
 -2: x_bytes, 
 -3: y_bytes,
 },
 6: enc_pin_blob
 }
 
 cbor_data = bytes([CTAP2_CLIENT_PIN]) + cbor2.dumps(params)
 self.send_message(CMD_CBOR, cbor_data)
 print("\nSent our Public key and the ciphered pin hash with the SHARED KEY!!!\n")
 # print("⏳ Waiting for user presence (touch the device)...")
 result = self.recv_message()
 if result is None:
 print(" No response from device")
 return None
 
 cmd, data = result

 if cmd == CMD_CBOR and len(data) > 0 and data[0] == 0x00:

 print("\nYou guessed the PIN!!\n")
 result = cbor2.loads(data[1:])
 print(result)
 
 pin_token_enc = result.get(2)
 zero_iv = b"\x00" * 16

 cipher = Cipher(algorithms.AES(shared_key), modes.CBC(zero_iv), backend=default_backend())
 decryptor = cipher.decryptor()
 self.current_pin_token = decryptor.update(pin_token_enc) + decryptor.finalize()
 print("\nStored the PIN TOKEN that was ciphered with the SHARED KEY!!!\n")
 return result
 else:
 status = data[0] if len(data) > 0 else 0xFF
 error_name = self.error_codes.get(status, f"UNKNOWN_ERROR")
 print(f" Failed: status {hex(status)} : {error_name}")
 
 return None
