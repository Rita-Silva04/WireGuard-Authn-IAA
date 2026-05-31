#!/usr/bin/env python3
import os
import struct
import time
import select
import errno
from ctaphid_handler import CTAPHIDHandler
import sys

class VirtualFIDO:

    def __init__(self, mode):
        self.fd = None
        self.running = False
        self.AAGUID = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.mode = mode
        self.ctaphid = CTAPHIDHandler(self.AAGUID)
        self.real_fd = None

    ## Create Device

    def create_uhid_device(self):
        print("=== Creating Virtual FIDO Device ===")

        try:
            self.fd = os.open('/dev/uhid', os.O_RDWR)
            rdesc = bytes([
                0x06, 0xD0, 0xF1,       # Usage Page (FIDO Alliance)
                0x09, 0x01,             # Usage (U2F Authenticator Device)
                0xA1, 0x01,             # Collection (Application)

                0x09, 0x20,             # Usage (Input Report Data)
                0x15, 0x00,             # Logical Minimum (0)
                0x26, 0xFF, 0x00,       # Logical Maximum (255)
                0x75, 0x08,             # Report Size (8)
                0x95, 0x40,             # Report Count (64)
                0x81, 0x02,             # Input (Data,Var,Abs)

                0x09, 0x21,             # Usage (Output Report Data)
                0x15, 0x00,             # Logical Minimum (0)
                0x26, 0xFF, 0x00,       # Logical Maximum (255)
                0x75, 0x08,             # Report Size (8)
                0x95, 0x40,             # Report Count (64)
                0x91, 0x02,             # Output (Data,Var,Abs)

                0xC0                    # End Collection
            ])

            print(f"  CTAPHID HID descriptor: {len(rdesc)} bytes")
            print(f"  Descriptor hex: {rdesc.hex()}")

            create_data = b''
            create_data += b'Yubico YubiKey\x00'.ljust(128, b'\x00')
            create_data += b'usb-0000:00:14.0-1\x00'.ljust(64, b'\x00')
            create_data += b'0001234567\x00'.ljust(64, b'\x00')
            create_data += struct.pack('<H', len(rdesc))   # rd_size (little-endian)
            create_data += struct.pack('<H', 0x0003)       # bus (USB)
            create_data += struct.pack('<I', 0x1050)       # vendor (Yubico)
            create_data += struct.pack('<I', 0x0407)       # product (YubiKey)
            create_data += struct.pack('<I', 0x0521)       # version
            create_data += struct.pack('<I', 0x0000)       # country
            create_data += rdesc
            create_data += b'\x00' * (4096 - len(rdesc))

            event_data = struct.pack('<I', 11)  # UHID_CREATE2
            event_data += create_data

            os.write(self.fd, event_data)
            time.sleep(2)

            return self.check_hidraw_device()

        except Exception as e:
            print(f"  UHID creation failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def check_hidraw_device(self):
        """Check if our device appears in hidraw"""
        for i in range(8):
            dev_path = f"/dev/hidraw{i}"
            if os.path.exists(dev_path):
                try:
                    result = os.popen(f'udevadm info {dev_path} 2>/dev/null').read()
                    if '1050:0407' in result or 'FIDO' in result or 'CTAPHID' in result:
                        print(f"  UHID device created: {dev_path}")
                        return dev_path
                except Exception:
                    pass
        print("UHID device not found in hidraw")
        return False

    ## For the proxy mode

    def find_real_fido_device(self):
        """Scan for a real FIDO HID device under /dev/hidraw*."""
        for i in range(8):
            dev_path = f"/dev/hidraw{i}"
            if os.path.exists(dev_path):
                try:
                    result = os.popen(f"udevadm info {dev_path} 2>/dev/null").read()
                    if ("FIDO" in result or "U2F" in result) and '1050:0407' not in result:
                        print(f"  Found real FIDO device: {dev_path}")
                        return dev_path
                except Exception:
                    pass
        print("  No physical FIDO device found.")
        return None

    ## For the stand alone mode

    def handle_ctaphid_command(self, hid_data: bytes):
        """Handle CTAPHID commands in standalone mode"""
        result = self.ctaphid.parse_ctaphid_packet(hid_data)

        if result is None:
            print("  Waiting for continuation packets...")
            return

        cid, cmd, data = result
        print(f"  Complete message: CID={cid:08x}, CMD={cmd:02x}, Data={len(data)} bytes")

        response_packets = self.ctaphid.handle_command(cid, cmd, data, self.real_fd)

        if response_packets is None:
            print("  No response generated")
            return

        UHID_INPUT2 = 12
        for i, packet in enumerate(response_packets):
            print(f"  <- Sending response packet {i+1}/{len(response_packets)}: {packet.hex()[:32]}...")
            event = struct.pack("<IH", UHID_INPUT2, len(packet)) + packet
            os.write(self.fd, event)

        print(f"  Sent {len(response_packets)} response packet(s)")

    ## Start

    def parse_uhid_output(self, payload):
        UHID_DATA_MAX = 4096

        if len(payload) >= UHID_DATA_MAX + 3:
            size = struct.unpack_from("<H", payload, UHID_DATA_MAX)[0]
            rtype = payload[UHID_DATA_MAX + 2]
            hid_data = payload[0:size]
            return hid_data, size, rtype

        if len(payload) >= 2:
            return payload, len(payload), 0

        return b"", 0, 0

    def read_loop(self):
        """Main UHID read loop (fixed to parse events per kernel ABI)."""
        self.running = True
        UHID_OUTPUT = 6
        print("=== Virtual Device is running ===")
        print("Press Ctrl+C to stop...")

        while self.running:
            try:
                r, _, _ = select.select([self.fd], [], [], 0.1)
                if not r:
                    continue

                data = os.read(self.fd, 8192)
                if len(data) < 4:
                    return None, None
                ev_type = struct.unpack_from("<I", data, 0)[0]
                payload = data[4:]

                if ev_type is None:
                    continue

                print("=" * 60)
                print(f"Event type: {ev_type}")

                if ev_type == UHID_OUTPUT:
                    hid_data, output_size, rtype = self.parse_uhid_output(payload)
                    print(f"  Output size: {output_size}, type: {rtype}")
                    print(f"  HID raw data: {hid_data.hex()}")

                    if self.mode == "real":
                        self.real_fd = None
                        pass

                    elif self.mode == "mitm":
                        print("  MiTM mode")
                        if self.real_fd is None:
                            dev_path = self.find_real_fido_device()
                            self.real_fd = os.open(dev_path, os.O_RDWR | os.O_NONBLOCK)
                        self.handle_ctaphid_command(hid_data)

                    else:
                        print("  Stand alone mode")
                        self.handle_ctaphid_command(hid_data)

                else:
                    pass

                print("-" * 60)

            except BlockingIOError:
                pass
            except Exception as e:
                if self.running:
                    print(f"Read loop error: {e}")
                    import traceback
                    traceback.print_exc()
                break

    def start(self):
        """Start the virtual FIDO device in a single thread (no background thread)."""
        device = self.create_uhid_device()
        if device is not None:
            self.running = True
            try:
                self.read_loop()
            except KeyboardInterrupt:
                print("\nStopping ...")
                self.stop()
        else:
            print("Failed to create virtual device.")

    def stop(self):
        """Stop the virtual FIDO device"""
        self.running = False

        if self.fd:
            try:
                destroy_data = struct.pack('I', 1)  # UHID_DESTROY
                os.write(self.fd, destroy_data)
                os.close(self.fd)
                print("UHID device destroyed")
            except Exception:
                pass


def main():
    mode = "virtual"

    if len(sys.argv) == 2:
        if sys.argv[1] == "-r":
            mode = "real"
        elif sys.argv[1] == "-m":
            mode = "mitm"

    emulator = VirtualFIDO(mode=mode)

    try:
        emulator.start()
    except Exception:
        import traceback
        traceback.print_exc()
    finally:
        emulator.stop()


if __name__ == "__main__":
    main()
