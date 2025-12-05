#!/usr/bin/env python3
"""
Distribution Substation HMI - Normal Operations
Simulates normal operator interaction with substation PLC
Performs routine monitoring and feeder breaker control
"""
from pymodbus.client import ModbusTcpClient
import time
import sys

PLC_IP = "192.168.20.20"
PLC_PORT = 502

def main():
    print("=" * 60)
    print("  SUBSTATION HMI - NORMAL OPERATIONS")
    print("=" * 60)
    print(f"[*] Connecting to PLC at {PLC_IP}:{PLC_PORT}")

    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    if not client.connect():
        print("[!] Failed to connect to PLC")
        sys.exit(1)

    print("[+] Connected to substation controller")
    print()

    # Normal operation: Read feeder voltages (input registers)
    print("[*] Reading feeder voltages (Phase A, B, C)...")
    result = client.read_input_registers(address=0, count=3, slave=1)
    if not result.isError():
        voltages = result.registers
        print(f"[+] Phase A: {voltages[0]} V")
        print(f"[+] Phase B: {voltages[1]} V")
        print(f"[+] Phase C: {voltages[2]} V")
    else:
        print(f"[!] Error reading voltages: {result}")

    # Normal operation: Read feeder currents (input registers)
    print("\n[*] Reading feeder currents...")
    result = client.read_input_registers(address=5, count=3, slave=1)
    if not result.isError():
        currents = result.registers
        print(f"[+] Phase A: {currents[0]} A")
        print(f"[+] Phase B: {currents[1]} A")
        print(f"[+] Phase C: {currents[2]} A")
    else:
        print(f"[!] Error reading currents: {result}")

    # Normal operation: Check breaker positions (coils)
    print("\n[*] Reading distribution feeder breaker states (Feeders 1-5)...")
    result = client.read_coils(address=0, count=5, slave=1)
    if not result.isError():
        breaker_states = result.bits[:5]
        for i, state in enumerate(breaker_states):
            status = "CLOSED" if state else "OPEN"
            print(f"[+] Feeder {i+1} Breaker: {status}")
    else:
        print(f"[!] Error reading breakers: {result}")

    # Normal operation: Energize Feeder 2 (routine switching operation)
    print("\n[*] Operator Action: Energizing Feeder 2 breaker...")
    result = client.write_coil(address=1, value=True, slave=1)
    if not result.isError():
        print("[+] Feeder 2 breaker CLOSED successfully")
    else:
        print(f"[!] Error closing breaker: {result}")

    time.sleep(2)

    # Verify breaker operation
    print("[*] Verifying Feeder 2 breaker position...")
    result = client.read_coils(address=1, count=1, slave=1)
    if not result.isError():
        breaker_state = result.bits[0]
        status = "CLOSED (energized)" if breaker_state else "OPEN (de-energized)"
        print(f"[+] Feeder 2 status: {status}")

    time.sleep(2)

    # Normal operation: De-energize Feeder 2 (end of switching operation)
    print("\n[*] Operator Action: De-energizing Feeder 2 breaker...")
    result = client.write_coil(address=1, value=False, slave=1)
    if not result.isError():
        print("[+] Feeder 2 breaker OPENED successfully")
    else:
        print(f"[!] Error opening breaker: {result}")

    # Final status check
    print("\n[*] Final system status check...")
    result = client.read_coils(address=0, count=5, slave=1)
    if not result.isError():
        breaker_states = result.bits[:5]
        print("[+] Breaker positions:")
        for i, state in enumerate(breaker_states):
            status = "CLOSED" if state else "OPEN"
            print(f"    Feeder {i+1}: {status}")

    client.close()
    print("\n" + "=" * 60)
    print("  NORMAL OPERATIONS COMPLETED")
    print("=" * 60)

if __name__ == "__main__":
    main()
