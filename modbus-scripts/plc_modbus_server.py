#!/usr/bin/env python3
"""
Distribution Substation PLC Simulator - Modbus TCP Server

Simulates a 69kV/13.8kV distribution substation with:
- Circuit breaker controls (coils)
- Capacitor bank switching (coils)
- Voltage and current monitoring (holding registers)
- Equipment status indicators (discrete inputs)
- Power quality measurements (input registers)

Listens on 0.0.0.0:502 for Modbus/TCP connections
"""
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.device import ModbusDeviceIdentification
import logging
from datetime import datetime

# Enable logging for forensic analysis
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
log = logging.getLogger()

def initialize_substation_datastore():
    """
    Initialize Modbus datastore with realistic substation values.

    COILS (Read/Write Binary Outputs) - Circuit Breaker and Switching Controls:
      0-9:   Distribution Feeder Circuit Breakers (0=Open, 1=Closed)
      10-14: Capacitor Bank Switches (0=Offline, 1=Online)
      15-19: Transformer Cooling Pump Controls
      20-29: Disconnect Switches
      99:    Emergency Main Breaker Trip (CRITICAL SAFETY SYSTEM)

    DISCRETE INPUTS (Read-Only Status Indicators):
      0-9:   Circuit Breaker Position Feedback (0=Open, 1=Closed)
      10-14: Capacitor Bank Status
      15-19: Overload Alarm Indicators
      20-29: Equipment Fault Indicators

    HOLDING REGISTERS (Read/Write Configuration):
      0-4:   Feeder Voltage Setpoints (in 0.1V, e.g., 138000 = 13.8kV)
      5-9:   Current Limit Thresholds (in Amps)
      10-14: Capacitor Bank Switching Thresholds
      15-19: Transformer Tap Position Settings

    INPUT REGISTERS (Read-Only Measurements):
      0-4:   Real-time Feeder Voltages (Phase A-B-C + Neutral)
      5-9:   Real-time Feeder Currents
      10-14: Active Power (kW)
      15-19: Reactive Power (kVAR)
      20-24: Power Factor (x100, e.g., 95 = 0.95 PF)
    """

    # COILS: Initialize circuit breakers in OPEN state (safe default)
    initial_coil_states = [0] * 100
    initial_coil_states[0] = 1  # Feeder 1 breaker CLOSED (normal operation)

    coils = ModbusSequentialDataBlock(0, initial_coil_states)

    # DISCRETE INPUTS: Status feedback matching coil states
    initial_discrete_inputs = [0] * 100
    initial_discrete_inputs[0] = 1  # Feeder 1 breaker position feedback

    discrete_inputs = ModbusSequentialDataBlock(0, initial_discrete_inputs)

    # HOLDING REGISTERS: Configuration values for substation equipment
    initial_holding_registers = [0] * 100
    # Voltage setpoints (addresses 0-4): 13.8kV = 138000 (in 0.1V units)
    initial_holding_registers[0:5] = [138000, 138000, 138000, 138000, 0]
    # Current limits (addresses 5-9): 600A typical distribution feeder limit
    initial_holding_registers[5:10] = [600, 600, 600, 600, 0]

    holding_registers = ModbusSequentialDataBlock(0, initial_holding_registers)

    # INPUT REGISTERS: Real-time measurements (simulated normal operating values)
    initial_input_registers = [0] * 100
    # Feeder voltages (addresses 0-4): Phase A, B, C at nominal 13.8kV
    initial_input_registers[0:3] = [13800, 13820, 13790]  # Slight variations realistic
    # Feeder currents (addresses 5-9): Moderate load ~300A
    initial_input_registers[5:8] = [305, 298, 310]
    # Active power (addresses 10-14): ~7.2 MW total (3 phases)
    initial_input_registers[10:13] = [2400, 2350, 2410]  # kW per phase
    # Power factor (addresses 20-24): Good PF ~0.95
    initial_input_registers[20:23] = [95, 96, 94]

    input_registers = ModbusSequentialDataBlock(0, initial_input_registers)

    # Create Modbus slave context
    substation_controller = ModbusSlaveContext(
        di=discrete_inputs,
        co=coils,
        hr=holding_registers,
        ir=input_registers
    )

    return substation_controller

def run_substation_server():
    """Start the distribution substation Modbus TCP server."""

    # Initialize substation datastore
    substation_controller = initialize_substation_datastore()
    server_context = ModbusServerContext(slaves=substation_controller, single=True)

    # Configure server identity (visible in Modbus diagnostics)
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'Capstone Energy Systems'
    identity.ProductCode = 'DIST-SUB-PLC-01'
    identity.VendorUrl = 'https://github.com/capstone-project'
    identity.ProductName = 'Distribution Substation Controller'
    identity.ModelName = '69kV/13.8kV Substation PLC Simulator'
    identity.MajorMinorRevision = '2.1.0'

    # Display startup banner
    print("=" * 70)
    print("  DISTRIBUTION SUBSTATION PLC SIMULATOR")
    print("  69kV/13.8kV Distribution Substation Control System")
    print("=" * 70)
    print(f"[*] Server Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[*] Protocol: Modbus/TCP")
    print("[*] Listening on: 0.0.0.0:502")
    print("[*] Simulated Equipment:")
    print("    - 10x Distribution Feeder Circuit Breakers (Coils 0-9)")
    print("    - 5x Capacitor Bank Switches (Coils 10-14)")
    print("    - Emergency Main Breaker Trip (Coil 99)")
    print("    - Real-time Voltage/Current Monitoring")
    print("    - Power Quality Measurements")
    print("[*] Initial State: Feeder 1 ENERGIZED, All others OFFLINE")
    print("[*] Logging: ENABLED (all operations will be logged)")
    print("=" * 70)
    print("[*] Press Ctrl+C to stop server")
    print()

    # Start Modbus TCP server
    StartTcpServer(
        context=server_context,
        identity=identity,
        address=("0.0.0.0", 502)
    )

if __name__ == "__main__":
    try:
        run_substation_server()
    except KeyboardInterrupt:
        print("\n[!] Server shutdown requested")
        print("[*] Shutting down substation controller...")
        print("[*] Server stopped")
    except Exception as error:
        log.error(f"Server error: {error}")
        raise
