# STM32 AUTOSAR SecOC & FVM Simulation

A dual-node CAN bus security demonstration simulating AUTOSAR SecOC (Secure Onboard Communication) and FVM (Freshness Value Manager) on two STM32F302R8 boards using external MCP2515 controllers.

## Features

- **AUTOSAR SecOC Specification:** Uses AES-128 CMAC (RFC 4493) to generate 32-bit truncated MACs over PDU payload and Freshness Values.
- **64-bit Freshness Value Manager (FVM):** Monotonic counter architecture (Trip, Reset, Message counter) protecting against replay attacks.
- **Acceptance Window Check:** Verification window (Delta = 16) rejecting out-of-order or stale frames.
- **Replay Attack Injection:** On-board user button (PC13) on Node A triggers a deliberate counter rollback to demonstrate detection on Node B.
- **FreeRTOS Integration:** Interrupt-driven reception (EXTI) and queue-based task processing on CMSIS_V2.

## CAN Frame Layout

```text
+-----------+-------------+---------------+--------------+--------------------+
| Speed     | Throttle %  | Engine Status | Truncated FV | Truncated MAC      |
| 1 Byte    | 1 Byte      | 1 Byte        | 1 Byte (LSB) | 4 Bytes (AES-CMAC) |
+-----------+-------------+---------------+--------------+--------------------+
|<----------------------- CAN Payload: 8 Bytes ------------------------------>|
```

### Authentication Data Buffer (13 Bytes)

```text
[ Data ID (2B: 0x10A2) ] + [ Payload (3B) ] + [ Full Freshness Value (8B) ]
```

## Hardware Wiring

Both nodes use the Nucleo-F302R8 Morpho connectors:

| MCP2515 | STM32F302R8 | Morpho Pin | Notes |
| :--- | :--- | :--- | :--- |
| VCC | 5V | CN6 Pin 5 | 5V Supply |
| GND | GND | CN7 Pin 20 | Common Ground |
| CS | PB6 | CN10 Pin 17 | GPIO Output |
| SO (MISO)| PA6 | CN10 Pin 13 | SPI1 MISO |
| SI (MOSI)| PA7 | CN10 Pin 15 | SPI1 MOSI |
| SCK | PA5 | CN10 Pin 11 | SPI1 SCK (4 MHz) |
| INT | PB0 | CN7 Pin 34 | EXTI0 (Node B only) |
| USER BTN | PC13 | On-board | Replay attack trigger (Node A) |
| LD2 | PB13 | On-board | Green LED toggle on valid PDU (Node B) |

Connect `CAN_H` to `CAN_H` and `CAN_L` to `CAN_L` between both MCP2515 modules. Ensure termination jumpers (120 Ohm) are closed.

## Project Structure

```text
.
├── .gitignore
├── README.md
├── NodeA_main.c
├── NodeB_main.c
├── dashboard.py
├── include/
│   ├── aes128_cmac.h
│   ├── mcp2515.h
│   └── secoc.h
└── src/
    ├── aes128_cmac.c
    ├── mcp2515.c
    └── secoc.c
```

## Running the Project

### 1. Flashing Firmware (STM32CubeIDE)
- Create two STM32F302R8 projects with FreeRTOS CMSIS_V2 enabled.
- Add `include/` to include paths and `src/` to source paths.
- Flash `NodeA_main.c` to Node A (Sender).
- Flash `NodeB_main.c` to Node B (Receiver).

### 2. Live Monitoring (PC)

```bash
pip install pyserial
python dashboard.py --tx COM3 --rx COM4
```

### 3. Testing Replay Attack
- Press the blue button (**PC13**) on Node A.
- Node A transmits a packet with counter rolled back by 10.
- Node B rejects the frame with `REPLAY DETECTED! PDU_DROPPED`.
