#!/usr/bin/env python3
import sys
import time
import threading
import argparse
import re

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_BG_RED = "\033[41m"
COLOR_BG_GREEN = "\033[42m"

class SecOCDashboard:
    def __init__(self, port_tx, port_rx, baudrate=115200):
        self.port_tx = port_tx
        self.port_rx = port_rx
        self.baudrate = baudrate
        self.running = True

        self.stats = {
            "tx_count": 0,
            "rx_accepted": 0,
            "rx_replay": 0,
            "rx_invalid_mac": 0,
            "attack_injected": 0,
            "last_speed": 0,
            "last_fv_tx": 0,
            "last_fv_rx": 0,
            "last_mac": "0x00000000"
        }
        self.lock = threading.Lock()

    def print_banner(self):
        print(f"{COLOR_CYAN}{COLOR_BOLD}")
        print("=" * 80)
        print("   AUTOSAR SecOC & FVM Dual-Node Live Security Monitor")
        print("   Node A (Sender) <---> CAN Bus (500k) <---> Node B (Receiver)")
        print("=" * 80)
        print(f"{COLOR_RESET}")
        print(f"[{COLOR_BLUE}CONFIG{COLOR_RESET}] TX Port (Node A): {self.port_tx}")
        print(f"[{COLOR_BLUE}CONFIG{COLOR_RESET}] RX Port (Node B): {self.port_rx}")
        print(f"[{COLOR_BLUE}CONFIG{COLOR_RESET}] Baudrate: {self.baudrate} 8N1")
        print("-" * 80)

    def tx_listener(self):
        try:
            ser_tx = serial.Serial(self.port_tx, self.baudrate, timeout=1)
        except Exception as e:
            print(f"{COLOR_RED}[TX PORT ERROR] Failed to open {self.port_tx}: {e}{COLOR_RESET}")
            return

        tx_regex = re.compile(r"\[TX\]\s+PDU:(0x[0-9A-Fa-f]+)\s+\|\s+CNT:(\d+)\s+\|\s+DATA:(\d+)\s+km/h\s+\|\s+MAC:(0x[0-9A-Fa-f]+)")

        while self.running:
            try:
                raw = ser_tx.readline()
                if not raw:
                    continue
                line = raw.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue

                with self.lock:
                    if "[TX_ATTACK]" in line:
                        self.stats["attack_injected"] += 1
                        ts = time.strftime("%H:%M:%S")
                        print(f"[{ts}] {COLOR_BG_RED}{COLOR_BOLD} [TX ATTACK INJECTED] {COLOR_RESET} {COLOR_RED}Node A sent rolled-back Freshness Counter!{COLOR_RESET}")
                    else:
                        match = tx_regex.search(line)
                        if match:
                            pdu, cnt, spd, mac = match.groups()
                            self.stats["tx_count"] += 1
                            self.stats["last_speed"] = int(spd)
                            self.stats["last_fv_tx"] = int(cnt)
                            self.stats["last_mac"] = mac

                            ts = time.strftime("%H:%M:%S")
                            print(f"[{ts}] {COLOR_BLUE}[TX]{COLOR_RESET} PDU:{COLOR_BOLD}{pdu}{COLOR_RESET} | CNT:{COLOR_YELLOW}{cnt:>3}{COLOR_RESET} | DATA:{COLOR_CYAN}{spd:>3} km/h{COLOR_RESET} | MAC:{COLOR_MAGENTA}{mac}{COLOR_RESET}")
                        elif "[INFO]" in line or "[ERROR]" in line or "===" in line:
                            print(f"      {COLOR_YELLOW}[NODE A LOG]{COLOR_RESET} {line}")
            except Exception as e:
                if self.running:
                    print(f"{COLOR_RED}[TX READ EXCEPTION] {e}{COLOR_RESET}")
                break

        ser_tx.close()

    def rx_listener(self):
        try:
            ser_rx = serial.Serial(self.port_rx, self.baudrate, timeout=1)
        except Exception as e:
            print(f"{COLOR_RED}[RX PORT ERROR] Failed to open {self.port_rx}: {e}{COLOR_RESET}")
            return

        rx_accepted_regex = re.compile(r"\[RX\]\s+PDU:(0x[0-9A-Fa-f]+)\s+\|\s+FV:(\d+)\s+\(SYNC\)\s+\|\s+MAC:VALID\s+->\s+PDU_ACCEPTED")
        rx_replay_regex = re.compile(r"\[RX\]\s+PDU:(0x[0-9A-Fa-f]+)\s+\|\s+FV:(\d+)\s+\(OLD\)\s+->\s+REPLAY DETECTED!\s+PDU_DROPPED")
        rx_invalid_regex = re.compile(r"\[RX\]\s+PDU:(0x[0-9A-Fa-f]+)\s+\|\s+FV:(\d+)\s+\|\s+MAC:INVALID\s+->\s+PDU_DROPPED")

        while self.running:
            try:
                raw = ser_rx.readline()
                if not raw:
                    continue
                line = raw.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue

                with self.lock:
                    ts = time.strftime("%H:%M:%S")

                    match_acc = rx_accepted_regex.search(line)
                    if match_acc:
                        pdu, fv = match_acc.groups()
                        self.stats["rx_accepted"] += 1
                        self.stats["last_fv_rx"] = int(fv)
                        print(f"[{ts}] {COLOR_GREEN}{COLOR_BOLD}[RX ACCEPTED]{COLOR_RESET} PDU:{pdu} | FV:{COLOR_YELLOW}{fv:>3}{COLOR_RESET} (SYNC) | {COLOR_GREEN}MAC VALID -> AUTHENTICATED{COLOR_RESET}")
                        continue

                    match_rep = rx_replay_regex.search(line)
                    if match_rep:
                        pdu, fv = match_rep.groups()
                        self.stats["rx_replay"] += 1
                        print(f"[{ts}] {COLOR_BG_RED}{COLOR_BOLD}[SECURITY ALERT]{COLOR_RESET} {COLOR_RED}PDU:{pdu} | FV:{fv} (OLD) -> REPLAY ATTACK BLOCKED! PACKET DROPPED{COLOR_RESET}")
                        continue

                    match_inv = rx_invalid_regex.search(line)
                    if match_inv:
                        pdu, fv = match_inv.groups()
                        self.stats["rx_invalid_mac"] += 1
                        print(f"[{ts}] {COLOR_RED}{COLOR_BOLD}[INTEGRITY VIOLATION]{COLOR_RESET} PDU:{pdu} | FV:{fv} | {COLOR_RED}MAC INVALID -> TAMPERED PDU DROPPED{COLOR_RESET}")
                        continue

                    if "[INFO]" in line or "[ERROR]" in line or "===" in line:
                        print(f"      {COLOR_YELLOW}[NODE B LOG]{COLOR_RESET} {line}")
            except Exception as e:
                if self.running:
                    print(f"{COLOR_RED}[RX READ EXCEPTION] {e}{COLOR_RESET}")
                break

        ser_rx.close()

    def run(self):
        self.print_banner()

        t_tx = threading.Thread(target=self.tx_listener, daemon=True)
        t_rx = threading.Thread(target=self.rx_listener, daemon=True)

        t_tx.start()
        t_rx.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{COLOR_YELLOW}Stopping SecOC monitor...{COLOR_RESET}")

        t_tx.join(timeout=1.0)
        t_rx.join(timeout=1.0)

        print("\n" + "=" * 80)
        print(f"{COLOR_BOLD}SUMMARY TELEMETRY REPORT:{COLOR_RESET}")
        print(f"  Total Transmitted PDUs (Node A): {self.stats['tx_count']}")
        print(f"  Total Accepted PDUs (Node B):    {COLOR_GREEN}{self.stats['rx_accepted']}{COLOR_RESET}")
        print(f"  Replay Attacks Injected (PC13):  {self.stats['attack_injected']}")
        print(f"  Replay Attacks Blocked (Node B): {COLOR_RED}{self.stats['rx_replay']}{COLOR_RESET}")
        print(f"  Tampered/Invalid MACs Blocked:   {self.stats['rx_invalid_mac']}")
        print("=" * 80)

def list_available_ports():
    ports = serial.tools.list_ports.comports()
    if not ports:
        print("[INFO] No serial ports found on system.")
        return []
    print("\nAvailable Serial Ports:")
    for p in ports:
        print(f"  - {p.device}: {p.description} [{p.hwid}]")
    return [p.device for p in ports]

def main():
    parser = argparse.ArgumentParser(description="AUTOSAR SecOC & FVM Dual-Node Terminal Monitor")
    parser.add_argument("--tx", type=str, help="Serial port for Node A (Sender), e.g. COM3 or /dev/ttyACM0")
    parser.add_argument("--rx", type=str, help="Serial port for Node B (Receiver), e.g. COM4 or /dev/ttyACM1")
    parser.add_argument("--baud", type=int, default=115200, help="Baudrate (default: 115200)")
    parser.add_argument("--list", action="store_true", help="List available serial ports and exit")

    args = parser.parse_args()

    if not HAS_SERIAL:
        print("[ERROR] pyserial is required to run the dashboard. Install it with: pip install pyserial")
        sys.exit(1)

    if args.list:
        list_available_ports()
        sys.exit(0)

    tx_port = args.tx
    rx_port = args.rx

    if not tx_port or not rx_port:
        available = list_available_ports()
        if len(available) >= 2:
            print(f"\nAuto-assigning first two available ports:")
            tx_port = tx_port or available[0]
            rx_port = rx_port or available[1]
            print(f"  Node A (TX): {tx_port}")
            print(f"  Node B (RX): {rx_port}")
        else:
            print("\n[ERROR] Both --tx and --rx ports must be specified.")
            print("Example usage: python dashboard.py --tx COM3 --rx COM4")
            sys.exit(1)

    dash = SecOCDashboard(port_tx=tx_port, port_rx=rx_port, baudrate=args.baud)
    dash.run()

if __name__ == "__main__":
    main()
