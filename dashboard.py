#!/usr/bin/env python3
import sys
import time
import threading
import argparse
import re
import random

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

class SecOCDashboardApp:
    def __init__(self, root, port_tx=None, port_rx=None, baudrate=115200):
        self.root = root
        self.root.title("AUTOSAR SecOC & FVM Security Dashboard")
        self.root.geometry("1050x750")
        self.root.minsize(950, 680)
        self.root.configure(bg="#121317")

        self.port_tx_param = port_tx
        self.port_rx_param = port_rx
        self.baudrate = baudrate

        self.ser_tx = None
        self.ser_rx = None
        self.is_connected = False
        self.is_sim_mode = False
        self.running = True

        self.stats = {
            "tx_count": 0,
            "rx_accepted": 0,
            "rx_replay": 0,
            "rx_invalid": 0,
            "attack_injected": 0
        }

        self.sim_cnt = 1
        self.sim_speed = 40
        self.sim_attack_pending = False

        self._create_styles()
        self._build_ui()
        self.refresh_ports()

        if port_tx and port_rx:
            self.tx_combo.set(port_tx)
            self.rx_combo.set(port_rx)
            self.toggle_connection()

    def _create_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("TFrame", background="#121317")
        self.style.configure("Card.TFrame", background="#1A1D24", relief="flat")
        self.style.configure("Header.TLabel", background="#121317", foreground="#FFFFFF", font=("Segoe UI", 16, "bold"))
        self.style.configure("SubHeader.TLabel", background="#121317", foreground="#8E95A5", font=("Segoe UI", 9))
        self.style.configure("CardTitle.TLabel", background="#1A1D24", foreground="#00D2FF", font=("Segoe UI", 12, "bold"))
        self.style.configure("CardSub.TLabel", background="#1A1D24", foreground="#8E95A5", font=("Segoe UI", 9))
        self.style.configure("MetricVal.TLabel", background="#1A1D24", foreground="#FFFFFF", font=("Segoe UI", 18, "bold"))
        self.style.configure("MetricLbl.TLabel", background="#1A1D24", foreground="#8E95A5", font=("Segoe UI", 9))

    def _build_ui(self):
        top_bar = tk.Frame(self.root, bg="#121317", padx=20, pady=12)
        top_bar.pack(fill=tk.X)

        title_frame = tk.Frame(top_bar, bg="#121317")
        title_frame.pack(side=tk.LEFT)
        tk.Label(title_frame, text="AUTOSAR SecOC & FVM Dashboard", font=("Segoe UI", 16, "bold"), fg="#FFFFFF", bg="#121317").pack(anchor="w")
        tk.Label(title_frame, text="Dual-Node CAN Security Monitor (STM32F302R8 + MCP2515)", font=("Segoe UI", 9), fg="#00D2FF", bg="#121317").pack(anchor="w")

        conn_frame = tk.Frame(top_bar, bg="#1A1D24", padx=12, pady=6, relief="flat", highlightbackground="#2A2F3D", highlightthickness=1)
        conn_frame.pack(side=tk.RIGHT)

        tk.Label(conn_frame, text="TX (Node A):", font=("Segoe UI", 9), fg="#A0A8B8", bg="#1A1D24").grid(row=0, column=0, padx=4)
        self.tx_combo = ttk.Combobox(conn_frame, width=10, state="readonly")
        self.tx_combo.grid(row=0, column=1, padx=4)

        tk.Label(conn_frame, text="RX (Node B):", font=("Segoe UI", 9), fg="#A0A8B8", bg="#1A1D24").grid(row=0, column=2, padx=4)
        self.rx_combo = ttk.Combobox(conn_frame, width=10, state="readonly")
        self.rx_combo.grid(row=0, column=3, padx=4)

        self.btn_refresh = tk.Button(conn_frame, text="↻", font=("Segoe UI", 10, "bold"), bg="#2A2F3D", fg="#FFFFFF", activebackground="#3B4254", relief="flat", width=3, command=self.refresh_ports)
        self.btn_refresh.grid(row=0, column=4, padx=4)

        self.btn_connect = tk.Button(conn_frame, text="Connect", font=("Segoe UI", 9, "bold"), bg="#0080FF", fg="#FFFFFF", activebackground="#0066CC", relief="flat", padx=10, pady=2, command=self.toggle_connection)
        self.btn_connect.grid(row=0, column=5, padx=6)

        self.btn_sim = tk.Button(conn_frame, text="Demo Mode", font=("Segoe UI", 9, "bold"), bg="#3A4050", fg="#FFFFFF", activebackground="#4B5368", relief="flat", padx=8, pady=2, command=self.toggle_sim_mode)
        self.btn_sim.grid(row=0, column=6, padx=4)

        stats_bar = tk.Frame(self.root, bg="#121317", padx=20, pady=6)
        stats_bar.pack(fill=tk.X)

        self.lbl_stat_tx = self._create_stat_box(stats_bar, "TOTAL TRANSMITTED", "0", "#00D2FF")
        self.lbl_stat_rx = self._create_stat_box(stats_bar, "PDUS ACCEPTED", "0", "#00FF88")
        self.lbl_stat_replay = self._create_stat_box(stats_bar, "REPLAYS BLOCKED", "0", "#FF3B5C")
        self.lbl_stat_mac = self._create_stat_box(stats_bar, "INVALID MACS", "0", "#FFAA00")

        main_panes = tk.Frame(self.root, bg="#121317", padx=20, pady=10)
        main_panes.pack(fill=tk.BOTH, expand=True)

        pane_tx = tk.Frame(main_panes, bg="#1A1D24", padx=16, pady=14, highlightbackground="#2A2F3D", highlightthickness=1)
        pane_tx.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        tk.Label(pane_tx, text="NODE A (SENDER / TRANSMITTER)", font=("Segoe UI", 11, "bold"), fg="#00D2FF", bg="#1A1D24").pack(anchor="w")
        tk.Label(pane_tx, text="STM32F302R8 -> MCP2515 (CAN ID: 0x120)", font=("Segoe UI", 8), fg="#727B8E", bg="#1A1D24").pack(anchor="w", pady=(0, 12))

        tx_grid = tk.Frame(pane_tx, bg="#1A1D24")
        tx_grid.pack(fill=tk.X, pady=4)

        self.lbl_speed = self._create_field(tx_grid, "Vehicle Speed", "0 km/h", 0, 0)
        self.lbl_throttle = self._create_field(tx_grid, "Throttle Position", "0 %", 0, 1)
        self.lbl_engine = self._create_field(tx_grid, "Engine Status", "STANDBY", 1, 0)
        self.lbl_tx_fv = self._create_field(tx_grid, "Freshness Counter (FV)", "0", 1, 1)

        mac_frame = tk.Frame(pane_tx, bg="#14161C", padx=10, pady=8, highlightbackground="#262B38", highlightthickness=1)
        mac_frame.pack(fill=tk.X, pady=12)
        tk.Label(mac_frame, text="Truncated MAC (AES-128 CMAC RFC 4493):", font=("Segoe UI", 8), fg="#8E95A5", bg="#14161C").pack(anchor="w")
        self.lbl_tx_mac = tk.Label(mac_frame, text="0x00000000", font=("Consolas", 14, "bold"), fg="#D4D9E2", bg="#14161C")
        self.lbl_tx_mac.pack(anchor="w", pady=2)

        self.btn_attack = tk.Button(pane_tx, text="⚡ Inject Replay Attack (Simulate PC13)", font=("Segoe UI", 10, "bold"), bg="#E02444", fg="#FFFFFF", activebackground="#C01C38", relief="flat", pady=8, command=self.trigger_attack)
        self.btn_attack.pack(fill=tk.X, pady=(10, 0))

        pane_rx = tk.Frame(main_panes, bg="#1A1D24", padx=16, pady=14, highlightbackground="#2A2F3D", highlightthickness=1)
        pane_rx.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))

        tk.Label(pane_rx, text="NODE B (RECEIVER / SECURE VERIFIER)", font=("Segoe UI", 11, "bold"), fg="#00FF88", bg="#1A1D24").pack(anchor="w")
        tk.Label(pane_rx, text="EXTI0 Interrupt -> Acceptance Window Check -> Verification", font=("Segoe UI", 8), fg="#727B8E", bg="#1A1D24").pack(anchor="w", pady=(0, 12))

        self.banner_frame = tk.Frame(pane_rx, bg="#162A22", padx=12, pady=12, highlightbackground="#00FF88", highlightthickness=1)
        self.banner_frame.pack(fill=tk.X, pady=(0, 12))
        self.lbl_banner_status = tk.Label(self.banner_frame, text="AWAITING PDU", font=("Segoe UI", 14, "bold"), fg="#00FF88", bg="#162A22")
        self.lbl_banner_status.pack()
        self.lbl_banner_detail = tk.Label(self.banner_frame, text="System initialized in synchronized standby", font=("Segoe UI", 9), fg="#99DDBB", bg="#162A22")
        self.lbl_banner_detail.pack()

        rx_grid = tk.Frame(pane_rx, bg="#1A1D24")
        rx_grid.pack(fill=tk.X, pady=4)

        self.lbl_rx_fv = self._create_field(rx_grid, "Received Freshness (FV)", "0", 0, 0)
        self.lbl_rx_window = self._create_field(rx_grid, "Acceptance Window", "Delta <= 16", 0, 1)
        self.lbl_rx_mac_status = self._create_field(rx_grid, "Cryptographic MAC", "PENDING", 1, 0)
        self.lbl_rx_led = self._create_field(rx_grid, "Hardware LD2 State", "OFF", 1, 1)

        log_box_frame = tk.Frame(self.root, bg="#121317", padx=20, pady=0)
        log_box_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        tk.Label(log_box_frame, text="REAL-TIME TELEMETRY LOG STREAM", font=("Segoe UI", 9, "bold"), fg="#727B8E", bg="#121317").pack(anchor="w", pady=(0, 4))
        self.log_text = scrolledtext.ScrolledText(log_box_frame, bg="#0E0F12", fg="#CAD1DE", font=("Consolas", 9), height=7, relief="flat", highlightbackground="#222530", highlightthickness=1)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log_text.tag_config("TX", foreground="#00D2FF")
        self.log_text.tag_config("RX_OK", foreground="#00FF88")
        self.log_text.tag_config("REPLAY", foreground="#FF3B5C", background="#2D0B12")
        self.log_text.tag_config("INVALID", foreground="#FFAA00")
        self.log_text.tag_config("SYS", foreground="#727B8E")

        self.append_log("[SYS] Dashboard loaded. Connect COM ports or click 'Demo Mode' for live test.", "SYS")

    def _create_stat_box(self, parent, title, val, color):
        frame = tk.Frame(parent, bg="#1A1D24", padx=12, pady=8, highlightbackground="#262B38", highlightthickness=1)
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        tk.Label(frame, text=title, font=("Segoe UI", 7, "bold"), fg="#727B8E", bg="#1A1D24").pack(anchor="w")
        lbl = tk.Label(frame, text=val, font=("Segoe UI", 16, "bold"), fg=color, bg="#1A1D24")
        lbl.pack(anchor="w")
        return lbl

    def _create_field(self, parent, title, val, r, c):
        frame = tk.Frame(parent, bg="#14161C", padx=10, pady=8, highlightbackground="#222632", highlightthickness=1)
        frame.grid(row=r, column=c, sticky="nsew", padx=4, pady=4)
        parent.grid_columnconfigure(c, weight=1)
        tk.Label(frame, text=title, font=("Segoe UI", 8), fg="#727B8E", bg="#14161C").pack(anchor="w")
        lbl = tk.Label(frame, text=val, font=("Segoe UI", 12, "bold"), fg="#FFFFFF", bg="#14161C")
        lbl.pack(anchor="w", pady=(2, 0))
        return lbl

    def refresh_ports(self):
        if not HAS_SERIAL:
            ports = []
        else:
            ports = [p.device for p in serial.tools.list_ports.comports()]

        self.tx_combo["values"] = ports
        self.rx_combo["values"] = ports

        if ports:
            if not self.tx_combo.get():
                self.tx_combo.current(0)
            if len(ports) > 1 and not self.rx_combo.get():
                self.rx_combo.current(1)
            elif not self.rx_combo.get():
                self.rx_combo.current(0)

    def append_log(self, text, tag="SYS"):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {text}\n"
        self.log_text.insert(tk.END, line, tag)
        self.log_text.see(tk.END)

    def toggle_connection(self):
        if self.is_connected:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        if not HAS_SERIAL:
            messagebox.showerror("Error", "pyserial is not installed.")
            return

        p_tx = self.tx_combo.get()
        p_rx = self.rx_combo.get()

        if not p_tx or not p_rx:
            messagebox.showwarning("Port Error", "Please select both TX and RX ports.")
            return

        try:
            self.ser_tx = serial.Serial(p_tx, self.baudrate, timeout=0.2)
            self.ser_rx = serial.Serial(p_rx, self.baudrate, timeout=0.2)
            self.is_connected = True
            self.btn_connect.config(text="Disconnect", bg="#E02444")
            self.append_log(f"Connected to Node A ({p_tx}) and Node B ({p_rx}) @ {self.baudrate} baud", "SYS")

            threading.Thread(target=self._reader_tx, daemon=True).start()
            threading.Thread(target=self._reader_rx, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to open ports:\n{e}")
            self.disconnect()

    def disconnect(self):
        self.is_connected = False
        if self.ser_tx:
            try: self.ser_tx.close()
            except: pass
        if self.ser_rx:
            try: self.ser_rx.close()
            except: pass
        self.ser_tx = None
        self.ser_rx = None
        self.btn_connect.config(text="Connect", bg="#0080FF")
        self.append_log("Disconnected from serial ports.", "SYS")

    def toggle_sim_mode(self):
        if self.is_sim_mode:
            self.is_sim_mode = False
            self.btn_sim.config(text="Demo Mode", bg="#3A4050")
            self.append_log("Demo mode stopped.", "SYS")
        else:
            if self.is_connected:
                self.disconnect()
            self.is_sim_mode = True
            self.btn_sim.config(text="Stop Demo", bg="#00FF88", fg="#000000")
            self.append_log("Demo mode active: Simulating SecOC traffic & FVM verification...", "SYS")
            threading.Thread(target=self._run_sim_loop, daemon=True).start()

    def trigger_attack(self):
        if self.is_sim_mode:
            self.sim_attack_pending = True
            self.append_log("[ACTION] Replay attack injection triggered!", "REPLAY")
        else:
            self.append_log("[NOTE] Physical mode: Press blue button PC13 on Node A to inject replay attack.", "SYS")

    def _reader_tx(self):
        tx_re = re.compile(r"\[TX\]\s+PDU:(0x[0-9A-Fa-f]+)\s+\|\s+CNT:(\d+)\s+\|\s+DATA:(\d+)\s+km/h\s+\|\s+MAC:(0x[0-9A-Fa-f]+)")
        while self.is_connected and self.running:
            try:
                line = self.ser_tx.readline().decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                if "[TX_ATTACK]" in line:
                    self.root.after(0, self._on_tx_attack)
                else:
                    m = tx_re.search(line)
                    if m:
                        pdu, cnt, spd, mac = m.groups()
                        self.root.after(0, self._update_tx_ui, int(cnt), int(spd), mac)
            except:
                break

    def _reader_rx(self):
        acc_re = re.compile(r"\[RX\]\s+PDU:(0x[0-9A-Fa-f]+)\s+\|\s+FV:(\d+)\s+\(SYNC\)\s+\|\s+MAC:VALID\s+->\s+PDU_ACCEPTED")
        rep_re = re.compile(r"\[RX\]\s+PDU:(0x[0-9A-Fa-f]+)\s+\|\s+FV:(\d+)\s+\(OLD\)\s+->\s+REPLAY DETECTED!\s+PDU_DROPPED")
        inv_re = re.compile(r"\[RX\]\s+PDU:(0x[0-9A-Fa-f]+)\s+\|\s+FV:(\d+)\s+\|\s+MAC:INVALID\s+->\s+PDU_DROPPED")

        while self.is_connected and self.running:
            try:
                line = self.ser_rx.readline().decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                m_acc = acc_re.search(line)
                if m_acc:
                    pdu, fv = m_acc.groups()
                    self.root.after(0, self._on_rx_accepted, int(fv))
                    continue
                m_rep = rep_re.search(line)
                if m_rep:
                    pdu, fv = m_rep.groups()
                    self.root.after(0, self._on_rx_replay, int(fv))
                    continue
                m_inv = inv_re.search(line)
                if m_inv:
                    pdu, fv = m_inv.groups()
                    self.root.after(0, self._on_rx_invalid, int(fv))
                    continue
            except:
                break

    def _update_tx_ui(self, cnt, spd, mac):
        self.stats["tx_count"] += 1
        self.lbl_stat_tx.config(text=str(self.stats["tx_count"]))
        self.lbl_speed.config(text=f"{spd} km/h")
        self.lbl_throttle.config(text=f"{(spd * 100) // 140} %")
        self.lbl_engine.config(text="RUNNING", fg="#00FF88")
        self.lbl_tx_fv.config(text=str(cnt))
        self.lbl_tx_mac.config(text=mac)
        self.append_log(f"[TX] PDU:0x120 | CNT:{cnt} | SPEED:{spd} km/h | MAC:{mac}", "TX")

    def _on_tx_attack(self):
        self.stats["attack_injected"] += 1
        self.append_log("[TX_ATTACK] Replay injected on PC13 press! Stale counter sent.", "REPLAY")

    def _on_rx_accepted(self, fv):
        self.stats["rx_accepted"] += 1
        self.lbl_stat_rx.config(text=str(self.stats["rx_accepted"]))
        self.lbl_rx_fv.config(text=str(fv))
        self.lbl_rx_window.config(text="DELTA IN RANGE (OK)", fg="#00FF88")
        self.lbl_rx_mac_status.config(text="VALID (RFC 4493)", fg="#00FF88")
        self.lbl_rx_led.config(text="BLINK (TOGGLED)", fg="#00FF88")

        self.banner_frame.config(bg="#122B1E", highlightbackground="#00FF88")
        self.lbl_banner_status.config(text="PDU AUTHENTICATED & ACCEPTED", fg="#00FF88", bg="#122B1E")
        self.lbl_banner_detail.config(text=f"FV:{fv} | Cryptographic CMAC Verified | Freshness Sync OK", fg="#80E8AA", bg="#122B1E")
        self.append_log(f"[RX] PDU:0x120 | FV:{fv} (SYNC) | MAC:VALID -> PDU_ACCEPTED", "RX_OK")

    def _on_rx_replay(self, fv):
        self.stats["rx_replay"] += 1
        self.lbl_stat_replay.config(text=str(self.stats["rx_replay"]))
        self.lbl_rx_fv.config(text=f"{fv} (STALE)", fg="#FF3B5C")
        self.lbl_rx_window.config(text="COUNTER REGRESSED!", fg="#FF3B5C")
        self.lbl_rx_mac_status.config(text="STALE TOKEN", fg="#FF3B5C")
        self.lbl_rx_led.config(text="OFF (DROPPED)", fg="#FF3B5C")

        self.banner_frame.config(bg="#330B14", highlightbackground="#FF3B5C")
        self.lbl_banner_status.config(text="SECURITY ALERT: REPLAY DETECTED!", fg="#FF3B5C", bg="#330B14")
        self.lbl_banner_detail.config(text=f"FV:{fv} is older than local window! Packet dropped immediately.", fg="#FFA0B0", bg="#330B14")
        self.append_log(f"[RX] PDU:0x120 | FV:{fv} (OLD) -> REPLAY DETECTED! PDU_DROPPED", "REPLAY")

    def _on_rx_invalid(self, fv):
        self.stats["rx_invalid"] += 1
        self.lbl_stat_mac.config(text=str(self.stats["rx_invalid"]))
        self.lbl_rx_fv.config(text=str(fv))
        self.lbl_rx_mac_status.config(text="INTEGRITY FAILED", fg="#FFAA00")
        self.banner_frame.config(bg="#33240A", highlightbackground="#FFAA00")
        self.lbl_banner_status.config(text="MAC VERIFICATION FAILED", fg="#FFAA00", bg="#33240A")
        self.lbl_banner_detail.config(text="Payload tampered or key mismatch! Frame dropped.", fg="#FFCC88", bg="#33240A")
        self.append_log(f"[RX] PDU:0x120 | FV:{fv} | MAC:INVALID -> PDU_DROPPED", "INVALID")

    def _run_sim_loop(self):
        speed_dir = 1
        while self.is_sim_mode and self.running:
            time.sleep(0.3)

            if speed_dir:
                self.sim_speed += 3
                if self.sim_speed >= 120:
                    speed_dir = 0
            else:
                self.sim_speed -= 3
                if self.sim_speed <= 30:
                    speed_dir = 1

            if self.sim_attack_pending:
                self.sim_attack_pending = False
                replayed_fv = max(1, self.sim_cnt - 10)
                mac_fake = f"0x{random.randint(0x10000000, 0xFFFFFFFF):08X}"

                self.root.after(0, self._on_tx_attack)
                self.root.after(0, self._update_tx_ui, replayed_fv, self.sim_speed, mac_fake)
                time.sleep(0.1)
                self.root.after(0, self._on_rx_replay, replayed_fv)
            else:
                self.sim_cnt = (self.sim_cnt + 1) % 256
                if self.sim_cnt == 0:
                    self.sim_cnt = 1
                mac_val = f"0x{random.randint(0x10000000, 0xFFFFFFFF):08X}"
                self.root.after(0, self._update_tx_ui, self.sim_cnt, self.sim_speed, mac_val)
                time.sleep(0.05)
                self.root.after(0, self._on_rx_accepted, self.sim_cnt)

def main():
    parser = argparse.ArgumentParser(description="AUTOSAR SecOC & FVM Dashboard")
    parser.add_argument("--tx", type=str, help="Serial port for Node A (TX)")
    parser.add_argument("--rx", type=str, help="Serial port for Node B (RX)")
    parser.add_argument("--baud", type=int, default=115200, help="Baudrate (default: 115200)")
    parser.add_argument("--list", action="store_true", help="List serial ports and exit")
    args = parser.parse_args()

    if args.list:
        if HAS_SERIAL:
            ports = serial.tools.list_ports.comports()
            print("\nAvailable Serial Ports:")
            for p in ports:
                print(f"  - {p.device}: {p.description}")
        else:
            print("[ERROR] pyserial is not installed.")
        sys.exit(0)

    root = tk.Tk()
    app = SecOCDashboardApp(root, port_tx=args.tx, port_rx=args.rx, baudrate=args.baud)
    root.protocol("WM_DELETE_WINDOW", lambda: (setattr(app, 'running', False), root.destroy()))
    root.mainloop()

if __name__ == "__main__":
    main()
