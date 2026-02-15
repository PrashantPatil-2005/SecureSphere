
import subprocess
import sys
import os
import time
import threading
import signal
from datetime import datetime

class TrafficCapture:
    def __init__(self, output_file=None, interface="any", duration=None):
        if output_file is None:
            output_file = f"captures/attack_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        self.output_file = output_file
        self.interface = interface
        self.duration = duration
        self.process = None
        self.capturing = False
        
        # Create captures directory
        os.makedirs(os.path.dirname(self.output_file) if os.path.dirname(self.output_file) else "captures", exist_ok=True)

    def start_capture(self):
        # tcpdump command
        cmd = [
            "tcpdump",
            "-i", self.interface,
            "-w", self.output_file,
            "-U",  # Write packets immediately
            # Capture relevant traffic only to avoid noise
            # (Note: In docker networks, might need to adjust filter or remove it)
            # For now, capturing everything on interface is safer for demo
        ]
        
        if self.duration:
            cmd.extend(["-G", str(self.duration), "-W", "1"])

        try:
            print(f"[*] Starting capture on {self.interface} -> {self.output_file}")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.capturing = True
            
            # Start a thread to read stderr (tcpdump output)
            def read_stderr():
                while self.capturing and self.process.poll() is None:
                    line = self.process.stderr.readline()
                    if line:
                        # print(f"TCPDUMP: {line.decode().strip()}")
                        pass
            
            threading.Thread(target=read_stderr, daemon=True).start()
            
        except FileNotFoundError:
            print("[!] Error: tcpdump not found. Please install it.")
        except Exception as e:
            print(f"[!] Error starting capture: {e}")

    def stop_capture(self):
        if self.process and self.capturing:
            print("[*] Stopping capture...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            
            self.capturing = False
            
            if os.path.exists(self.output_file):
                size = os.path.getsize(self.output_file)
                print(f"[*] Capture saved: {self.output_file} ({size} bytes)")
            else:
                print(f"[!] Warning: Output file not created.")

    def capture_during_attack(self, attack_function):
        self.start_capture()
        time.sleep(2)  # Settle
        
        try:
            print("[*] Running attack simulation...")
            attack_function()
        except Exception as e:
            print(f"[!] Error during attack: {e}")
        finally:
            time.sleep(2)  # Capture trailing packets
            self.stop_capture()
            
        return self.output_file

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Capture network traffic')
    parser.add_argument('--output', '-o', type=str, default=None, help='Output .pcap file path')
    parser.add_argument('--duration', '-d', type=int, default=None, help='Capture duration in seconds')
    parser.add_argument('--interface', '-i', type=str, default='any', help='Network interface')
    parser.add_argument('--with-attack', action='store_true', help='Run attack simulation during capture')
    
    args = parser.parse_args()
    
    capture = TrafficCapture(
        output_file=args.output,
        interface=args.interface,
        duration=args.duration
    )
    
    if args.with_attack:
        # Import and run attack (Assumes we are in proper directory)
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        try:
            from attack_orchestrator import AttackSimulator
            simulator = AttackSimulator(target_url="http://localhost", delay_mode="fast")
            
            def run_attack():
                # Run full kill chain
                simulator.scenario_full_kill_chain()
            
            pcap_file = capture.capture_during_attack(run_attack)
            print(f"\nCapture complete: {pcap_file}")
            print(f"Analyze with: python monitors/network/pcap_analyzer.py {pcap_file}")
            
        except ImportError:
            print("[!] Could not import AttackSimulator. Run from project root.")
    
    elif args.duration:
        capture.start_capture()
        print(f"Capturing for {args.duration} seconds...")
        time.sleep(args.duration)
        capture.stop_capture()
        
    else:
        capture.start_capture()
        print("Capturing... Press Ctrl+C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            capture.stop_capture()
