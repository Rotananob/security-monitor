#!/usr/bin/env python3
"""
Security Monitoring Script
ស្កេនរក files ដែលបានផ្លាស់ប្តូរ និង processes ដែលប្រើ CPU ខ្ពស់
"""

import os
import time
import psutil
from datetime import datetime, timedelta
from pathlib import Path
import json

class SecurityMonitor:
    def __init__(self, scan_paths=None, cpu_threshold=80.0):
        """
        Initialize Security Monitor
        
        Args:
            scan_paths: List នៃ directories ដែលត្រូវស្កេន
            cpu_threshold: CPU usage percentage ដែលចាត់ទុកជាខុសធម្មតា
        """
        self.scan_paths = scan_paths or [
            str(Path.home()),  # Home directory
            "C:\\Windows\\System32" if os.name == 'nt' else "/usr/bin",
            "C:\\Program Files" if os.name == 'nt' else "/usr/local/bin"
        ]
        self.cpu_threshold = cpu_threshold
        self.time_window = timedelta(minutes=5)
        
    def scan_modified_files(self):
        """ស្កេនរក files ដែលបានកែប្រែក្នុង 5 នាទីចុងក្រោយ"""
        print(f"\n{'='*70}")
        print(f"🔍 កំពុងស្កេនរក Files ដែលបានផ្លាស់ប្តូរ...")
        print(f"{'='*70}\n")
        
        current_time = datetime.now()
        cutoff_time = current_time - self.time_window
        modified_files = []
        
        for scan_path in self.scan_paths:
            if not os.path.exists(scan_path):
                print(f"⚠️  Path មិនមាន: {scan_path}")
                continue
                
            print(f"📂 កំពុងស្កេន: {scan_path}")
            
            try:
                for root, dirs, files in os.walk(scan_path):
                    # ចៀសវាង system directories
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                    for file in files:
                        try:
                            file_path = os.path.join(root, file)
                            mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                            
                            if mtime > cutoff_time:
                                file_size = os.path.getsize(file_path)
                                modified_files.append({
                                    'path': file_path,
                                    'modified': mtime.strftime('%Y-%m-%d %H:%M:%S'),
                                    'size': self._format_size(file_size),
                                    'extension': os.path.splitext(file)[1]
                                })
                        except (PermissionError, FileNotFoundError):
                            continue
                            
            except PermissionError:
                print(f"⚠️  Permission denied: {scan_path}")
                
        return modified_files
    
    def monitor_suspicious_processes(self):
        """តាមដាន processes ដែលប្រើ CPU ខ្ពស់"""
        print(f"\n{'='*70}")
        print(f"🔍 កំពុងតាមដាន Processes ដែលប្រើ CPU ខ្ពស់...")
        print(f"{'='*70}\n")
        
        suspicious_processes = []
        
        # ប្រមូល CPU usage data
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads']):
            try:
                # ទទួល CPU usage (sampling period 1 second)
                cpu_usage = proc.cpu_percent(interval=0.1)
                
                if cpu_usage > self.cpu_threshold:
                    proc_info = proc.info
                    suspicious_processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cpu_percent': f"{cpu_usage:.2f}%",
                        'memory_percent': f"{proc_info['memory_percent']:.2f}%",
                        'threads': proc_info['num_threads']
                    })
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        return suspicious_processes
    
    def get_network_connections(self, pids):
        """ទទួល network connections សម្រាប់ processes គួរឱ្យសង្ស័យ"""
        connections = {}
        
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                conns = proc.connections(kind='inet')
                
                if conns:
                    connections[pid] = []
                    for conn in conns:
                        connections[pid].append({
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                            'status': conn.status
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return connections
    
    def _format_size(self, size):
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def generate_report(self):
        """បង្កើតរបាយការណ៍ security monitoring"""
        print(f"\n{'='*70}")
        print(f"📊 SECURITY MONITORING REPORT")
        print(f"⏰ Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}")
        
        # ស្កេន modified files
        modified_files = self.scan_modified_files()
        
        if modified_files:
            print(f"\n⚠️  រកឃើញ {len(modified_files)} files ដែលបានកែប្រែ:\n")
            for idx, file in enumerate(modified_files[:20], 1):  # បង្ហាញតែ 20 files ដំបូង
                print(f"{idx}. {file['path']}")
                print(f"   📅 Modified: {file['modified']} | 📦 Size: {file['size']} | 📄 Type: {file['extension']}")
                
            if len(modified_files) > 20:
                print(f"\n   ... និង {len(modified_files) - 20} files ផ្សេងទៀត")
        else:
            print("\n✅ គ្មាន files ដែលបានកែប្រែថ្មីទេ")
        
        # តាមដាន suspicious processes
        suspicious_procs = self.monitor_suspicious_processes()
        
        if suspicious_procs:
            print(f"\n⚠️  រកឃើញ {len(suspicious_procs)} processes ដែលប្រើ CPU ខ្ពស់:\n")
            for idx, proc in enumerate(suspicious_procs, 1):
                print(f"{idx}. PID: {proc['pid']} | {proc['name']}")
                print(f"   💻 CPU: {proc['cpu_percent']} | 🧠 Memory: {proc['memory_percent']} | 🔗 Threads: {proc['threads']}")
            
            # ពិនិត្យ network connections
            pids = [p['pid'] for p in suspicious_procs]
            connections = self.get_network_connections(pids)
            
            if connections:
                print(f"\n🌐 Network Connections របស់ Suspicious Processes:\n")
                for pid, conns in connections.items():
                    proc_name = next(p['name'] for p in suspicious_procs if p['pid'] == pid)
                    print(f"   PID {pid} ({proc_name}):")
                    for conn in conns[:5]:  # បង្ហាញតែ 5 connections ដំបូង
                        print(f"      {conn['local']} → {conn['remote']} ({conn['status']})")
        else:
            print(f"\n✅ គ្មាន processes ដែលប្រើ CPU លើស {self.cpu_threshold}% ទេ")
        
        print(f"\n{'='*70}")
        print(f"✅ ការស្កេនបានបញ្ចប់")
        print(f"{'='*70}\n")
        
        return {
            'modified_files': modified_files,
            'suspicious_processes': suspicious_procs
        }


def main():
    """Main function"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║          🛡️  SECURITY MONITORING TOOL 🛡️                     ║
    ║                                                               ║
    ║  ✓ ស្កេនរក Files ដែលបានផ្លាស់ប្តូរក្នុង 5 នាទីចុងក្រោយ        ║
    ║  ✓ តាមដាន Processes ដែលប្រើ CPU ខ្ពស់                         ║
    ║  ✓ ពិនិត្យ Network Connections គួរឱ្យសង្ស័យ                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Configuration
    scan_paths = [
        str(Path.home() / "Documents"),
        str(Path.home() / "Downloads"),
        str(Path.home() / "Desktop")
    ]
    
    # បង្កើត monitor instance
    monitor = SecurityMonitor(scan_paths=scan_paths, cpu_threshold=70.0)
    
    # រត់ការស្កេន
    results = monitor.generate_report()
    
    # រក្សាទុក results ជា JSON (optional)
    output_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"📄 របាយការណ៍បានរក្សាទុកនៅ: {output_file}")


if __name__ == "__main__":
    main()