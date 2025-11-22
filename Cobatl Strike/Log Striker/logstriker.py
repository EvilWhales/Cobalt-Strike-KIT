#!/usr/bin/env python3
"""
LogStriker - Cobalt Strike Log Aggregation Tool

Parses Cobalt Strike Beacon logs from multiple files and organizes them
chronologically for penetration testing analysis.
"""

import re
import sys
import os
import shlex
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
import subprocess


@dataclass
class LogEntry:
    """Represents a single log entry with timestamp and content."""
    timestamp: datetime
    entry_type: str
    content: List[str]
    source_file: str
    ip_address: Optional[str] = None
    date_folder: Optional[str] = None

    def format(self) -> str:
        """Reconstruct entry in original log format."""
        if not self.content:
            return (
                f"{self.timestamp.strftime('%m/%d %H:%M:%S')} UTC "
                f"[{self.entry_type}] (empty)\n"
            )

        lines = [
            f"{self.timestamp.strftime('%m/%d %H:%M:%S')} UTC "
            f"[{self.entry_type}] {self.content[0]}"
        ]
        if len(self.content) > 1:
            lines.extend(self.content[1:])
        return '\n'.join(lines) + '\n'


class SSHManager:
    """Manages SSH connections to Cobalt Strike teamserver."""

    CONNECTION_TIMEOUT = 10
    COMMAND_TIMEOUT = 30
    FILE_TRANSFER_TIMEOUT = 300

    def __init__(self, ssh_config_host: str):
        self.ssh_config_host = ssh_config_host
        self.connected = False

    def connect(self) -> bool:
        """Test SSH connection using config entry."""
        try:
            result = subprocess.run(
                ['ssh', '-q', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                 self.ssh_config_host, 'echo', 'connected'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=self.CONNECTION_TIMEOUT
            )

            if result.returncode == 0 and 'connected' in result.stdout:
                self.connected = True
                return True
            else:
                return False
        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            print("[!] SSH client not found. Please ensure OpenSSH is installed.")
            return False

    def execute_command(self, command: str) -> Tuple[int, str, str]:
        """Execute command on remote server."""
        if not self.connected:
            return (1, '', 'Not connected')

        try:
            result = subprocess.run(
                ['ssh', self.ssh_config_host, command],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=self.COMMAND_TIMEOUT
            )
            return (result.returncode, result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return (1, '', 'Command timeout')

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file from remote server using scp."""
        if not self.connected:
            return False

        try:
            result = subprocess.run(
                ['scp', '-q', f'{self.ssh_config_host}:{remote_path}', local_path],
                capture_output=True,
                timeout=self.FILE_TRANSFER_TIMEOUT
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def read_remote_file(self, remote_path: str) -> Optional[str]:
        """Read file content from remote server."""
        safe_path = shlex.quote(remote_path)
        returncode, stdout, stderr = self.execute_command(f'cat {safe_path}')
        if returncode == 0:
            return stdout
        return None


class LogDiscovery:
    """Discovers and inventories Cobalt Strike logs."""

    DEFAULT_LOGS_PATH = '/opt/tools/cobaltstrike/server/logs'
    DATE_PATTERN = re.compile(r'/(\d{6})/')
    IP_PATTERN = re.compile(r'/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/')

    def __init__(self, ssh_manager: SSHManager):
        self.ssh = ssh_manager
        self.logs_path = None

    def find_logs_directory(self) -> Optional[str]:
        """Find Cobalt Strike logs directory."""
        print("[*] Locating Cobalt Strike logs directory...")

        safe_path = shlex.quote(self.DEFAULT_LOGS_PATH)
        returncode, stdout, _ = self.ssh.execute_command(f'test -d {safe_path} && echo "exists"')

        if returncode == 0 and 'exists' in stdout:
            self.logs_path = self.DEFAULT_LOGS_PATH
            print(f"[+] Found logs at: {self.logs_path}")
            return self.logs_path

        print(f"[-] Default path not found: {self.DEFAULT_LOGS_PATH}")
        print("[*] Searching for Cobalt Strike logs directory...")

        search_paths = [
            '/opt/cobaltstrike/logs',
            '/opt/tools/cobaltstrike/logs',
            '/opt/*/cobaltstrike/*/logs',
            '~/cobaltstrike/logs'
        ]

        for path in search_paths:
            returncode, stdout, _ = self.ssh.execute_command(f'ls -d {path} 2>/dev/null | head -1')
            if returncode == 0 and stdout.strip():
                candidate = stdout.strip()
                if self._verify_logs_directory(candidate):
                    self.logs_path = candidate
                    print(f"[+] Found logs at: {self.logs_path}")
                    return self.logs_path

        print("[-] Could not locate logs directory automatically")
        user_path = input("    Please enter the full path to the logs directory: ").strip()

        if self._verify_logs_directory(user_path):
            self.logs_path = user_path
            print(f"[+] Verified logs at: {self.logs_path}")
            return self.logs_path

        print("[!] Invalid logs directory")
        return None

    def _verify_logs_directory(self, path: str) -> bool:
        """Verify this is actually a Cobalt Strike logs directory."""
        safe_path = shlex.quote(path)
        returncode, stdout, _ = self.ssh.execute_command(
            f'ls {safe_path} 2>/dev/null | grep -E "^[0-9]{{6}}$" | head -1'
        )
        return returncode == 0 and stdout.strip()

    def scan_structure(self) -> Dict:
        """Scan logs directory and build inventory."""
        if not self.logs_path:
            return {}

        print("[*] Scanning log structure...")

        inventory = {
            'beacon_logs': defaultdict(list),
            'system_logs': defaultdict(list)
        }

        safe_path = shlex.quote(self.logs_path)
        returncode, stdout, _ = self.ssh.execute_command(
            f'find {safe_path} -type f -name "*.log" 2>/dev/null'
        )

        if returncode != 0:
            return inventory

        date_folders = set()
        ip_addresses = set()

        for log_file in stdout.strip().split('\n'):
            if not log_file:
                continue

            if 'beacon_' in log_file:
                date_match = self.DATE_PATTERN.search(log_file)
                ip_match = self.IP_PATTERN.search(log_file)

                if date_match and ip_match:
                    date_folder = date_match.group(1)
                    ip_address = ip_match.group(1)

                    date_folders.add(date_folder)
                    ip_addresses.add(ip_address)

                    inventory['beacon_logs'][ip_address].append({
                        'path': log_file,
                        'date_folder': date_folder
                    })
            else:
                filename = os.path.basename(log_file)

                if filename == 'download.log':
                    inventory['system_logs']['download'].append(log_file)
                elif filename == 'weblog_80.log':
                    inventory['system_logs']['weblog_80'].append(log_file)
                elif filename == 'weblog_443.log':
                    inventory['system_logs']['weblog_443'].append(log_file)
                elif filename == 'events.log':
                    inventory['system_logs']['events'].append(log_file)

        print(f"[+] Found {len(date_folders)} date folders: {', '.join(sorted(date_folders))}")
        print(f"[+] Found {len(ip_addresses)} unique IP addresses")

        total_beacon_logs = sum(len(logs) for logs in inventory['beacon_logs'].values())
        total_system_logs = sum(len(logs) for logs in inventory['system_logs'].values())

        print(f"[+] Found {total_beacon_logs} beacon logs, {total_system_logs} system logs")

        return inventory


class LogParser:
    """Parses Cobalt Strike log files into LogEntry objects."""

    TIMESTAMP_PATTERN = re.compile(
        r'^(\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})\s+UTC\s+\[([^\]]+)\]\s+(.*)$'
    )
    UTC_TZ = timezone.utc
    DATE_FOLDER_FORMAT = '%y%m%d'

    @staticmethod
    def parse_beacon_log(content: str, date_folder: str, source_file: str, ip_address: str) -> List[LogEntry]:
        """Parse beacon log file into LogEntry objects."""
        if not content:
            return []

        if not date_folder or len(date_folder) != 6 or not date_folder.isdigit():
            print(f"[!] Warning: Invalid date_folder '{date_folder}' in {source_file}, using current year")
            base_year = datetime.now().year
        else:
            year_suffix = int(date_folder[:2])
            base_year = 2000 + year_suffix

        entries = []
        current_entry = None

        for line in content.splitlines():
            match = LogParser.TIMESTAMP_PATTERN.match(line)

            if match:
                if current_entry:
                    entries.append(current_entry)

                mm_dd, time_str, entry_type, content_line = match.groups()

                try:
                    month, day = map(int, mm_dd.split('/'))
                    hour, minute, second = map(int, time_str.split(':'))

                    timestamp = datetime(
                        base_year, month, day, hour, minute, second,
                        tzinfo=LogParser.UTC_TZ
                    )

                    current_entry = LogEntry(
                        timestamp=timestamp,
                        entry_type=entry_type,
                        content=[content_line],
                        source_file=source_file,
                        ip_address=ip_address,
                        date_folder=date_folder
                    )
                except (ValueError, OverflowError) as e:
                    print(f"[!] Warning: Skipping malformed timestamp in {source_file}: {line[:80]}")
                    current_entry = None
            else:
                if current_entry:
                    current_entry.content.append(line)
                elif line.strip():
                    print(f"[!] Warning: Orphaned line in {source_file}: {line[:50]}")

        if current_entry:
            entries.append(current_entry)

        return entries

    @staticmethod
    def parse_system_log(content: str, date_folder: str, source_file: str) -> List[LogEntry]:
        """Parse system log file (download, weblog, events)."""
        return LogParser.parse_beacon_log(content, date_folder, source_file, ip_address=None)


class LogAggregator:
    """Aggregates and sorts log entries."""

    @staticmethod
    def aggregate_by_ip(entries_by_ip: Dict[str, List[LogEntry]]) -> Dict[str, List[LogEntry]]:
        """Combine and sort all entries per IP address."""
        for entries in entries_by_ip.values():
            entries.sort(key=lambda e: e.timestamp)
        return entries_by_ip

    @staticmethod
    def aggregate_by_ip_and_date(entries_by_ip: Dict[str, List[LogEntry]]) -> Dict[Tuple[str, str], List[LogEntry]]:
        """Aggregate entries by IP address and date folder."""
        aggregated = defaultdict(list)

        for ip, entries in entries_by_ip.items():
            for entry in entries:
                if entry.date_folder:
                    key = (ip, entry.date_folder)
                    aggregated[key].append(entry)

        for entries in aggregated.values():
            entries.sort(key=lambda e: e.timestamp)

        return dict(aggregated)

    @staticmethod
    def aggregate_system_logs(entries_by_type: Dict[str, List[LogEntry]]) -> Dict[str, List[LogEntry]]:
        """Combine and sort system log entries by type."""
        for entries in entries_by_type.values():
            entries.sort(key=lambda e: e.timestamp)
        return entries_by_type


class LogWriter:
    """Writes aggregated logs to output files."""

    FILE_BUFFER_SIZE = 65536

    @staticmethod
    def write_complete_logs(aggregated_entries: Dict[str, List[LogEntry]], output_dir: Path) -> int:
        """Write complete (all dates) combined log files per IP."""
        complete_dir = output_dir / "complete"
        complete_dir.mkdir(exist_ok=True)

        files_written = 0

        for ip, entries in aggregated_entries.items():
            if not entries:
                continue

            output_file = complete_dir / f"{ip}-Complete.log"

            try:
                with open(output_file, 'w', encoding='utf-8', buffering=LogWriter.FILE_BUFFER_SIZE) as f:
                    f.writelines(entry.format() for entry in entries)

                print(f"    - {ip} ({len(entries)} entries) -> complete/{output_file.name}")
                files_written += 1
            except IOError as e:
                print(f"[!] Error writing {output_file}: {e}")
                continue
            except Exception as e:
                print(f"[!] Unexpected error writing {output_file}: {e}")
                continue

        return files_written

    @staticmethod
    def write_daily_logs(aggregated_entries: Dict[Tuple[str, str], List[LogEntry]], output_dir: Path) -> int:
        """Write daily breakdown log files per IP and date."""
        daily_dir = output_dir / "daily"
        daily_dir.mkdir(exist_ok=True)

        files_written = 0

        for (ip, date_folder), entries in aggregated_entries.items():
            if not entries:
                continue

            output_file = daily_dir / f"{ip}-{date_folder}.log"

            try:
                with open(output_file, 'w', encoding='utf-8', buffering=LogWriter.FILE_BUFFER_SIZE) as f:
                    f.writelines(entry.format() for entry in entries)

                print(f"    - {ip} [{date_folder}] ({len(entries)} entries) -> daily/{output_file.name}")
                files_written += 1
            except IOError as e:
                print(f"[!] Error writing {output_file}: {e}")
                continue
            except Exception as e:
                print(f"[!] Unexpected error writing {output_file}: {e}")
                continue

        return files_written


def main():
    """Main CLI interface."""
    print("=" * 60)
    print("LogStriker - Cobalt Strike Log Aggregation Tool")
    print("=" * 60)
    print()

    ssh_host = input("Enter SSH config host entry for teamserver: ").strip()

    if not ssh_host:
        print("[!] No SSH host provided")
        return 1

    print()
    print(f"[*] Connecting to teamserver via SSH config: {ssh_host}")

    ssh = SSHManager(ssh_host)

    if not ssh.connect():
        print(f"[!] Failed to connect to '{ssh_host}'")
        print()
        print("Troubleshooting:")
        print("  1. Check SSH config file (~/.ssh/config)")
        print("  2. Verify host entry exists")
        print(f"  3. Test connection: ssh {ssh_host}")
        return 1

    print("[+] Connected successfully")
    print()

    discovery = LogDiscovery(ssh)

    if not discovery.find_logs_directory():
        return 1

    print()

    inventory = discovery.scan_structure()

    if not inventory['beacon_logs'] and not inventory['system_logs']:
        print("[!] No log files found")
        return 1

    print()

    print("[*] Downloading and parsing beacon logs...")

    beacon_entries_by_ip = defaultdict(list)
    total_beacon_entries = 0

    for ip, log_files in inventory['beacon_logs'].items():
        for log_info in log_files:
            content = ssh.read_remote_file(log_info['path'])

            if content is None:
                print(f"[!] Warning: Failed to download {log_info['path']}")
                continue
            elif not content:
                print(f"[!] Warning: Empty file {log_info['path']}")
                continue

            entries = LogParser.parse_beacon_log(
                content,
                log_info['date_folder'],
                log_info['path'],
                ip
            )
            beacon_entries_by_ip[ip].extend(entries)
            total_beacon_entries += len(entries)

    print(f"[+] Parsed {total_beacon_entries} entries from {len(inventory['beacon_logs'])} IPs")

    print("[*] Downloading and parsing system logs...")

    system_entries_by_type = defaultdict(list)
    total_system_entries = 0

    for log_type, log_files in inventory['system_logs'].items():
        for log_path in log_files:
            date_match = LogDiscovery.DATE_PATTERN.search(log_path)
            if date_match:
                date_folder = date_match.group(1)
            else:
                current_date = datetime.now()
                date_folder = current_date.strftime(LogParser.DATE_FOLDER_FORMAT)

            content = ssh.read_remote_file(log_path)

            if content is None or not content:
                continue

            entries = LogParser.parse_system_log(
                content,
                date_folder,
                log_path
            )
            system_entries_by_type[log_type].extend(entries)
            total_system_entries += len(entries)

    if total_system_entries > 0:
        print(f"[+] Parsed {total_system_entries} entries from system logs")
    else:
        print(f"[+] No system logs found")

    print()
    print("[*] Aggregating logs for complete view...")

    aggregated_complete = LogAggregator.aggregate_by_ip(beacon_entries_by_ip)
    print(f"[+] Created {len(aggregated_complete)} complete IP logs")

    print("[*] Aggregating logs by date...")

    aggregated_daily = LogAggregator.aggregate_by_ip_and_date(beacon_entries_by_ip)
    unique_ips = set(ip for ip, _ in aggregated_daily.keys())
    print(f"[+] Created {len(aggregated_daily)} daily logs across {len(unique_ips)} IPs")

    print()

    output_dir = Path.cwd()
    print(f"[*] Writing output to: {output_dir}")
    print()

    complete_files = LogWriter.write_complete_logs(aggregated_complete, output_dir)
    print()
    daily_files = LogWriter.write_daily_logs(aggregated_daily, output_dir)

    print()
    print(f"[+] Complete! Wrote {complete_files + daily_files} total files")
    print(f"    - {complete_files} complete logs in complete/")
    print(f"    - {daily_files} daily logs in daily/")
    print(f"[+] Total entries processed: {total_beacon_entries}")

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)
