#!/usr/bin/env python3
"""
NFSpider - Spider NFS shares for sensitive files
Inspired by MANSPIDER (https://github.com/blacklanternsecurity/MANSPIDER)
"""

import argparse
import logging
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set, Callable
import hashlib

# ANSI colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger('nfspider')


@dataclass
class NFSpiderOptions:
    """Configuration options for NFSpider"""
    targets: List[str] = field(default_factory=list)
    loot_dir: str = ''
    maxdepth: int = 10
    threads: int = 5
    filenames: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    exclude_extensions: List[str] = field(default_factory=list)
    content: List[str] = field(default_factory=list)
    dirnames: List[str] = field(default_factory=list)
    exclude_dirnames: List[str] = field(default_factory=list)
    max_filesize: int = 10 * 1024 * 1024  # 10MB default
    no_download: bool = False
    quiet: bool = False
    or_logic: bool = False
    nfs_version: str = 'auto'
    mount_options: str = ''
    timeout: int = 30


# Default sensitive file extensions (from MANSPIDER)
SENSITIVE_EXTENSIONS = {
    # Password databases
    'kdbx', 'kdb', '1pif', 'agilekeychain', 'opvault', 'lpd', 'dashlane',
    'psafe3', 'enpass', 'bwdb', 'msecure', 'stickypass', 'pwm', 'rdb',
    'safe', 'zps', 'pmvault', 'mywallet', 'jpass', 'pwmdb',
    # Keys and certificates
    'pem', 'key', 'pfx', 'p12', 'pkcs12', 'crt', 'cer', 'csr', 'jks',
    'keystore', 'ppk', 'rsa', 'der', 'pub',
    # Config files
    'conf', 'config', 'cfg', 'ini', 'env', 'yml', 'yaml', 'json', 'xml',
    # Scripts
    'sh', 'bash', 'ps1', 'psm1', 'psd1', 'bat', 'cmd', 'vbs',
    # Documents
    'doc', 'docx', 'xls', 'xlsx', 'pdf', 'txt', 'csv', 'rtf',
    # Database
    'sql', 'db', 'sqlite', 'sqlite3', 'mdb', 'accdb',
    # Backup/VM
    'bak', 'backup', 'vmdk', 'vhd', 'vdi', 'dit',
    # Misc sensitive
    'htpasswd', 'shadow', 'passwd', 'id_rsa', 'id_dsa', 'id_ed25519',
}

# Default sensitive filename patterns
SENSITIVE_PATTERNS = [
    r'passw',
    r'secret',
    r'credential',
    r'private',
    r'\.env',
    r'config',
    r'backup',
    r'id_rsa',
    r'id_dsa',
    r'\.pem$',
    r'\.key$',
    r'\.ppk$',
    r'shadow',
    r'htpasswd',
    r'database',
    r'dump',
    r'export',
    r'user',
    r'admin',
    r'login',
    r'auth',
    r'token',
    r'api.?key',
    r'aws',
    r'azure',
    r'gcp',
    r'kube',
]


class NFSClient:
    """Handles NFS share operations"""
    
    def __init__(self, server: str, options: NFSpiderOptions):
        self.server = server
        self.options = options
        self.mount_point = None
        self._exports = None
    
    def get_exports(self) -> List[str]:
        """Get list of NFS exports from server using showmount"""
        if self._exports is not None:
            return self._exports
        
        try:
            cmd = ['showmount', '-e', self.server, '--no-headers']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.options.timeout
            )
            
            if result.returncode != 0:
                log.warning(f"[{self.server}] showmount failed: {result.stderr.strip()}")
                return []
            
            exports = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    # Format: /export/path clients
                    parts = line.split()
                    if parts:
                        exports.append(parts[0])
            
            self._exports = exports
            return exports
            
        except subprocess.TimeoutExpired:
            log.warning(f"[{self.server}] showmount timed out")
            return []
        except FileNotFoundError:
            log.error("showmount not found. Install nfs-common: apt install nfs-common")
            return []
        except Exception as e:
            log.warning(f"[{self.server}] Error getting exports: {e}")
            return []
    
    def mount(self, export: str) -> Optional[str]:
        """Mount an NFS export and return the mount point"""
        mount_point = tempfile.mkdtemp(prefix='nfspider_')
        
        try:
            # Start with minimal options (like the working manual mount)
            # Only add options if explicitly requested
            cmd = ['mount', '-t', 'nfs']
            
            # Build mount options only if needed
            mount_opts = []
            
            # Add NFS version only if explicitly set to something other than auto
            if self.options.nfs_version and self.options.nfs_version != 'auto':
                mount_opts.append(f'vers={self.options.nfs_version}')
            
            # Add soft mount for timeout handling
            mount_opts.append('soft')
            mount_opts.append(f'timeo={self.options.timeout * 10}')
            
            # Add custom mount options
            if self.options.mount_options:
                mount_opts.append(self.options.mount_options)
            
            # Only add -o if we have options
            if mount_opts:
                cmd.extend(['-o', ','.join(mount_opts)])
            
            # Source and destination
            cmd.append(f'{self.server}:{export}')
            cmd.append(mount_point)
            
            log.debug(f"Mount command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.options.timeout
            )
            
            if result.returncode != 0:
                error_msg = result.stderr.strip()
                log.debug(f"[{self.server}:{export}] Mount with options failed: {error_msg}")
                
                # Fallback: try bare mount like manual command
                cmd_bare = ['mount', '-t', 'nfs', f'{self.server}:{export}', mount_point]
                log.debug(f"Trying bare mount: {' '.join(cmd_bare)}")
                
                result_bare = subprocess.run(
                    cmd_bare,
                    capture_output=True,
                    text=True,
                    timeout=self.options.timeout
                )
                
                if result_bare.returncode == 0:
                    self.mount_point = mount_point
                    return mount_point
                
                log.warning(f"[{self.server}:{export}] Mount failed: {result_bare.stderr.strip()}")
                os.rmdir(mount_point)
                return None
            
            self.mount_point = mount_point
            return mount_point
            
        except subprocess.TimeoutExpired:
            log.warning(f"[{self.server}:{export}] Mount timed out")
            self._cleanup_mount(mount_point)
            return None
        except Exception as e:
            log.warning(f"[{self.server}:{export}] Mount error: {e}")
            self._cleanup_mount(mount_point)
            return None
    
    def unmount(self, mount_point: str = None):
        """Unmount the NFS share"""
        mp = mount_point or self.mount_point
        if mp:
            self._cleanup_mount(mp)
    
    def _cleanup_mount(self, mount_point: str):
        """Clean up mount point"""
        try:
            subprocess.run(['umount', '-l', mount_point], 
                         capture_output=True, timeout=10)
        except:
            pass
        try:
            os.rmdir(mount_point)
        except:
            pass


class FileFilter:
    """Filter files based on various criteria"""
    
    def __init__(self, options: NFSpiderOptions):
        self.options = options
        
        # Compile regex patterns
        self.filename_patterns = []
        for pattern in options.filenames:
            try:
                self.filename_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                log.warning(f"Invalid filename regex '{pattern}': {e}")
        
        self.content_patterns = []
        for pattern in options.content:
            try:
                self.content_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                log.warning(f"Invalid content regex '{pattern}': {e}")
        
        self.dirname_patterns = []
        for pattern in options.dirnames:
            try:
                self.dirname_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                log.warning(f"Invalid dirname regex '{pattern}': {e}")
        
        self.exclude_dirname_patterns = []
        for pattern in options.exclude_dirnames:
            try:
                self.exclude_dirname_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                log.warning(f"Invalid exclude dirname regex '{pattern}': {e}")
    
    def should_process_dir(self, dir_path: str) -> bool:
        """Check if directory should be processed"""
        dir_name = os.path.basename(dir_path)
        
        # Check exclusions first
        for pattern in self.exclude_dirname_patterns:
            if pattern.search(dir_name):
                return False
        
        # If dirnames specified, only process matching dirs
        if self.dirname_patterns:
            for pattern in self.dirname_patterns:
                if pattern.search(dir_name):
                    return True
            return False
        
        return True
    
    def matches_filename(self, filepath: str) -> bool:
        """Check if filename matches patterns"""
        filename = os.path.basename(filepath)
        
        if not self.filename_patterns:
            return True
        
        for pattern in self.filename_patterns:
            if pattern.search(filename):
                return True
        return False
    
    def matches_extension(self, filepath: str) -> bool:
        """Check if file extension matches"""
        ext = os.path.splitext(filepath)[1].lower().lstrip('.')
        
        # Check exclusions
        if ext in self.options.exclude_extensions:
            return False
        
        # If extensions specified, check for match
        if self.options.extensions:
            return ext in [e.lower().lstrip('.') for e in self.options.extensions]
        
        return True
    
    def matches_filters(self, filepath: str) -> bool:
        """Check if file matches all filters (AND logic) or any filter (OR logic)"""
        matches_name = self.matches_filename(filepath)
        matches_ext = self.matches_extension(filepath)
        
        # Check file size
        try:
            if os.path.getsize(filepath) > self.options.max_filesize:
                return False
        except OSError:
            return False
        
        if self.options.or_logic:
            # OR logic: any filter match is sufficient
            if self.options.filenames and matches_name:
                return True
            if self.options.extensions and matches_ext:
                return True
            # Content will be checked later if no other matches
            if self.options.content:
                return True  # Will be validated during content search
            return False
        else:
            # AND logic: all specified filters must match
            if self.options.filenames and not matches_name:
                return False
            if self.options.extensions and not matches_ext:
                return False
            return True
    
    def search_content(self, filepath: str) -> Optional[str]:
        """Search file content for patterns, return matching text if found"""
        if not self.content_patterns:
            return None
        
        try:
            # Try to read as text
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(self.options.max_filesize)
            
            for pattern in self.content_patterns:
                match = pattern.search(content)
                if match:
                    # Return context around match
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    return content[start:end]
            
        except Exception as e:
            log.debug(f"Error reading {filepath}: {e}")
        
        return None


class Spiderling:
    """Worker that crawls a single NFS export"""
    
    def __init__(self, server: str, export: str, options: NFSpiderOptions, 
                 file_filter: FileFilter, loot_dir: str):
        self.server = server
        self.export = export
        self.options = options
        self.filter = file_filter
        self.loot_dir = loot_dir
        self.client = NFSClient(server, options)
        self.files_found = 0
        self.files_downloaded = 0
    
    def run(self) -> dict:
        """Spider the NFS export"""
        result = {
            'server': self.server,
            'export': self.export,
            'files_found': 0,
            'files_downloaded': 0,
            'errors': [],
            'matches': []
        }
        
        log.info(f"{Colors.CYAN}[*]{Colors.RESET} Spidering {self.server}:{self.export}")
        
        # Mount the export
        mount_point = self.client.mount(self.export)
        if not mount_point:
            result['errors'].append(f"Failed to mount {self.server}:{self.export}")
            return result
        
        try:
            # Spider the mounted filesystem
            self._spider_directory(mount_point, 0, result)
        finally:
            # Always unmount
            self.client.unmount(mount_point)
        
        result['files_found'] = self.files_found
        result['files_downloaded'] = self.files_downloaded
        
        return result
    
    def _spider_directory(self, directory: str, depth: int, result: dict):
        """Recursively spider a directory"""
        if depth > self.options.maxdepth:
            return
        
        try:
            entries = os.listdir(directory)
        except PermissionError:
            log.debug(f"Permission denied: {directory}")
            return
        except OSError as e:
            log.debug(f"Error listing {directory}: {e}")
            return
        
        for entry in entries:
            full_path = os.path.join(directory, entry)
            
            try:
                if os.path.isdir(full_path):
                    if self.filter.should_process_dir(full_path):
                        self._spider_directory(full_path, depth + 1, result)
                elif os.path.isfile(full_path):
                    self._process_file(full_path, result)
            except OSError:
                continue
    
    def _process_file(self, filepath: str, result: dict):
        """Process a single file"""
        # Check basic filters
        if not self.filter.matches_filters(filepath):
            return
        
        self.files_found += 1
        
        # Check content if needed
        content_match = None
        if self.options.content:
            content_match = self.filter.search_content(filepath)
            if not content_match and not self.options.or_logic:
                return
            if self.options.or_logic and not content_match:
                # In OR mode, if we got here without content match,
                # we need filename or extension match
                if not (self.filter.matches_filename(filepath) or 
                       (self.options.extensions and self.filter.matches_extension(filepath))):
                    return
        
        # We have a match!
        relative_path = filepath.split(tempfile.gettempdir())[-1].lstrip('/')
        remote_path = f"{self.server}:{self.export}/{relative_path.split('/', 1)[-1] if '/' in relative_path else ''}"
        
        match_info = {
            'local_path': filepath,
            'remote_path': remote_path,
            'filename': os.path.basename(filepath),
            'content_match': content_match
        }
        
        # Log the find
        self._log_match(match_info)
        result['matches'].append(match_info)
        
        # Download if enabled
        if not self.options.no_download:
            self._download_file(filepath, match_info)
    
    def _log_match(self, match_info: dict):
        """Log a matching file"""
        print(f"\n{Colors.GREEN}[+] MATCH:{Colors.RESET} {match_info['remote_path']}")
        
        if match_info['content_match'] and not self.options.quiet:
            # Truncate and clean content for display
            content = match_info['content_match'][:200]
            content = content.replace('\n', ' ').replace('\r', '')
            print(f"    {Colors.YELLOW}Content:{Colors.RESET} ...{content}...")
    
    def _download_file(self, filepath: str, match_info: dict):
        """Download a matching file to loot directory"""
        try:
            # Create subdirectory structure
            server_dir = os.path.join(self.loot_dir, self.server.replace(':', '_'))
            export_dir = os.path.join(server_dir, self.export.replace('/', '_').strip('_'))
            os.makedirs(export_dir, exist_ok=True)
            
            # Handle duplicate filenames
            dest_filename = match_info['filename']
            dest_path = os.path.join(export_dir, dest_filename)
            
            if os.path.exists(dest_path):
                # Add hash to filename if duplicate
                file_hash = hashlib.md5(filepath.encode()).hexdigest()[:8]
                name, ext = os.path.splitext(dest_filename)
                dest_filename = f"{name}_{file_hash}{ext}"
                dest_path = os.path.join(export_dir, dest_filename)
            
            shutil.copy2(filepath, dest_path)
            self.files_downloaded += 1
            log.debug(f"Downloaded: {dest_path}")
            
        except Exception as e:
            log.warning(f"Failed to download {filepath}: {e}")


class NFSpider:
    """Main orchestrator for NFS spidering"""
    
    def __init__(self, options: NFSpiderOptions):
        self.options = options
        self.setup_directories()
        self.file_filter = FileFilter(options)
        self.results = []
    
    def setup_directories(self):
        """Set up loot and log directories"""
        home = os.path.expanduser('~')
        base_dir = os.path.join(home, '.nfspider')
        
        if self.options.loot_dir:
            self.loot_dir = self.options.loot_dir
        else:
            self.loot_dir = os.path.join(base_dir, 'loot')
        
        self.log_dir = os.path.join(base_dir, 'logs')
        
        os.makedirs(self.loot_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Set up file logging
        log_file = os.path.join(
            self.log_dir, 
            f"nfspider_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        log.addHandler(file_handler)
    
    def run(self):
        """Run the spider"""
        log.info(f"NFSpider starting with {len(self.options.targets)} targets")
        log.info(f"Loot directory: {self.loot_dir}")
        
        # Build list of (server, export) pairs to spider
        work_items = []
        
        for target in self.options.targets:
            log.info(f"{Colors.BLUE}[*]{Colors.RESET} Enumerating exports on {target}")
            client = NFSClient(target, self.options)
            exports = client.get_exports()
            
            if not exports:
                log.warning(f"{Colors.YELLOW}[-]{Colors.RESET} No exports found on {target}")
                continue
            
            for export in exports:
                log.info(f"    Found export: {export}")
                work_items.append((target, export))
        
        if not work_items:
            log.error("No NFS exports found to spider")
            return
        
        log.info(f"\n{Colors.CYAN}[*]{Colors.RESET} Starting spider with {self.options.threads} threads")
        log.info(f"    Total exports to spider: {len(work_items)}")
        
        # Spider with thread pool
        with ThreadPoolExecutor(max_workers=self.options.threads) as executor:
            futures = {}
            
            for server, export in work_items:
                spiderling = Spiderling(
                    server, export, self.options, 
                    self.file_filter, self.loot_dir
                )
                future = executor.submit(spiderling.run)
                futures[future] = (server, export)
            
            for future in as_completed(futures):
                server, export = futures[future]
                try:
                    result = future.result()
                    self.results.append(result)
                except Exception as e:
                    log.error(f"Error spidering {server}:{export}: {e}")
        
        # Print summary
        self._print_summary()
    
    def _print_summary(self):
        """Print summary of results"""
        total_matches = sum(len(r['matches']) for r in self.results)
        total_downloads = sum(r['files_downloaded'] for r in self.results)
        total_errors = sum(len(r['errors']) for r in self.results)
        
        print(f"\n{'='*60}")
        print(f"{Colors.BOLD}NFSpider Summary{Colors.RESET}")
        print(f"{'='*60}")
        print(f"  Exports spidered: {len(self.results)}")
        print(f"  {Colors.GREEN}Files matched:{Colors.RESET} {total_matches}")
        print(f"  {Colors.CYAN}Files downloaded:{Colors.RESET} {total_downloads}")
        if total_errors:
            print(f"  {Colors.RED}Errors:{Colors.RESET} {total_errors}")
        print(f"\n  Loot saved to: {self.loot_dir}")
        print(f"{'='*60}\n")


def make_targets(target_str: str) -> List[str]:
    """Process target string into list of targets"""
    # Check if it's a file
    if os.path.isfile(target_str):
        targets = []
        with open(target_str, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        return targets
    
    # Single target
    return [target_str]


def main():
    """Main entry point"""
    banner = f"""{Colors.RED}
    _   __ ______ _____       _     __         
   / | / // ____// ___/____  (_)___/ /___  _____
  /  |/ // /_    \\__ \\/ __ \\/ / __  / _ \\/ ___/
 / /|  // __/   ___/ / /_/ / / /_/ /  __/ /    
/_/ |_//_/     /____/ .___/_/\\__,_/\\___/_/     
                   /_/                          
{Colors.RESET}
    NFS Share Spider - https://github.com/pathsec/NFSpider
    Inspired by MANSPIDER (blacklanternsecurity)
    """
    print(banner)
    
    parser = argparse.ArgumentParser(
        description='Spider NFS shares for sensitive files. '
                    'Matching files and logs are stored in $HOME/.nfspider. '
                    'All filters are case-insensitive.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Spider a single host for files with passwords in content
  nfspider 192.168.1.100 -c 'passw|secret|credential'
  
  # Spider multiple hosts for sensitive extensions
  nfspider hosts.txt -e pem key pfx kdbx
  
  # Search for config files with specific patterns
  nfspider 192.168.1.0/24 -f config -c 'password|api.?key|token'
  
  # Find SSH keys and certificates
  nfspider 10.0.0.5 -e pem ppk pub -f 'id_rsa|id_dsa|id_ed25519'
  
  # Search financial directories for account numbers
  nfspider share.corp.local --dirnames bank financ payment -c '[0-9]{10,}'
        """
    )
    
    # Targets
    parser.add_argument('targets', nargs='+', 
        help='IPs, hostnames, or files containing NFS targets')
    
    # Output options
    parser.add_argument('-l', '--loot-dir', default='',
        help='Loot directory (default: ~/.nfspider/loot)')
    parser.add_argument('-n', '--no-download', action='store_true',
        help="Don't download matching files, just report")
    parser.add_argument('-q', '--quiet', action='store_true',
        help="Don't display file content matches")
    
    # Spider options  
    parser.add_argument('-m', '--maxdepth', type=int, default=10,
        help='Maximum directory depth to spider (default: 10)')
    parser.add_argument('-t', '--threads', type=int, default=5,
        help='Number of concurrent threads (default: 5)')
    parser.add_argument('-s', '--max-filesize', type=str, default='10M',
        help='Maximum file size to process (default: 10M)')
    
    # Filter options
    parser.add_argument('-f', '--filenames', nargs='+', default=[],
        metavar='REGEX', help='Filename patterns to match (regex)')
    parser.add_argument('-e', '--extensions', nargs='+', default=[],
        metavar='EXT', help='File extensions to match')
    parser.add_argument('--exclude-extensions', nargs='+', default=[],
        metavar='EXT', help='File extensions to exclude')
    parser.add_argument('-c', '--content', nargs='+', default=[],
        metavar='REGEX', help='Content patterns to search (regex)')
    parser.add_argument('--dirnames', nargs='+', default=[],
        metavar='DIR', help='Only spider directories matching patterns')
    parser.add_argument('--exclude-dirnames', nargs='+', default=[],
        metavar='DIR', help='Directories to exclude')
    parser.add_argument('-o', '--or-logic', action='store_true',
        help='Use OR logic for filters (default: AND)')
    
    # NFS options
    parser.add_argument('--nfs-version', default='auto', 
        choices=['auto', '3', '4', '4.1', '4.2'],
        help='NFS version to use (default: auto)')
    parser.add_argument('--mount-options', default='',
        help='Additional mount options')
    parser.add_argument('--timeout', type=int, default=30,
        help='Timeout for NFS operations in seconds (default: 30)')
    
    parser.add_argument('-v', '--verbose', action='store_true',
        help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        log.setLevel(logging.DEBUG)
    
    # Parse file size
    size_str = args.max_filesize.upper()
    multipliers = {'K': 1024, 'M': 1024**2, 'G': 1024**3}
    if size_str[-1] in multipliers:
        max_size = int(size_str[:-1]) * multipliers[size_str[-1]]
    else:
        max_size = int(size_str)
    
    # Validate we have at least one filter
    if not (args.filenames or args.extensions or args.exclude_extensions or args.content):
        log.error("Please specify at least one of --filenames, --content, "
                 "--extensions, or --exclude-extensions")
        sys.exit(1)
    
    # Warn about OR logic with content
    if args.or_logic and args.content:
        log.warning('WARNING: "--or-logic" causes files to be content-searched '
                   'even if filename/extension filters do not match!')
    
    # Build target list
    targets = []
    for t in args.targets:
        targets.extend(make_targets(t))
    
    # Create options
    options = NFSpiderOptions(
        targets=targets,
        loot_dir=args.loot_dir,
        maxdepth=args.maxdepth,
        threads=args.threads,
        filenames=args.filenames,
        extensions=args.extensions,
        exclude_extensions=args.exclude_extensions,
        content=args.content,
        dirnames=args.dirnames,
        exclude_dirnames=args.exclude_dirnames,
        max_filesize=max_size,
        no_download=args.no_download,
        quiet=args.quiet,
        or_logic=args.or_logic,
        nfs_version=args.nfs_version,
        mount_options=args.mount_options,
        timeout=args.timeout,
    )
    
    # Run spider
    spider = NFSpider(options)
    spider.run()


if __name__ == '__main__':
    main()
