# NFSpider

> Spider NFS shares for sensitive files

NFSpider is an NFS share enumeration and file extraction tool. It automatically crawls NFS exports across network targets to identify and retrieve files matching specified criteria.

**Inspired by [MANSPIDER](https://github.com/blacklanternsecurity/MANSPIDER)** - this tool follows similar design patterns and CLI conventions.

## Features

- 🔍 **Multi-threaded scanning** - Concurrent crawling of multiple NFS exports
- 📝 **Flexible filtering** - Search by filename, extension, or file content (regex supported)
- 📁 **Automatic loot organization** - Downloaded files organized by server/export
- 🎯 **Directory targeting** - Focus on specific directory names
- ⚡ **Efficient** - Configurable depth limits, file size limits, and timeouts
- 📊 **Detailed logging** - Full audit trail of discovered files

## Requirements

- Python 3.8+
- `nfs-common` package (for `showmount` and `mount.nfs`)
- Root/sudo privileges (for NFS mounting)

### Installation

```bash
# Install NFS utilities (Debian/Ubuntu)
sudo apt install nfs-common

# Install NFSpider
chmod +x nfspider.py

# Or install as a module
pip install -e .
```

## Usage

```
usage: nfspider.py [-h] [-l LOOT_DIR] [-n] [-q] [-m MAXDEPTH] [-t THREADS]
                   [-s MAX_FILESIZE] [-f REGEX [REGEX ...]]
                   [-e EXT [EXT ...]] [--exclude-extensions EXT [EXT ...]]
                   [-c REGEX [REGEX ...]] [--dirnames DIR [DIR ...]]
                   [--exclude-dirnames DIR [DIR ...]] [-o]
                   [--nfs-version {3,4,4.1,4.2}] [--mount-options OPTIONS]
                   [--timeout TIMEOUT] [-v]
                   targets [targets ...]
```

### Options

| Option                 | Description                                                 |
| ---------------------- | ----------------------------------------------------------- |
| `targets`              | IPs, hostnames, or files containing NFS targets             |
| `-l, --loot-dir`       | Directory to save matched files (default: ~/.nfspider/loot) |
| `-n, --no-download`    | Report matches without downloading                          |
| `-q, --quiet`          | Don't display content match snippets                        |
| `-m, --maxdepth`       | Maximum directory depth (default: 10)                       |
| `-t, --threads`        | Concurrent threads (default: 5)                             |
| `-s, --max-filesize`   | Max file size to process (default: 10M)                     |
| `-f, --filenames`      | Filename patterns to match (regex)                          |
| `-e, --extensions`     | File extensions to match                                    |
| `--exclude-extensions` | Extensions to skip                                          |
| `-c, --content`        | Content patterns to search (regex)                          |
| `--dirnames`           | Only spider matching directories                            |
| `--exclude-dirnames`   | Directories to skip                                         |
| `-o, --or-logic`       | Match ANY filter (default: ALL must match)                  |
| `--nfs-version`        | NFS protocol version (default: 3)                           |
| `--timeout`            | Operation timeout in seconds (default: 30)                  |
| `-v, --verbose`        | Enable debug output                                         |

## Examples

### Basic Credential Hunting

Search for files containing passwords or credentials:

```bash
sudo ./nfspider.py 192.168.1.100 -c 'passw|secret|credential|api.?key'
```

### Search for Sensitive Extensions

Find key files, certificates, and password databases:

```bash
sudo ./nfspider.py 192.168.1.0/24 -e pem key pfx p12 kdbx kdb ppk
```

### Configuration File Analysis

Find config files and search for sensitive content:

```bash
sudo ./nfspider.py targets.txt -f 'config|\.env|settings' -c 'password|token|secret'
```

### SSH Key Discovery

```bash
sudo ./nfspider.py 10.0.0.5 -f 'id_rsa|id_dsa|id_ed25519|authorized_keys' -e '' -o
```

### Financial Data Search

Search finance-related directories for account numbers:

```bash
sudo ./nfspider.py share.corp.local \
    --dirnames bank financ payment invoice \
    -c '[0-9]{10,}' \
    -e xlsx csv pdf
```

### Database Credentials

```bash
sudo ./nfspider.py 192.168.1.50 \
    -f 'database|db\.conf|mysql|postgres|mongo' \
    -c 'password|passwd|pwd'
```

### Backup File Discovery

```bash
sudo ./nfspider.py datacenter.internal \
    -e bak backup sql dump tar gz zip \
    -f 'backup|dump|export|archive'
```

### Certificates and Keys

```bash
sudo ./nfspider.py 10.10.10.0/24 \
    -e pem crt cer key pfx p12 jks \
    -c 'BEGIN.*(PRIVATE|CERTIFICATE)'
```

### Using Target Files

Create a file with one target per line:

```bash
# targets.txt
192.168.1.10
192.168.1.20
fileserver.corp.local
```

Then run:

```bash
sudo ./nfspider.py targets.txt -c 'password'
```

### Dry Run (No Download)

See what would match without downloading:

```bash
sudo ./nfspider.py 192.168.1.100 -e conf cfg ini -n
```

## Output Structure

```
~/.nfspider/
├── loot/
│   └── 192.168.1.100/
│       ├── _export_data/
│       │   ├── config.ini
│       │   └── database.conf
│       └── _home/
│           └── .ssh/
│               └── id_rsa
└── logs/
    └── nfspider_20240115_143052.log
```

## Filter Logic

By default, NFSpider uses **AND logic** - all specified filters must match:

```bash
# File must have .conf extension AND contain "password"
sudo ./nfspider.py target -e conf -c password
```

With `-o/--or-logic`, **OR logic** is used - any filter can match:

```bash
# File has .conf extension OR contains "password"
sudo ./nfspider.py target -e conf -c password -o
```

## Common Sensitive Patterns

### Credentials

```
-c 'passw|secret|credential|token|api.?key|auth'
```

### Connection Strings

```
-c 'mysql://|postgres://|mongodb://|redis://|jdbc:'
```

### AWS/Cloud

```
-c 'AKIA|aws_access|aws_secret|AZURE|GOOGLE'
```

### Private Keys

```
-c 'BEGIN.*(RSA|DSA|EC|OPENSSH|PRIVATE)'
```

## Tips

1. **Start broad, then narrow** - Begin with extension filters, then add content filters
2. **Use `--no-download` first** - Preview matches before downloading
3. **Mind the depth** - Deep directories can slow scanning; use `-m` to limit
4. **Check permissions** - You may need root for NFS mounting
5. **Respect scope** - Only test systems you're authorized to assess

## Troubleshooting

### "showmount not found"

```bash
sudo apt install nfs-common
```

### "Permission denied" on mount

```bash
# Run with sudo
sudo ./nfspider.py target -c password
```

### Timeouts

```bash
# Increase timeout and use NFS v3
./nfspider.py target --timeout 60 --nfs-version 3
```

### "No exports found"

The target may not have NFS enabled, or exports may be restricted by IP. Check with:

```bash
showmount -e <target>
```

## Legal Disclaimer

This tool is intended for authorized security testing only. Always ensure you have explicit written permission before scanning or accessing any systems. Unauthorized access to computer systems is illegal.

## Credits

- Inspired by [MANSPIDER](https://github.com/blacklanternsecurity/MANSPIDER) by Black Lantern Security
- Architecture patterns borrowed from manspider's excellent design
