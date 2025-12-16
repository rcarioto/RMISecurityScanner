# RMI Security Scanner

A comprehensive Python tool for security testing Java RMI (Remote Method Invocation) services. The scanner can detect authentication requirements, test credentials, identify remote codebase vulnerabilities, and enumerate exposed Java objects.

## Features

### Core Security Testing
- **Connection Testing**: Test connectivity to Java RMI services with SSL/TLS support
- **Authentication Detection**: Automatically detect if authentication is required
- **Credential Brute Forcing**: Test common default credentials (admin:admin, admin:password, etc.)
- **Remote Codebase Detection**: Check if RMI services allow downloading classes from remote URLs
- **Remote Codebase Testing**: Actually test if remote codebase downloading works (security risk detection)
- **Object Enumeration**: List all Java objects exposed in the RMI registry
- **Detailed Error Reporting**: Comprehensive error messages with nested exception details
- **JSON Output**: Export scan results to JSON format for further analysis

### Advanced Features
- **SSL/TLS Support**: Test RMI services over encrypted connections
- **Timeout Configuration**: Configurable connection timeouts
- **Verbose Output**: Detailed diagnostic information
- **Multi-Host Scanning**: Scan multiple hosts from a file
- **Multi-Credential Testing**: Test multiple usernames and passwords from files
- **Error Analysis**: Detailed explanations of RMI errors and exceptions

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd <repository-directory>

# Make script executable
chmod +x RMISecurityScanner.py
```

### Requirements

- **Python 3.6+**: Standard library only (no external packages required)
- **Java JDK**: Required for full RMI functionality (OpenJDK 17 recommended)
  ```bash
  sudo apt install -y openjdk-17-jdk
  ```

## Usage

### Basic Usage
```bash
# Scan RMI service on default port (1099)
./RMISecurityScanner.py -H example.com

# Scan specific host and port
./RMISecurityScanner.py -H 192.168.1.100 -p 1099

# Scan with SSL/TLS
./RMISecurityScanner.py -H example.com -p 1099 --ssl

# Save results to JSON file
./RMISecurityScanner.py -H example.com -p 1099 -o results.json

# Verbose output
./RMISecurityScanner.py -H example.com -p 1099 -v
```

### Command Line Options
- `-H, --host HOST`: RMI server hostname or IP (required, or use --hosts-file)
- `--hosts-file FILE`: File containing list of hosts (one per line, format: host:port or host)
- `-p, --port PORT`: RMI server port (default: 1099, ignored if hosts-file specifies ports)
- `-s, --ssl`: Use SSL/TLS connection
- `-t, --timeout SECONDS`: Connection timeout in seconds (default: 5)
- `-u, --username USERNAME`: Single username to use for authentication
- `--usernames-file FILE`: File containing list of usernames to test (one per line)
- `--password PASSWORD`: Single password to test
- `--passwords-file FILE`: File containing list of passwords to test (one per line)
- `-o, --output FILE`: Output results to JSON file (for single host)
- `--output-dir DIR`: Output directory for multi-host scans (default: ./rmi_scan_results)
- `-v, --verbose`: Verbose output

### Advanced Usage

#### Multiple Hosts and Credentials
```bash
# Multiple hosts with single password
./RMISecurityScanner.py --hosts-file hosts.txt --password mypass

# Single host with password list
./RMISecurityScanner.py -H example.com --passwords-file passwords.txt

# All combinations: hosts, usernames, and passwords from files
./RMISecurityScanner.py --hosts-file hosts.txt --usernames-file usernames.txt --passwords-file passwords.txt

# Single host with username and password
./RMISecurityScanner.py -H example.com -u admin --password mypass
```

## Example Output

### Standard RMI Server Scan
```
[*] Scanning RMI service at example.com:1099 (SSL: False)
[*] Testing connection...
[+] Connection successful
[*] Checking for authentication...
[+] No authentication required
[*] Enumerating exposed objects...
[+] Found 1 exposed object(s):
    - Calculator
[*] Checking for remote codebase downloading...
[+] Remote codebase downloading appears to be disabled

============================================================
SCAN SUMMARY
============================================================
Host: example.com:1099
SSL: False
Connection: SUCCESS
Authentication Required: False
Remote Codebase Enabled: False
Exposed Objects: 1
  - Calculator
============================================================
```

### Authenticated RMI Server Scan
```
[*] Scanning RMI service at example.com:1099 (SSL: False)
[*] Testing connection...
[+] Connection successful
[*] Checking for authentication...
[+] Authentication is required
[*] Attempting to authenticate with common credentials...
[*] Trying: admin:admin
[*] Trying: admin:password
[+] Authentication successful with: admin:password
```

### Remote Codebase Detection
```
[*] Checking for remote codebase downloading...
[!] WARNING: Remote codebase downloading may be enabled
[*] Testing if remote codebase downloading actually works...
[!] CRITICAL: Remote codebase downloading is WORKING!
[!] Classes can be downloaded from remote URLs - SECURITY RISK!
    [+] Calculator: Successfully loaded from remote codebase
        Codebase URL: http://example.com/classes/
```

## Security Features

### What Gets Tested
1. **Connection**: Can we connect to the RMI service?
2. **Authentication**: Is authentication required?
3. **Credential Brute Force**: Try common passwords (admin:admin, admin:password, etc.)
4. **Remote Codebase**: Can classes be downloaded remotely? (Security risk)
5. **Object Enumeration**: What objects are exposed?

### Common Default Credentials Tested
- `admin:admin`
- `admin:password`
- `user:password`
- `guest:guest`
- `test:test`
- `rmi:rmi`
- Empty credentials
- And more...

## Project Structure

```
.
├── RMISecurityScanner.py            # Main RMI security scanner
├── README.md                         # This file
├── LICENSE                           # GPL v3.0 License
└── requirements.txt                  # Python dependencies
```

## Requirements

### Python Dependencies
- Python 3.6+
- Standard library only (no external packages required)

### System Dependencies
- **Java JDK** (for full functionality)
  - Required for RMI enumeration and testing
  - Test with: `java -version` and `javac -version`
  - Recommended: OpenJDK 17
  - Install with: `sudo apt install -y openjdk-17-jdk`

### Optional Tools
- `keytool` (for SSL connections, usually comes with JDK)
- `lsof` or `netstat` (for port checking)

## Known Limitations

### RMI Authentication
The RMI security scanner can detect authentication requirements and attempt credential brute forcing. However, due to JVM-local system properties, authentication may not succeed when testing against custom authenticated RMI servers that rely on system properties for authentication. This is a known limitation of RMI authentication mechanisms.

**The scanner correctly:**
- Detects authentication requirements
- Attempts credential brute forcing
- Reports authentication status

**Authentication may fail when:**
- Server uses JVM-local authentication mechanisms
- System properties don't transmit over RMI calls

This is expected behavior and demonstrates the scanner's detection capabilities.

## Troubleshooting

### Java Not Found
```bash
sudo apt update
sudo apt install -y openjdk-17-jdk
java -version
javac -version
```

### Port Already in Use
```bash
# Find process using port 1099
sudo lsof -i :1099
# Or
sudo netstat -tulpn | grep 1099

# Kill the process if needed
sudo kill <PID>
```

### Permission Denied
```bash
chmod +x RMISecurityScanner.py
```

### Connection Timeouts
- Increase timeout: `-t 10` or higher
- Check firewall rules
- Verify host and port are correct
- Test with `telnet` or `nc`: `telnet host port`

## Documentation

For detailed usage information, run:
```bash
./RMISecurityScanner.py --help
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before testing any RMI service. The authors are not responsible for any misuse of this tool.

## Author

Ray Carioto <raymond.carioto@gmail.com>

## Version History

- **v1.0.0**: Initial release
  - RMI security scanner with authentication detection
  - Remote codebase download testing
  - Object enumeration capabilities
  - Multi-host and multi-credential scanning support
  - Comprehensive documentation
