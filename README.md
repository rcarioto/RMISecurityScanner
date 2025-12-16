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
- **Comprehensive CVE Detection**: Database of 21+ CVEs including RMI-specific, deserialization, and Java version vulnerabilities
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

#### Security Testing Options
```bash
# Run only safe read-only tests (default)
./RMISecurityScanner.py -H example.com --test-safe-only

# Run specific security tests
./RMISecurityScanner.py -H example.com --test-security-manager --test-serialization-filter

# Run CVE detection
./RMISecurityScanner.py -H example.com --test-cve-detection

# Run all security tests (WARNING: Includes potentially harmful tests)
./RMISecurityScanner.py -H example.com --test-all

# Run specific potentially harmful tests (use with caution)
./RMISecurityScanner.py -H example.com --test-registry-manipulation --test-dos
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

### CVE Detection
```
[*] Checking for known CVEs...
[!] Potential CVEs detected: 5
    [!] CVE-2017-3241 (CRITICAL) - RMI Registry allows remote code execution via deserialization
        Type: RMI, Fixed in: Java 8u121+
    [!] CVE-2015-4902 (CRITICAL) - Java deserialization vulnerability - remote code execution
        Type: Deserialization, Fixed in: JEP 290 (Java 9+) or serialization filter
    [!] CVE-2019-2684 (HIGH) - RMI Registry vulnerability allowing unauthorized access
        Type: RMI, Fixed in: Java 8u212+
    [*] CVE-2018-11776 (HIGH) - Multiple security vulnerabilities in Java 8
        Type: General, Fixed in: Java 8u191+
    [*] CVE-NO-SECURITY-MANAGER (MEDIUM) - No security manager configured - reduced security controls
        Type: Configuration, Fixed in: Enable security manager
```

## Security Features

### What Gets Tested (Default - Safe Tests Only)
By default, the scanner performs only safe, read-only tests:
1. **Connection**: Can we connect to the RMI service?
2. **Authentication**: Is authentication required?
3. **Credential Brute Force**: Try common passwords (admin:admin, admin:password, etc.)
4. **Remote Codebase**: Can classes be downloaded remotely? (Security risk)
5. **Object Enumeration**: What objects are exposed?

### Optional Security Tests

The scanner includes many additional security tests that are **disabled by default**. These can be enabled individually or all at once using command-line flags. See the [Security Test Risk Levels](#security-test-risk-levels) section below for details.

**Available Test Flags:**
- `--test-deserialization` - Test for deserialization vulnerabilities
- `--test-registry-manipulation` - Test registry bind/rebind/unbind operations
- `--test-method-invocation` - Test method invocation on exposed objects
- `--test-security-manager` - Detect security manager configuration
- `--test-serialization-filter` - Detect serialization filter configuration
- `--test-dgc` - Test DGC (Distributed Garbage Collection) endpoint
- `--test-activation` - Test RMI activation system
- `--test-information-disclosure` - Gather information disclosure
- `--test-ssl-tls` - Test SSL/TLS configuration
- `--test-cve-detection` - Comprehensive CVE detection (21+ CVEs, version & config-based)
- `--test-network-protocol` - Test network protocol level issues
- `--test-auth-bypass` - Test authentication bypass techniques
- `--test-codebase-validation` - Validate codebase URLs
- `--test-dos` - Test for DoS vulnerabilities
- `--test-logging` - Detect logging configuration

**Convenience Flags:**
- `--test-all` - Run all security tests (WARNING: Includes potentially harmful tests)
- `--test-safe-only` - Run only safe read-only tests (default behavior)

## Security Test Risk Levels

### High Risk Tests (Potentially Harmful)
These tests can cause harm to the remote server and should only be used with explicit authorization:

1. **DoS Testing** (`--test-dos`)
   - **Risk Level**: HIGH
   - **What it does**: Creates multiple simultaneous connections to test connection limits
   - **Potential Impact**: May cause service disruption or denial of service on vulnerable servers
   - **Use Case**: Testing DoS protection mechanisms

2. **Registry Manipulation Testing** (`--test-registry-manipulation`)
   - **Risk Level**: HIGH
   - **What it does**: Attempts to bind/rebind/unbind objects in the RMI registry
   - **Potential Impact**: Modifies the registry by adding test objects (names like `TEST_BIND_*`)
   - **Use Case**: Testing if registry write access is properly restricted

### Medium Risk Tests
These tests may cause unintended side effects:

3. **Method Invocation Testing** (`--test-method-invocation`)
   - **Risk Level**: MEDIUM
   - **What it does**: Invokes methods on discovered remote objects (methods with no parameters)
   - **Potential Impact**: If methods are destructive (delete files, shutdown services, etc.), this could cause harm
   - **Use Case**: Testing what methods are callable and what they return

4. **Deserialization Vulnerability Testing** (`--test-deserialization`)
   - **Risk Level**: MEDIUM
   - **What it does**: Attempts to deserialize objects from the registry
   - **Potential Impact**: If the service is vulnerable to deserialization attacks, this could trigger code execution
   - **Note**: Current implementation doesn't send malicious payloads, but deserialization itself can be risky
   - **Use Case**: Testing if services properly handle deserialization

### Low Risk Tests (Safe - Read-Only)
These tests are safe and perform only read-only operations:

5. **Security Manager Detection** (`--test-security-manager`)
   - **Risk Level**: LOW
   - **What it does**: Checks if a security manager is configured
   - **Impact**: Read-only, no modifications

6. **Serialization Filter Detection** (`--test-serialization-filter`)
   - **Risk Level**: LOW
   - **What it does**: Detects if serialization filters (JEP 290) are configured
   - **Impact**: Read-only, no modifications

7. **DGC Testing** (`--test-dgc`)
   - **Risk Level**: LOW
   - **What it does**: Tests if DGC endpoint is accessible (connection test only)
   - **Impact**: Minimal, just checks port accessibility

8. **Activation System Testing** (`--test-activation`)
   - **Risk Level**: LOW
   - **What it does**: Tests if RMI activation daemon is accessible (connection test only)
   - **Impact**: Minimal, just checks port accessibility

9. **Information Disclosure** (`--test-information-disclosure`)
   - **Risk Level**: LOW
   - **What it does**: Gathers Java version, OS info, and error messages
   - **Impact**: Read-only, information gathering

10. **SSL/TLS Configuration Testing** (`--test-ssl-tls`)
    - **Risk Level**: LOW
    - **What it does**: Tests SSL/TLS configuration for weak protocols/ciphers
    - **Impact**: Read-only, connection analysis

11. **CVE Detection** (`--test-cve-detection`)
    - **Risk Level**: LOW
    - **What it does**: Comprehensive CVE detection based on Java version and configuration
    - **Impact**: Read-only, version and configuration analysis
    - **Features**:
      - **21+ CVEs in database** including RMI-specific, deserialization, and general Java CVEs
      - **Version-based detection**: Checks Java 8, 11, 17 versions against known vulnerabilities
      - **Configuration-based detection**: Identifies CVEs based on security settings (serialization filters, security manager, etc.)
      - **RMI-specific CVEs**: CVE-2017-3241, CVE-2019-2684, CVE-2020-1472
      - **Severity classification**: CRITICAL, HIGH, MEDIUM, LOW
      - **Detailed information**: CVE ID, description, severity, type, and fix version

12. **Network Protocol Testing** (`--test-network-protocol`)
    - **Risk Level**: LOW
    - **What it does**: Tests protocol version negotiation
    - **Impact**: Minimal, protocol handshake only

13. **Authentication Bypass Testing** (`--test-auth-bypass`)
    - **Risk Level**: LOW
    - **What it does**: Tests authentication bypass techniques with null credentials
    - **Impact**: Read-only, authentication testing

14. **Codebase URL Validation** (`--test-codebase-validation`)
    - **Risk Level**: LOW
    - **What it does**: Validates codebase URL format
    - **Impact**: Read-only, URL parsing

15. **Logging Detection** (`--test-logging`)
    - **Risk Level**: LOW
    - **What it does**: Attempts to detect if operations are logged (requires server-side analysis)
    - **Impact**: Read-only, detection only

### Default Behavior
By default, the scanner runs only the core safe tests (connection, authentication, codebase detection, object enumeration). All optional security tests are disabled unless explicitly enabled with flags.

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
  - Comprehensive CVE detection (21+ CVEs, version & configuration-based)
  - Comprehensive documentation
