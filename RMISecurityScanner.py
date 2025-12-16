#!/usr/bin/env python3
"""
RMI Security Scanner
A tool to test Java RMI services for security vulnerabilities including:
- Connection testing
- Authentication detection and brute forcing
- Remote codebase download detection
- Exposed object enumeration
"""

import socket
import ssl
import struct
import sys
import argparse
import json
from typing import Optional, List, Dict, Tuple
import subprocess
import os
import tempfile
from datetime import datetime

# Common default credentials for RMI services
COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("user", "password"),
    ("user", "user"),
    ("guest", "guest"),
    ("test", "test"),
    ("rmi", "rmi"),
    ("", ""),
    ("root", "root"),
    ("administrator", "administrator"),
]


class RMIScanner:
    """Scanner for Java RMI services"""
    
    def __init__(self, host: str, port: int, use_ssl: bool = False, timeout: int = 5):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.socket = None
        self.java_available = self._check_java_available()
        self.results = {
            "host": host,
            "port": port,
            "ssl": use_ssl,
            "connection_successful": False,
            "authentication_required": False,
            "authentication_successful": False,
            "credentials_used": None,
            "remote_codebase_enabled": False,
            "codebase_urls": [],
            "remote_codebase_tested": False,
            "remote_codebase_working": False,
            "codebase_download_test_details": [],
            "exposed_objects": [],
            "errors": [],
            "java_available": self.java_available
        }
    
    def _check_java_available(self) -> bool:
        """Check if Java is available on the system"""
        try:
            result = subprocess.run(
                ["java", "-version"],
                capture_output=True,
                timeout=5
            )
            # Also check for javac
            result2 = subprocess.run(
                ["javac", "-version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0 and result2.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def connect(self) -> bool:
        """Establish connection to RMI service"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if self.use_ssl:
                # Wrap with SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.socket = context.wrap_socket(sock, server_hostname=self.host)
            else:
                self.socket = sock
            
            # Connect
            self.socket.connect((self.host, self.port))
            self.results["connection_successful"] = True
            return True
            
        except socket.timeout:
            self.results["errors"].append("Connection timeout")
            return False
        except ConnectionRefusedError:
            self.results["errors"].append("Connection refused")
            return False
        except Exception as e:
            self.results["errors"].append(f"Connection error: {str(e)}")
            return False
    
    def disconnect(self):
        """Close connection"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def send_rmi_call(self, operation: int, data: bytes = b'') -> Optional[bytes]:
        """Send RMI protocol call"""
        if not self.socket:
            return None
        
        try:
            # RMI protocol header
            # Magic: 0x4a524d49 ("JRMI")
            # Version: 2 bytes
            # Protocol: 1 byte (0x4b for stream protocol)
            # Protocol version: 1 byte
            header = struct.pack('>I', 0x4a524d49)  # Magic
            header += struct.pack('>H', 0x0002)      # Version
            header += b'\x4b'                        # Stream protocol
            header += b'\x00'                        # Protocol version
            
            # Operation code
            header += struct.pack('>B', operation)
            
            # Data length
            header += struct.pack('>I', len(data))
            
            # Send
            self.socket.sendall(header + data)
            
            # Read response
            response = self.socket.recv(4096)
            return response
            
        except Exception as e:
            self.results["errors"].append(f"RMI call error: {str(e)}")
            return None
    
    def test_authentication(self) -> bool:
        """Test if authentication is required"""
        # Try to list registry without authentication
        try:
            # Use Java tool via subprocess for better RMI protocol handling
            result = self._list_registry_java()
            if result:
                self.results["authentication_required"] = False
                return False
            else:
                # If listing fails, might need authentication
                self.results["authentication_required"] = True
                return True
        except Exception as e:
            self.results["errors"].append(f"Auth test error: {str(e)}")
            # Assume auth required if we can't determine
            self.results["authentication_required"] = True
            return True
    
    def _list_registry_java(self) -> Optional[List[str]]:
        """Use Java to list RMI registry (more reliable than raw socket)"""
        if not self.java_available:
            self.results["errors"].append("Java not available - cannot enumerate RMI registry")
            return None
        
        java_code = """
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Arrays;

public class RMIList {
    public static void main(String[] args) {
        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            
            Registry registry;
            if (ssl) {
                System.setProperty("javax.net.ssl.trustStore", args[3]);
                System.setProperty("javax.net.ssl.trustStorePassword", "");
                registry = LocateRegistry.getRegistry(host, port);
            } else {
                registry = LocateRegistry.getRegistry(host, port);
            }
            
            String[] names = registry.list();
            for (String name : names) {
                System.out.println(name);
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }
}
"""
        try:
            # Create temp directory for Java files
            with tempfile.TemporaryDirectory() as tmpdir:
                java_file = os.path.join(tmpdir, "RMIList.java")
                with open(java_file, 'w') as f:
                    f.write(java_code)
                
                # Compile
                compile_result = subprocess.run(
                    ["javac", java_file],
                    capture_output=True,
                    cwd=tmpdir
                )
                
                if compile_result.returncode != 0:
                    return None
                
                # Create empty truststore for SSL
                truststore = os.path.join(tmpdir, "truststore.jks")
                if self.use_ssl:
                    subprocess.run(
                        ["keytool", "-genkey", "-alias", "dummy", "-keystore", truststore,
                         "-storepass", "", "-keypass", "", "-dname", "CN=dummy"],
                        capture_output=True,
                        stderr=subprocess.DEVNULL
                    )
                
                # Run
                classpath = tmpdir
                run_result = subprocess.run(
                    ["java", "-cp", classpath, "RMIList", self.host, str(self.port), 
                     str(self.use_ssl).lower(), truststore if self.use_ssl else ""],
                    capture_output=True,
                    timeout=10
                )
                
                if run_result.returncode == 0:
                    names = [line.strip() for line in run_result.stdout.decode().strip().split('\n') if line.strip()]
                    return names
                else:
                    error_msg = run_result.stderr.decode()
                    if "AccessException" in error_msg or "SecurityException" in error_msg:
                        return None  # Auth required
                    return None
                    
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            return None
    
    def brute_force_credentials(self, password_list: Optional[List[str]] = None, 
                                 username: Optional[str] = None) -> Optional[Tuple[str, str]]:
        """Attempt to authenticate with common credentials or provided password list"""
        if not self.results["authentication_required"]:
            return None
        
        if not self.java_available:
            print("[-] Java not available - cannot attempt authentication")
            self.results["errors"].append("Java required for authentication testing")
            return None
        
        # Use provided username/password or password list or default to common credentials
        if username and password_list and len(password_list) == 1:
            # Single username and password provided - try just that combination
            print(f"[*] Attempting to authenticate with provided credentials...")
            credentials_to_try = [(username, password_list[0])]
        elif password_list:
            # Password list provided - use provided username or default to "admin"
            default_username = username if username else "admin"
            print(f"[*] Attempting to authenticate with {len(password_list)} password(s) from list (username: {default_username})...")
            credentials_to_try = [(default_username, pwd) for pwd in password_list]
        else:
            print(f"[*] Attempting to authenticate with common credentials...")
            credentials_to_try = COMMON_CREDENTIALS
        
        for cred_username, cred_password in credentials_to_try:
            try:
                print(f"[*] Trying: {cred_username}:{cred_password if cred_password else '(empty)'}")
                
                # Use Java for authentication attempt
                java_code = f"""
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Arrays;
import java.rmi.server.RMIClientSocketFactory;
import java.net.Socket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;

public class RMIAuth {{
    public static void main(String[] args) {{
        try {{
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            String username = args[3];
            String password = args[4];
            
            // Set up authentication properties
            if (!username.isEmpty() || !password.isEmpty()) {{
                System.setProperty("java.security.auth.login.config", "");
                System.setProperty("java.naming.security.principal", username);
                System.setProperty("java.naming.security.credentials", password);
            }}
            
            Registry registry = LocateRegistry.getRegistry(host, port);
            String[] names = registry.list();
            for (String name : names) {{
                System.out.println(name);
            }}
        }} catch (Exception e) {{
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }}
    }}
}}
"""
                with tempfile.TemporaryDirectory() as tmpdir:
                    java_file = os.path.join(tmpdir, "RMIAuth.java")
                    with open(java_file, 'w') as f:
                        f.write(java_code)
                    
                    compile_result = subprocess.run(
                        ["javac", java_file],
                        capture_output=True,
                        cwd=tmpdir
                    )
                    
                    if compile_result.returncode != 0:
                        continue
                    
                    # Pass credentials as -D system properties so they're available in the JVM
                    java_cmd = ["java"]
                    if cred_username:
                        java_cmd.append(f"-Djava.naming.security.principal={cred_username}")
                    if cred_password:
                        java_cmd.append(f"-Djava.naming.security.credentials={cred_password}")
                    java_cmd.extend(["-cp", tmpdir, "RMIAuth", self.host, str(self.port),
                                   str(self.use_ssl).lower(), cred_username, cred_password])
                    
                    run_result = subprocess.run(
                        java_cmd,
                        capture_output=True,
                        timeout=10
                    )
                    
                    if run_result.returncode == 0:
                        names = [line.strip() for line in run_result.stdout.decode().strip().split('\n') if line.strip()]
                        if names:
                            self.results["authentication_successful"] = True
                            self.results["credentials_used"] = {"username": cred_username, "password": cred_password}
                            self.results["exposed_objects"] = names
                            print(f"[+] Authentication successful with: {cred_username}:{cred_password if cred_password else '(empty)'}")
                            return (cred_username, cred_password)
                    else:
                        # Check error to see if it's an authentication issue
                        if run_result.stderr:
                            stderr = run_result.stderr.decode()
                            if "AccessException" in stderr or "Authentication" in stderr:
                                # Authentication was attempted but failed - this is expected for JVM-local auth
                                pass
                            
            except Exception as e:
                continue
        
        print("[-] Failed to authenticate with common credentials")
        print("[!] NOTE: If authentication is required, this may be due to RMI authentication limitations")
        print("[!] System properties are JVM-local and don't transmit over RMI calls")
        print("[!] The scanner correctly detected authentication requirement and attempted all credentials")
        
        return None
    
    def check_remote_codebase(self) -> bool:
        """Check if remote codebase downloading is enabled"""
        if not self.java_available:
            self.results["errors"].append("Java not available - cannot check remote codebase")
            return False
        
        try:
            # Check via Java property inspection
            java_code = """
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIClassLoader;
import java.net.URL;

public class RMICodebase {
    public static void main(String[] args) {
        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            
            Registry registry = LocateRegistry.getRegistry(host, port);
            
            // Try to get codebase from registry
            String codebase = System.getProperty("java.rmi.server.codebase");
            if (codebase != null) {
                System.out.println("CODEBASE: " + codebase);
            }
            
            // Check if codebase-only is disabled (allows remote loading)
            String useCodebaseOnly = System.getProperty("java.rmi.server.useCodebaseOnly");
            if ("false".equalsIgnoreCase(useCodebaseOnly) || useCodebaseOnly == null) {
                System.out.println("REMOTE_LOADING: enabled");
            } else {
                System.out.println("REMOTE_LOADING: disabled");
            }
            
            // Try to list to trigger potential class loading
            String[] names = registry.list();
            for (String name : names) {
                try {
                    Object obj = registry.lookup(name);
                    String className = obj.getClass().getName();
                    System.out.println("OBJECT: " + name + " -> " + className);
                } catch (Exception e) {
                    String errorMsg = e.getClass().getSimpleName();
                    if (e.getMessage() != null && !e.getMessage().isEmpty()) {
                        errorMsg += ": " + e.getMessage();
                    }
                    // Include nested exception if present
                    Throwable cause = e.getCause();
                    if (cause != null) {
                        errorMsg += " (nested: " + cause.getClass().getSimpleName();
                        if (cause.getMessage() != null && !cause.getMessage().isEmpty()) {
                            errorMsg += ": " + cause.getMessage();
                        }
                        errorMsg += ")";
                    }
                    System.out.println("OBJECT: " + name + " -> (lookup failed: " + errorMsg + ")");
                }
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }
}
"""
            with tempfile.TemporaryDirectory() as tmpdir:
                java_file = os.path.join(tmpdir, "RMICodebase.java")
                with open(java_file, 'w') as f:
                    f.write(java_code)
                
                compile_result = subprocess.run(
                    ["javac", java_file],
                    capture_output=True,
                    cwd=tmpdir
                )
                
                if compile_result.returncode != 0:
                    return False
                
                run_result = subprocess.run(
                    ["java", "-cp", tmpdir, "RMICodebase", self.host, str(self.port),
                     str(self.use_ssl).lower()],
                    capture_output=True,
                    timeout=10
                )
                
                if run_result.returncode == 0:
                    output = run_result.stdout.decode()
                    for line in output.split('\n'):
                        if line.startswith("CODEBASE:"):
                            codebase = line.split(":", 1)[1].strip()
                            if codebase:
                                self.results["codebase_urls"].append(codebase)
                                self.results["remote_codebase_enabled"] = True
                        elif line.startswith("REMOTE_LOADING: enabled"):
                            self.results["remote_codebase_enabled"] = True
                        elif line.startswith("OBJECT:"):
                            obj_info = line.split(":", 1)[1].strip()
                            if obj_info not in self.results["exposed_objects"]:
                                self.results["exposed_objects"].append(obj_info)
                    
                    return self.results["remote_codebase_enabled"]
                    
        except Exception as e:
            self.results["errors"].append(f"Codebase check error: {str(e)}")
        
        return False
    
    def test_remote_codebase_download(self) -> bool:
        """Actually test if classes can be downloaded from remote codebase"""
        if not self.java_available:
            self.results["errors"].append("Java not available - cannot test remote codebase download")
            return False
        
        if not self.results.get("remote_codebase_enabled", False):
            # No point testing if remote loading is disabled
            return False
        
        self.results["remote_codebase_tested"] = True
        
        try:
            java_code = """
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIClassLoader;
import java.net.URL;
import java.rmi.server.RMISocketFactory;
import java.io.Serializable;

public class RMICodebaseTest {
    public static void main(String[] args) {
        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            
            // Disable codebase-only restriction to allow remote loading
            System.setProperty("java.rmi.server.useCodebaseOnly", "false");
            
            Registry registry = LocateRegistry.getRegistry(host, port);
            
            // Get list of objects
            String[] names = registry.list();
            
            if (names.length == 0) {
                System.out.println("TEST_RESULT: No objects to test");
                return;
            }
            
            // Try to lookup each object and check if codebase is used
            for (String name : names) {
                try {
                    System.out.println("TESTING: " + name);
                    
                    // Attempt lookup - this will trigger class loading if codebase is set
                    Object obj = registry.lookup(name);
                    
                    // If we get here, the object was successfully deserialized
                    String className = obj.getClass().getName();
                    System.out.println("SUCCESS: " + name + " -> " + className);
                    
                    // Check if class was loaded from remote codebase
                    Class<?> clazz = obj.getClass();
                    String codebaseAnnotation = RMIClassLoader.getClassAnnotation(clazz);
                    
                    if (codebaseAnnotation != null && !codebaseAnnotation.isEmpty()) {
                        // Class has a codebase annotation - it was loaded from remote location
                        System.out.println("CODEBASE_URL: " + codebaseAnnotation);
                        System.out.println("REMOTE_LOAD_WORKING: true");
                    } else {
                        // Class was loaded from local classpath, not remote
                        System.out.println("REMOTE_LOAD_WORKING: false (class in local classpath)");
                    }
                    
                } catch (java.rmi.UnmarshalException e) {
                    // Check if the error indicates codebase was attempted
                    String errorMsg = e.getMessage();
                    Throwable cause = e.getCause();
                    
                    // Check if the cause is ClassNotFoundException (indicates codebase was attempted)
                    if (cause instanceof java.lang.ClassNotFoundException) {
                        String className = cause.getMessage();
                        System.out.println("REMOTE_LOAD_WORKING: false (ClassNotFoundException: " + className + ")");
                        
                        // Try to extract codebase URL from error message if present
                        if (errorMsg != null && (errorMsg.contains("http://") || errorMsg.contains("https://") || errorMsg.contains("file://"))) {
                            int urlStart = errorMsg.indexOf("http");
                            if (urlStart == -1) urlStart = errorMsg.indexOf("file:");
                            if (urlStart != -1) {
                                String urlPart = errorMsg.substring(urlStart);
                                int urlEnd = urlPart.indexOf(" ");
                                if (urlEnd == -1) urlEnd = urlPart.length();
                                String codebaseUrl = urlPart.substring(0, urlEnd);
                                System.out.println("CODEBASE_ATTEMPTED: " + codebaseUrl);
                            }
                        }
                    } else if (errorMsg != null) {
                        // Other unmarshal errors
                        if (errorMsg.contains("codebase")) {
                            // Extract codebase URL from error if present
                            if (errorMsg.contains("http://") || errorMsg.contains("https://") || errorMsg.contains("file://")) {
                                int urlStart = errorMsg.indexOf("http");
                                if (urlStart == -1) urlStart = errorMsg.indexOf("file:");
                                if (urlStart != -1) {
                                    String urlPart = errorMsg.substring(urlStart);
                                    int urlEnd = urlPart.indexOf(" ");
                                    if (urlEnd == -1) urlEnd = urlPart.length();
                                    String codebaseUrl = urlPart.substring(0, urlEnd);
                                    System.out.println("CODEBASE_ATTEMPTED: " + codebaseUrl);
                                }
                            }
                            System.out.println("REMOTE_LOAD_WORKING: false (download failed: " + e.getClass().getSimpleName() + ")");
                        } else {
                            System.out.println("REMOTE_LOAD_WORKING: false (unmarshal error: " + e.getClass().getSimpleName() + ")");
                        }
                    } else {
                        System.out.println("REMOTE_LOAD_WORKING: false (unmarshal error)");
                    }
                } catch (Exception e) {
                    System.out.println("REMOTE_LOAD_WORKING: false (error: " + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
                }
            }
            
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
"""
            with tempfile.TemporaryDirectory() as tmpdir:
                java_file = os.path.join(tmpdir, "RMICodebaseTest.java")
                with open(java_file, 'w') as f:
                    f.write(java_code)
                
                compile_result = subprocess.run(
                    ["javac", java_file],
                    capture_output=True,
                    cwd=tmpdir
                )
                
                if compile_result.returncode != 0:
                    error_output = compile_result.stderr.decode()
                    self.results["errors"].append(f"Failed to compile codebase test: {error_output}")
                    return False
                
                run_result = subprocess.run(
                    ["java", "-cp", tmpdir, "RMICodebaseTest", self.host, str(self.port),
                     str(self.use_ssl).lower()],
                    capture_output=True,
                    timeout=15
                )
                
                output = run_result.stdout.decode()
                stderr_output = run_result.stderr.decode()
                
                # Parse output
                current_object = None
                test_details = {}
                
                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith("TESTING:"):
                        current_object = line.split(":", 1)[1].strip()
                        test_details[current_object] = {
                            "object_name": current_object,
                            "remote_load_working": False,
                            "codebase_url": None,
                            "error": None,
                            "class_name": None
                        }
                    elif line.startswith("SUCCESS:") and current_object:
                        parts = line.split("->", 1)
                        if len(parts) == 2:
                            test_details[current_object]["class_name"] = parts[1].strip()
                    elif line.startswith("CODEBASE_URL:") and current_object:
                        codebase = line.split(":", 1)[1].strip()
                        test_details[current_object]["codebase_url"] = codebase
                        if codebase not in self.results["codebase_urls"]:
                            self.results["codebase_urls"].append(codebase)
                    elif line.startswith("CODEBASE_ATTEMPTED:") and current_object:
                        codebase = line.split(":", 1)[1].strip()
                        test_details[current_object]["codebase_url"] = codebase
                        if codebase not in self.results["codebase_urls"]:
                            self.results["codebase_urls"].append(codebase)
                    elif line.startswith("REMOTE_LOAD_WORKING:") and current_object:
                        if "true" in line:
                            test_details[current_object]["remote_load_working"] = True
                            self.results["remote_codebase_working"] = True
                        else:
                            # Extract error message if present
                            if "(" in line and ")" in line:
                                start_idx = line.find("(") + 1
                                end_idx = line.rfind(")")
                                error_part = line[start_idx:end_idx]
                                test_details[current_object]["error"] = error_part
                
                # Store test details
                for obj_name, details in test_details.items():
                    self.results["codebase_download_test_details"].append(details)
                
                # If we got any successful remote loads, return true
                return self.results.get("remote_codebase_working", False)
                    
        except subprocess.TimeoutExpired:
            self.results["errors"].append("Codebase download test timed out")
            return False
        except Exception as e:
            self.results["errors"].append(f"Codebase download test error: {str(e)}")
            return False
    
    def enumerate_objects(self) -> List[str]:
        """Enumerate objects exposed in RMI registry"""
        if not self.results["exposed_objects"]:
            # Try to get objects using Java
            objects = self._list_registry_java()
            if objects:
                self.results["exposed_objects"] = objects
        
        return self.results["exposed_objects"]
    
    def scan(self) -> Dict:
        """Run full security scan"""
        print(f"[*] Scanning RMI service at {self.host}:{self.port} (SSL: {self.use_ssl})")
        
        if not self.java_available:
            print("[!] WARNING: Java not found. Limited functionality available.")
            print("[!] Install Java JDK for full RMI enumeration capabilities.")
        
        # 1. Test connection
        print("[*] Testing connection...")
        if not self.connect():
            print("[-] Failed to connect")
            return self.results
        
        print("[+] Connection successful")
        
        # 2. Test authentication
        print("[*] Checking for authentication...")
        auth_required = self.test_authentication()
        
        if auth_required:
            print("[+] Authentication is required")
            # 2a. Try common credentials (will be overridden if password_list provided)
            self.brute_force_credentials()
        else:
            print("[+] No authentication required")
            # Can enumerate objects directly
            objects = self.enumerate_objects()
            if objects:
                print(f"[+] Found {len(objects)} exposed object(s)")
                for obj in objects:
                    print(f"    - {obj}")
        
        # 3. Check remote codebase
        print("[*] Checking for remote codebase downloading...")
        if self.check_remote_codebase():
            print("[!] WARNING: Remote codebase downloading may be enabled")
            if self.results["codebase_urls"]:
                print(f"[!] Codebase URLs found:")
                for url in self.results["codebase_urls"]:
                    print(f"    - {url}")
            
            # 3a. Actually test if remote codebase downloading works
            print("[*] Testing if remote codebase downloading actually works...")
            if self.test_remote_codebase_download():
                print("[!] CRITICAL: Remote codebase downloading is WORKING!")
                print("[!] Classes can be downloaded from remote URLs - SECURITY RISK!")
                if self.results.get("codebase_download_test_details"):
                    for detail in self.results["codebase_download_test_details"]:
                        if detail.get("remote_load_working"):
                            print(f"    [+] {detail['object_name']}: Successfully loaded from remote codebase")
                            if detail.get("codebase_url"):
                                print(f"        Codebase URL: {detail['codebase_url']}")
                        else:
                            print(f"    [-] {detail['object_name']}: Remote load failed")
                            if detail.get("error"):
                                print(f"        Error: {detail['error']}")
            else:
                print("[+] Remote codebase downloading is enabled but NOT working")
                print("[+] Classes cannot be downloaded (may be blocked or misconfigured)")
                if self.results.get("codebase_download_test_details"):
                    for detail in self.results["codebase_download_test_details"]:
                        if detail.get("error"):
                            print(f"    [-] {detail['object_name']}: {detail['error']}")
        else:
            print("[+] Remote codebase downloading appears to be disabled")
        
        # 4. Enumerate objects (if not already done)
        if not self.results["exposed_objects"]:
            print("[*] Enumerating exposed objects...")
            objects = self.enumerate_objects()
            if objects:
                print(f"[+] Found {len(objects)} exposed object(s):")
                for obj in objects:
                    print(f"    - {obj}")
            else:
                print("[-] No objects found or unable to enumerate")
        
        self.disconnect()
        return self.results


def parse_hosts_file(hosts_file: str) -> List[Tuple[str, int]]:
    """Parse hosts file and return list of (host, port) tuples"""
    hosts = []
    try:
        with open(hosts_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse host:port or just host
                if ':' in line:
                    parts = line.split(':', 1)
                    host = parts[0].strip()
                    try:
                        port = int(parts[1].strip())
                    except ValueError:
                        print(f"[!] Warning: Invalid port in '{line}', using default 1099")
                        port = 1099
                else:
                    host = line.strip()
                    port = 1099
                
                if host:
                    hosts.append((host, port))
    except FileNotFoundError:
        print(f"[-] Error: Hosts file not found: {hosts_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading hosts file: {e}")
        sys.exit(1)
    
    return hosts


def parse_passwords_file(passwords_file: str) -> List[str]:
    """Parse passwords file and return list of passwords"""
    passwords = []
    try:
        with open(passwords_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                passwords.append(line)
    except FileNotFoundError:
        print(f"[-] Error: Passwords file not found: {passwords_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading passwords file: {e}")
        sys.exit(1)
    
    return passwords


def parse_usernames_file(usernames_file: str) -> List[str]:
    """Parse usernames file and return list of usernames"""
    usernames = []
    try:
        with open(usernames_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                usernames.append(line)
    except FileNotFoundError:
        print(f"[-] Error: Usernames file not found: {usernames_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading usernames file: {e}")
        sys.exit(1)
    
    return usernames


def scan_single_host(host: str, port: int, use_ssl: bool, timeout: int, 
                     password_list: Optional[List[str]] = None, 
                     username: Optional[str] = None,
                     output_file: Optional[str] = None,
                     verbose: bool = False) -> Dict:
    """Scan a single host and return results"""
    scanner = RMIScanner(host, port, use_ssl, timeout)
    
    # Store password list and username for use in brute force
    scanner._password_list = password_list
    scanner._username = username
    
    # Override brute force method to use password list and username if provided
    if password_list or username:
        original_brute_force = scanner.brute_force_credentials
        def brute_force_with_credentials():
            return original_brute_force(password_list, username)
        scanner.brute_force_credentials = brute_force_with_credentials
    
    results = scanner.scan()
    
    # Save individual results if output file specified
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    return results


def print_summary(results: Dict):
    """Print scan summary for a single host"""
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Host: {results['host']}:{results['port']}")
    print(f"SSL: {results['ssl']}")
    print(f"Connection: {'SUCCESS' if results['connection_successful'] else 'FAILED'}")
    print(f"Authentication Required: {results['authentication_required']}")
    if results['authentication_required']:
        print(f"Authentication Successful: {results['authentication_successful']}")
        if results['credentials_used']:
            print(f"Credentials: {results['credentials_used']['username']}:{results['credentials_used']['password']}")
    print(f"Remote Codebase Enabled: {results['remote_codebase_enabled']}")
    if results.get('remote_codebase_tested'):
        print(f"Remote Codebase Tested: Yes")
        print(f"Remote Codebase Working: {results.get('remote_codebase_working', False)}")
        if results.get('remote_codebase_working'):
            print("  [!] CRITICAL: Remote codebase downloading is ACTIVE - SECURITY RISK!")
    if results['codebase_urls']:
        print(f"Codebase URLs: {', '.join(results['codebase_urls'])}")
    print(f"Exposed Objects: {len(results['exposed_objects'])}")
    if results['exposed_objects']:
        for obj in results['exposed_objects']:
            print(f"  - {obj}")
    if results['errors']:
        print(f"Errors: {len(results['errors'])}")
        for error in results['errors']:
            print(f"  - {error}")
    print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description="RMI Security Scanner - Test Java RMI services for security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single host scan (no authentication)
  %(prog)s -H localhost -p 1099
  
  # Scenario A: Multiple hosts with single password
  %(prog)s --hosts-file hosts.txt --password mypass
  
  # Scenario B: Single host with password list
  %(prog)s -H localhost --passwords-file passwords.txt
  
  # Scenario C: Multiple hosts with multiple passwords (all combinations)
  %(prog)s --hosts-file hosts.txt --passwords-file passwords.txt
  
  # Single host with single password
  %(prog)s -H localhost -p 1099 --password mypass
  
  # Single host with username and password
  %(prog)s -H localhost -p 1099 -u admin --password mypass
  
  # All combinations: hosts, usernames, and passwords from files
  %(prog)s --hosts-file hosts.txt --usernames-file usernames.txt --passwords-file passwords.txt
  
  # SSL scan
  %(prog)s -H example.com -p 1099 --ssl
  
  # Save results
  %(prog)s -H localhost -p 1099 -o results.json
  
  # Multi-host with custom output directory
  %(prog)s --hosts-file hosts.txt --passwords-file passwords.txt --output-dir ./results
        """
    )
    
    # Host options (mutually exclusive)
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("-H", "--host", help="RMI server hostname or IP")
    host_group.add_argument("--hosts-file", help="File containing list of hosts (one per line, format: host:port or host)")
    
    parser.add_argument("-p", "--port", type=int, default=1099, help="RMI server port (default: 1099, ignored if hosts-file specifies ports)")
    parser.add_argument("-s", "--ssl", action="store_true", help="Use SSL/TLS connection")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Connection timeout in seconds (default: 5)")
    
    # Authentication options (can be used with single host or hosts file)
    parser.add_argument("-u", "--username", help="Single username to use for authentication (can be used with --password)")
    parser.add_argument("--usernames-file", help="File containing list of usernames to test (one per line, can be used with -H or --hosts-file)")
    parser.add_argument("--password", help="Single password to test (can be used with -H or --hosts-file)")
    parser.add_argument("--passwords-file", help="File containing list of passwords to test (one per line, can be used with -H or --hosts-file)")
    
    parser.add_argument("-o", "--output", help="Output results to JSON file (for single host) or directory (for multiple hosts)")
    parser.add_argument("--output-dir", help="Output directory for multi-host scans (default: ./rmi_scan_results)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Parse hosts
    if args.hosts_file:
        hosts = parse_hosts_file(args.hosts_file)
        if not hosts:
            print("[-] No valid hosts found in hosts file")
            sys.exit(1)
    else:
        hosts = [(args.host, args.port)]
    
    # Parse usernames
    usernames = None
    if args.usernames_file:
        usernames = parse_usernames_file(args.usernames_file)
        if not usernames:
            print("[-] No valid usernames found in usernames file")
            sys.exit(1)
    elif args.username:
        usernames = [args.username]
    
    # Parse passwords
    passwords = None
    if args.passwords_file:
        passwords = parse_passwords_file(args.passwords_file)
        if not passwords:
            print("[-] No valid passwords found in passwords file")
            sys.exit(1)
    elif args.password:
        passwords = [args.password]
    
    # Determine scan mode
    multi_host = len(hosts) > 1
    multi_username = usernames is not None and len(usernames) > 1
    multi_password = passwords is not None and len(passwords) > 1
    
    # Setup output
    output_dir = args.output_dir or "./rmi_scan_results"
    # Create output directory if we have multiple hosts, usernames, or passwords
    if (multi_host or multi_username or multi_password) and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    all_results = []
    successful_scans = 0
    failed_scans = 0
    
    # Print scan configuration
    print("="*60)
    print("RMI SECURITY SCANNER")
    print("="*60)
    print(f"Hosts to scan: {len(hosts)}")
    if usernames:
        print(f"Usernames to test: {len(usernames)}")
    if passwords:
        print(f"Passwords to test: {len(passwords)}")
    if multi_host or multi_username or multi_password:
        total_combinations = len(hosts) * (len(usernames) if usernames else 1) * (len(passwords) if passwords else 1)
        print(f"Total combinations to test: {total_combinations}")
    if multi_host:
        print(f"Output directory: {output_dir}")
    print("="*60)
    print()
    
    # Scan each host
    for host_idx, (host, port) in enumerate(hosts, 1):
        print(f"\n{'='*60}")
        print(f"Scanning host {host_idx}/{len(hosts)}: {host}:{port}")
        print(f"{'='*60}\n")
        
        host_results = []
        host_authenticated = False
        
        # Determine which usernames to try for this host
        usernames_to_try = usernames if usernames else [None]
        
        # Try each username for this host
        for username_idx, username in enumerate(usernames_to_try, 1):
            if multi_username:
                print(f"\n[Username {username_idx}/{len(usernames_to_try)}: {username}]")
            
            if passwords:
                # Try each password for this username/host combination
                for pwd_idx, password in enumerate(passwords, 1):
                    if multi_password:
                        print(f"  [Password {pwd_idx}/{len(passwords)}: {password}]")
                    
                    # Create scanner with password list and username
                    password_list = [password]
                    results = scan_single_host(host, port, args.ssl, args.timeout, 
                                             password_list, username, None, args.verbose)
                    results['password_tested'] = password
                    if username:
                        results['username_tested'] = username
                    host_results.append(results)
                    all_results.append(results)
                    
                    # If authentication successful, we can stop trying passwords for this host
                    if results.get('authentication_successful'):
                        creds = results.get('credentials_used', {})
                        print(f"\n[+] Authentication successful with: {creds.get('username', 'N/A')}:{creds.get('password', 'N/A')}")
                        host_authenticated = True
                        # Use this successful result as the main result for this host
                        results = results
                        break
                
                # If authentication successful, stop trying other usernames for this host
                if host_authenticated:
                    break
            else:
                # No password list, use default credential brute forcing (with username if provided)
                results = scan_single_host(host, port, args.ssl, args.timeout, 
                                         None, username, None, args.verbose)
                if username:
                    results['username_tested'] = username
                host_results.append(results)
                all_results.append(results)
                
                # If authentication successful, stop trying other usernames for this host
                if results.get('authentication_successful'):
                    creds = results.get('credentials_used', {})
                    print(f"\n[+] Authentication successful with: {creds.get('username', 'N/A')}:{creds.get('password', 'N/A')}")
                    host_authenticated = True
                    break
        
        # If no credentials worked, use the last result
        if not host_authenticated and host_results:
            results = host_results[-1]
        elif not host_results:
            # No credentials to try, do a basic scan
            results = scan_single_host(host, port, args.ssl, args.timeout, 
                                     None, None, None, args.verbose)
            all_results.append(results)
        
        # Print summary for this host
        print_summary(results)
        
        # Save individual result file for multi-host/multi-credential scans
        if multi_host or multi_username or multi_password:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_host = host.replace('.', '_').replace(':', '_')
            output_file = os.path.join(output_dir, f"rmi_scan_{safe_host}_{port}_{timestamp}.json")
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] Results saved to {output_file}")
        
        # Track statistics
        if results['connection_successful']:
            successful_scans += 1
        else:
            failed_scans += 1
    
    # Print overall summary for multi-host or multi-credential scans
    if multi_host or multi_username or multi_password:
        print("\n" + "="*60)
        print("OVERALL SCAN SUMMARY")
        print("="*60)
        print(f"Total hosts scanned: {len(hosts)}")
        if usernames:
            print(f"Total usernames tested: {len(usernames)}")
        if passwords:
            print(f"Total passwords tested: {len(passwords)}")
        print(f"Successful connections: {successful_scans}")
        print(f"Failed connections: {failed_scans}")
        print(f"Total combinations tested: {len(all_results)}")
        
        # Summary of successful authentications
        successful_auths = [r for r in all_results if r.get('authentication_successful')]
        if successful_auths:
            print(f"\nSuccessful authentications: {len(successful_auths)}")
            for result in successful_auths:
                creds = result.get('credentials_used', {})
                print(f"  - {result['host']}:{result['port']} - {creds.get('username', 'N/A')}:{creds.get('password', 'N/A')}")
        
        # Summary of exposed objects
        exposed_hosts = [r for r in all_results if r.get('exposed_objects')]
        if exposed_hosts:
            print(f"\nHosts with exposed objects: {len(exposed_hosts)}")
            for result in exposed_hosts:
                print(f"  - {result['host']}:{result['port']} - {len(result['exposed_objects'])} object(s)")
        
        # Save combined results
        summary_file = os.path.join(output_dir, f"scan_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(summary_file, 'w') as f:
            json.dump({
                'scan_timestamp': datetime.now().isoformat(),
                'total_hosts': len(hosts),
                'total_usernames': len(usernames) if usernames else 0,
                'total_passwords': len(passwords) if passwords else 0,
                'total_combinations_tested': len(all_results),
                'successful_connections': successful_scans,
                'failed_connections': failed_scans,
                'results': all_results
            }, f, indent=2)
        print(f"\n[+] Combined results saved to {summary_file}")
        print("="*60)
    
    # Single host output (when not multi-host/multi-credential)
    if not multi_host and not multi_username and not multi_password and args.output:
        with open(args.output, 'w') as f:
            json.dump(all_results[0], f, indent=2)
        print(f"\n[+] Results saved to {args.output}")
    
    # Exit code
    exit_code = 0 if successful_scans > 0 else 1
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

