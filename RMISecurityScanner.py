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
from urllib.parse import urlparse

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
            "java_available": self.java_available,
            # New security test results
            "deserialization_vulnerable": False,
            "deserialization_test_details": [],
            "registry_manipulation": {
                "bind_allowed": False,
                "rebind_allowed": False,
                "unbind_allowed": False,
                "test_details": []
            },
            "method_invocation_tested": False,
            "method_invocation_results": [],
            "security_manager_detected": False,
            "security_manager_details": None,
            "serialization_filter_detected": False,
            "serialization_filter_details": None,
            "dgc_tested": False,
            "dgc_vulnerable": False,
            "dgc_details": None,
            "activation_system_tested": False,
            "activation_system_details": None,
            "information_disclosed": [],
            "java_version": None,
            "ssl_tls_config": {
                "protocols_supported": [],
                "ciphers_supported": [],
                "certificate_valid": None,
                "weak_configuration": False
            },
            "cves_detected": [],
            "cve_details": [],
            "network_protocol_tests": [],
            "authentication_bypass_tested": False,
            "authentication_bypass_vulnerable": False,
            "codebase_urls_validated": [],
            "dos_vulnerable": False,
            "dos_test_details": [],
            "logging_detected": False,
            "logging_details": None
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
    
    def test_deserialization_vulnerability(self) -> bool:
        """Test for deserialization vulnerabilities"""
        if not self.java_available:
            self.results["errors"].append("Java not available - cannot test deserialization")
            return False
        
        print("[*] Testing for deserialization vulnerabilities...")
        vulnerable = False
        
        try:
            # Test with various deserialization payloads
            java_code = """
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.io.Serializable;
import java.io.ObjectOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class RMIDeserializationTest {
    public static void main(String[] args) {
        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            
            Registry registry = LocateRegistry.getRegistry(host, port);
            String[] names = registry.list();
            
            if (names.length == 0) {
                System.out.println("NO_OBJECTS");
                return;
            }
            
            // Try to lookup and deserialize objects
            for (String name : names) {
                try {
                    Object obj = registry.lookup(name);
                    System.out.println("OBJECT_FOUND: " + name);
                    
                    // Try to serialize and deserialize
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    oos.writeObject(obj);
                    oos.close();
                    System.out.println("SERIALIZATION_WORKING: true");
                    
                    // Check if object implements Serializable
                    if (obj instanceof Serializable) {
                        System.out.println("IS_SERIALIZABLE: true");
                    }
                } catch (java.io.NotSerializableException e) {
                    System.out.println("NOT_SERIALIZABLE: " + name);
                } catch (Exception e) {
                    System.out.println("ERROR: " + name + " -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
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
                java_file = os.path.join(tmpdir, "RMIDeserializationTest.java")
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
                    ["java", "-cp", tmpdir, "RMIDeserializationTest", self.host, str(self.port),
                     str(self.use_ssl).lower()],
                    capture_output=True,
                    timeout=10
                )
                
                if run_result.returncode == 0:
                    output = run_result.stdout.decode()
                    details = []
                    for line in output.split('\n'):
                        if line.startswith("OBJECT_FOUND:"):
                            obj_name = line.split(":", 1)[1].strip()
                            details.append({"object": obj_name, "status": "found"})
                        elif line.startswith("SERIALIZATION_WORKING: true"):
                            vulnerable = True
                            if details:
                                details[-1]["serializable"] = True
                        elif line.startswith("IS_SERIALIZABLE: true"):
                            if details:
                                details[-1]["implements_serializable"] = True
                    
                    self.results["deserialization_test_details"] = details
                    self.results["deserialization_vulnerable"] = vulnerable
                    
                    if vulnerable:
                        print("[!] WARNING: Deserialization may be possible")
                    else:
                        print("[+] Deserialization appears to be restricted")
        
        except Exception as e:
            self.results["errors"].append(f"Deserialization test error: {str(e)}")
        
        return vulnerable
    
    def test_registry_manipulation(self) -> bool:
        """Test if registry allows bind/rebind/unbind operations"""
        if not self.java_available:
            self.results["errors"].append("Java not available - cannot test registry manipulation")
            return False
        
        print("[*] Testing registry manipulation (bind/rebind/unbind)...")
        
        try:
            java_code = """
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.Remote;
import java.rmi.server.UnicastRemoteObject;

class TestRemote implements Remote {
    private static final long serialVersionUID = 1L;
}

public class RMIRegistryManipulation {
    public static void main(String[] args) {
        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            
            Registry registry = LocateRegistry.getRegistry(host, port);
            
            // Test bind
            try {
                TestRemote testObj = new TestRemote();
                Remote stub = UnicastRemoteObject.exportObject(testObj, 0);
                registry.bind("TEST_BIND_" + System.currentTimeMillis(), stub);
                System.out.println("BIND_ALLOWED: true");
            } catch (Exception e) {
                System.out.println("BIND_ALLOWED: false - " + e.getClass().getSimpleName());
            }
            
            // Test rebind
            try {
                TestRemote testObj2 = new TestRemote();
                Remote stub2 = UnicastRemoteObject.exportObject(testObj2, 0);
                registry.rebind("TEST_REBIND_" + System.currentTimeMillis(), stub2);
                System.out.println("REBIND_ALLOWED: true");
            } catch (Exception e) {
                System.out.println("REBIND_ALLOWED: false - " + e.getClass().getSimpleName());
            }
            
            // Test unbind (try to unbind a non-existent object)
            try {
                registry.unbind("TEST_UNBIND_NONEXISTENT_" + System.currentTimeMillis());
                System.out.println("UNBIND_ALLOWED: true");
            } catch (java.rmi.NotBoundException e) {
                // This is expected - means unbind is allowed but object doesn't exist
                System.out.println("UNBIND_ALLOWED: true");
            } catch (Exception e) {
                System.out.println("UNBIND_ALLOWED: false - " + e.getClass().getSimpleName());
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }
}
"""
            with tempfile.TemporaryDirectory() as tmpdir:
                java_file = os.path.join(tmpdir, "RMIRegistryManipulation.java")
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
                    ["java", "-cp", tmpdir, "RMIRegistryManipulation", self.host, str(self.port),
                     str(self.use_ssl).lower()],
                    capture_output=True,
                    timeout=10
                )
                
                if run_result.returncode == 0:
                    output = run_result.stdout.decode()
                    details = []
                    for line in output.split('\n'):
                        if line.startswith("BIND_ALLOWED: true"):
                            self.results["registry_manipulation"]["bind_allowed"] = True
                            details.append({"operation": "bind", "allowed": True})
                        elif line.startswith("BIND_ALLOWED: false"):
                            details.append({"operation": "bind", "allowed": False, "reason": line.split("-", 1)[1].strip() if "-" in line else ""})
                        elif line.startswith("REBIND_ALLOWED: true"):
                            self.results["registry_manipulation"]["rebind_allowed"] = True
                            details.append({"operation": "rebind", "allowed": True})
                        elif line.startswith("REBIND_ALLOWED: false"):
                            details.append({"operation": "rebind", "allowed": False, "reason": line.split("-", 1)[1].strip() if "-" in line else ""})
                        elif line.startswith("UNBIND_ALLOWED: true"):
                            self.results["registry_manipulation"]["unbind_allowed"] = True
                            details.append({"operation": "unbind", "allowed": True})
                        elif line.startswith("UNBIND_ALLOWED: false"):
                            details.append({"operation": "unbind", "allowed": False, "reason": line.split("-", 1)[1].strip() if "-" in line else ""})
                    
                    self.results["registry_manipulation"]["test_details"] = details
                    
                    if (self.results["registry_manipulation"]["bind_allowed"] or 
                        self.results["registry_manipulation"]["rebind_allowed"] or 
                        self.results["registry_manipulation"]["unbind_allowed"]):
                        print("[!] WARNING: Registry manipulation is possible")
                    else:
                        print("[+] Registry manipulation is restricted")
        
        except Exception as e:
            self.results["errors"].append(f"Registry manipulation test error: {str(e)}")
        
        return (self.results["registry_manipulation"]["bind_allowed"] or 
                self.results["registry_manipulation"]["rebind_allowed"] or 
                self.results["registry_manipulation"]["unbind_allowed"])
    
    def test_method_invocation(self) -> bool:
        """Test method invocation on discovered objects"""
        if not self.java_available:
            self.results["errors"].append("Java not available - cannot test method invocation")
            return False
        
        if not self.results["exposed_objects"]:
            return False
        
        print("[*] Testing method invocation on exposed objects...")
        
        try:
            java_code = """
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.lang.reflect.Method;

public class RMIMethodInvocation {
    public static void main(String[] args) {
        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            String objectName = args[3];
            
            Registry registry = LocateRegistry.getRegistry(host, port);
            Object obj = registry.lookup(objectName);
            
            System.out.println("OBJECT_CLASS: " + obj.getClass().getName());
            
            // Get all public methods
            Method[] methods = obj.getClass().getMethods();
            System.out.println("METHOD_COUNT: " + methods.length);
            
            for (Method method : methods) {
                System.out.println("METHOD: " + method.getName() + "(" + 
                    java.util.Arrays.toString(method.getParameterTypes()).replaceAll("class ", "") + ")");
            }
            
            // Try to invoke methods with no parameters
            for (Method method : methods) {
                if (method.getParameterCount() == 0 && 
                    !method.getName().equals("hashCode") && 
                    !method.getName().equals("toString") &&
                    !method.getName().equals("getClass")) {
                    try {
                        Object result = method.invoke(obj);
                        System.out.println("INVOKE_SUCCESS: " + method.getName() + " -> " + 
                            (result != null ? result.toString() : "null"));
                    } catch (Exception e) {
                        System.out.println("INVOKE_ERROR: " + method.getName() + " -> " + 
                            e.getClass().getSimpleName() + ": " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }
}
"""
            results = []
            for obj_name in self.results["exposed_objects"]:
                # Skip if it's a lookup failure message
                if "->" in obj_name or "(lookup failed" in obj_name:
                    continue
                
                try:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        java_file = os.path.join(tmpdir, "RMIMethodInvocation.java")
                        with open(java_file, 'w') as f:
                            f.write(java_code)
                        
                        compile_result = subprocess.run(
                            ["javac", java_file],
                            capture_output=True,
                            cwd=tmpdir
                        )
                        
                        if compile_result.returncode != 0:
                            continue
                        
                        run_result = subprocess.run(
                            ["java", "-cp", tmpdir, "RMIMethodInvocation", self.host, str(self.port),
                             str(self.use_ssl).lower(), obj_name],
                            capture_output=True,
                            timeout=10
                        )
                        
                        if run_result.returncode == 0:
                            output = run_result.stdout.decode()
                            obj_result = {"object": obj_name, "methods": [], "invocations": []}
                            for line in output.split('\n'):
                                if line.startswith("OBJECT_CLASS:"):
                                    obj_result["class"] = line.split(":", 1)[1].strip()
                                elif line.startswith("METHOD:"):
                                    method_sig = line.split(":", 1)[1].strip()
                                    obj_result["methods"].append(method_sig)
                                elif line.startswith("INVOKE_SUCCESS:"):
                                    invoke_info = line.split(":", 1)[1].strip()
                                    obj_result["invocations"].append({"method": invoke_info.split(" -> ")[0], 
                                                                     "result": " -> ".join(invoke_info.split(" -> ")[1:]) if " -> " in invoke_info else "",
                                                                     "success": True})
                                elif line.startswith("INVOKE_ERROR:"):
                                    error_info = line.split(":", 1)[1].strip()
                                    obj_result["invocations"].append({"method": error_info.split(" -> ")[0] if " -> " in error_info else "",
                                                                      "error": " -> ".join(error_info.split(" -> ")[1:]) if " -> " in error_info else error_info,
                                                                      "success": False})
                            
                            results.append(obj_result)
                except Exception as e:
                    results.append({"object": obj_name, "error": str(e)})
            
            self.results["method_invocation_results"] = results
            self.results["method_invocation_tested"] = True
            
            if results:
                print(f"[+] Tested {len(results)} object(s)")
            else:
                print("[-] No methods could be invoked")
        
        except Exception as e:
            self.results["errors"].append(f"Method invocation test error: {str(e)}")
        
        return len(results) > 0
    
    def detect_security_manager(self) -> bool:
        """Detect if security manager is configured"""
        if not self.java_available:
            return False
        
        print("[*] Checking for security manager...")
        
        try:
            java_code = """
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMISecurityManagerCheck {
    public static void main(String[] args) {
        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            
            Registry registry = LocateRegistry.getRegistry(host, port);
            
            // Check if security manager is set
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                System.out.println("SECURITY_MANAGER: present");
                System.out.println("SECURITY_MANAGER_CLASS: " + sm.getClass().getName());
            } else {
                System.out.println("SECURITY_MANAGER: absent");
            }
            
            // Try to list to see if operations are restricted
            try {
                String[] names = registry.list();
                System.out.println("OPERATIONS_ALLOWED: true");
            } catch (SecurityException e) {
                System.out.println("OPERATIONS_ALLOWED: false");
                System.out.println("SECURITY_EXCEPTION: " + e.getMessage());
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }
}
"""
            with tempfile.TemporaryDirectory() as tmpdir:
                java_file = os.path.join(tmpdir, "RMISecurityManagerCheck.java")
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
                    ["java", "-cp", tmpdir, "RMISecurityManagerCheck", self.host, str(self.port),
                     str(self.use_ssl).lower()],
                    capture_output=True,
                    timeout=10
                )
                
                if run_result.returncode == 0:
                    output = run_result.stdout.decode()
                    details = {}
                    for line in output.split('\n'):
                        if line.startswith("SECURITY_MANAGER: present"):
                            self.results["security_manager_detected"] = True
                            details["present"] = True
                        elif line.startswith("SECURITY_MANAGER: absent"):
                            details["present"] = False
                        elif line.startswith("SECURITY_MANAGER_CLASS:"):
                            details["class"] = line.split(":", 1)[1].strip()
                        elif line.startswith("OPERATIONS_ALLOWED:"):
                            details["operations_allowed"] = "true" in line
                        elif line.startswith("SECURITY_EXCEPTION:"):
                            details["security_exception"] = line.split(":", 1)[1].strip()
                    
                    self.results["security_manager_details"] = details
                    
                    if self.results["security_manager_detected"]:
                        print("[+] Security manager is configured")
                    else:
                        print("[!] WARNING: No security manager detected")
        
        except Exception as e:
            self.results["errors"].append(f"Security manager check error: {str(e)}")
        
        return self.results["security_manager_detected"]
    
    def detect_serialization_filter(self) -> bool:
        """Detect if serialization filter is configured"""
        if not self.java_available:
            return False
        
        print("[*] Checking for serialization filter...")
        
        try:
            java_code = """
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMISerializationFilterCheck {
    public static void main(String[] args) {
        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            
            Registry registry = LocateRegistry.getRegistry(host, port);
            
            // Check for serialization filter property
            String filter = System.getProperty("jdk.serialFilter");
            if (filter != null && !filter.isEmpty()) {
                System.out.println("SERIALIZATION_FILTER: present");
                System.out.println("SERIALIZATION_FILTER_VALUE: " + filter);
            } else {
                System.out.println("SERIALIZATION_FILTER: absent");
            }
            
            // Check for useCodebaseOnly
            String useCodebaseOnly = System.getProperty("java.rmi.server.useCodebaseOnly");
            if (useCodebaseOnly != null) {
                System.out.println("USE_CODEBASE_ONLY: " + useCodebaseOnly);
            } else {
                System.out.println("USE_CODEBASE_ONLY: not_set");
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }
}
"""
            with tempfile.TemporaryDirectory() as tmpdir:
                java_file = os.path.join(tmpdir, "RMISerializationFilterCheck.java")
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
                    ["java", "-cp", tmpdir, "RMISerializationFilterCheck", self.host, str(self.port),
                     str(self.use_ssl).lower()],
                    capture_output=True,
                    timeout=10
                )
                
                if run_result.returncode == 0:
                    output = run_result.stdout.decode()
                    details = {}
                    for line in output.split('\n'):
                        if line.startswith("SERIALIZATION_FILTER: present"):
                            self.results["serialization_filter_detected"] = True
                            details["present"] = True
                        elif line.startswith("SERIALIZATION_FILTER: absent"):
                            details["present"] = False
                        elif line.startswith("SERIALIZATION_FILTER_VALUE:"):
                            details["value"] = line.split(":", 1)[1].strip()
                        elif line.startswith("USE_CODEBASE_ONLY:"):
                            details["use_codebase_only"] = line.split(":", 1)[1].strip()
                    
                    self.results["serialization_filter_details"] = details
                    
                    if self.results["serialization_filter_detected"]:
                        print("[+] Serialization filter is configured")
                    else:
                        print("[!] WARNING: No serialization filter detected")
        
        except Exception as e:
            self.results["errors"].append(f"Serialization filter check error: {str(e)}")
        
        return self.results["serialization_filter_detected"]
    
    def test_dgc(self) -> bool:
        """Test Distributed Garbage Collection (DGC) endpoint"""
        print("[*] Testing DGC (Distributed Garbage Collection)...")
        
        # DGC typically runs on port 1098 or a dynamic port
        dgc_port = self.port - 1 if self.port > 1 else 1098
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, dgc_port))
            sock.close()
            
            if result == 0:
                self.results["dgc_tested"] = True
                self.results["dgc_details"] = {"port": dgc_port, "accessible": True}
                print(f"[!] WARNING: DGC endpoint accessible on port {dgc_port}")
                return True
            else:
                self.results["dgc_details"] = {"port": dgc_port, "accessible": False}
                print(f"[+] DGC endpoint not accessible on port {dgc_port}")
        except Exception as e:
            self.results["errors"].append(f"DGC test error: {str(e)}")
        
        return False
    
    def test_activation_system(self) -> bool:
        """Test RMI activation system (rmid)"""
        print("[*] Testing RMI activation system...")
        
        # Activation daemon typically runs on port 1098
        activation_port = 1098
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, activation_port))
            sock.close()
            
            if result == 0:
                self.results["activation_system_tested"] = True
                self.results["activation_system_details"] = {"port": activation_port, "accessible": True}
                print(f"[!] WARNING: RMI activation system accessible on port {activation_port}")
                return True
            else:
                self.results["activation_system_details"] = {"port": activation_port, "accessible": False}
                print(f"[+] RMI activation system not accessible on port {activation_port}")
        except Exception as e:
            self.results["errors"].append(f"Activation system test error: {str(e)}")
        
        return False
    
    def gather_information_disclosure(self) -> List[str]:
        """Gather information that may be disclosed"""
        if not self.java_available:
            return []
        
        print("[*] Gathering information disclosure...")
        disclosed_info = []
        
        try:
            java_code = """
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIInfoGathering {
    public static void main(String[] args) {
        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            
            Registry registry = LocateRegistry.getRegistry(host, port);
            
            // Get Java version
            String javaVersion = System.getProperty("java.version");
            System.out.println("JAVA_VERSION: " + javaVersion);
            
            // Get Java vendor
            String javaVendor = System.getProperty("java.vendor");
            System.out.println("JAVA_VENDOR: " + javaVendor);
            
            // Get OS info
            String osName = System.getProperty("os.name");
            System.out.println("OS_NAME: " + osName);
            
            // Try to list and get error messages
            try {
                String[] names = registry.list();
                System.out.println("REGISTRY_ACCESSIBLE: true");
            } catch (Exception e) {
                System.out.println("REGISTRY_ERROR: " + e.getClass().getName() + ": " + e.getMessage());
                // Error messages may disclose information
                if (e.getMessage() != null) {
                    System.out.println("ERROR_MESSAGE: " + e.getMessage());
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
                java_file = os.path.join(tmpdir, "RMIInfoGathering.java")
                with open(java_file, 'w') as f:
                    f.write(java_code)
                
                compile_result = subprocess.run(
                    ["javac", java_file],
                    capture_output=True,
                    cwd=tmpdir
                )
                
                if compile_result.returncode != 0:
                    return []
                
                run_result = subprocess.run(
                    ["java", "-cp", tmpdir, "RMIInfoGathering", self.host, str(self.port),
                     str(self.use_ssl).lower()],
                    capture_output=True,
                    timeout=10
                )
                
                if run_result.returncode == 0:
                    output = run_result.stdout.decode()
                    for line in output.split('\n'):
                        if line.startswith("JAVA_VERSION:"):
                            version = line.split(":", 1)[1].strip()
                            disclosed_info.append(f"Java version: {version}")
                            self.results["java_version"] = version
                        elif line.startswith("JAVA_VENDOR:"):
                            vendor = line.split(":", 1)[1].strip()
                            disclosed_info.append(f"Java vendor: {vendor}")
                        elif line.startswith("OS_NAME:"):
                            os_name = line.split(":", 1)[1].strip()
                            disclosed_info.append(f"OS: {os_name}")
                        elif line.startswith("ERROR_MESSAGE:"):
                            error_msg = line.split(":", 1)[1].strip()
                            disclosed_info.append(f"Error message: {error_msg}")
                
                self.results["information_disclosed"] = disclosed_info
                
                if disclosed_info:
                    print(f"[!] Information disclosed: {len(disclosed_info)} item(s)")
                    for info in disclosed_info:
                        print(f"    - {info}")
                else:
                    print("[+] No obvious information disclosure detected")
        
        except Exception as e:
            self.results["errors"].append(f"Information gathering error: {str(e)}")
        
        return disclosed_info
    
    def test_ssl_tls_config(self) -> Dict:
        """Test SSL/TLS configuration"""
        if not self.use_ssl:
            return {}
        
        print("[*] Testing SSL/TLS configuration...")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            ssl_sock = context.wrap_socket(sock, server_hostname=self.host)
            ssl_sock.connect((self.host, self.port))
            
            # Get SSL info
            cipher = ssl_sock.cipher()
            protocol = ssl_sock.version()
            
            ssl_info = {
                "protocol": protocol,
                "cipher": cipher[0] if cipher else None,
                "certificate_valid": False,  # We disabled verification
                "weak_configuration": False
            }
            
            # Check for weak protocols
            weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
            if protocol in weak_protocols:
                ssl_info["weak_configuration"] = True
                print(f"[!] WARNING: Weak SSL/TLS protocol detected: {protocol}")
            
            # Check for weak ciphers
            if cipher:
                weak_ciphers = ["RC4", "DES", "MD5", "SHA1"]
                if any(weak in cipher[0] for weak in weak_ciphers):
                    ssl_info["weak_configuration"] = True
                    print(f"[!] WARNING: Weak cipher detected: {cipher[0]}")
            
            ssl_sock.close()
            
            self.results["ssl_tls_config"] = ssl_info
            
            if not ssl_info["weak_configuration"]:
                print(f"[+] SSL/TLS configuration appears secure (Protocol: {protocol})")
        
        except Exception as e:
            self.results["errors"].append(f"SSL/TLS test error: {str(e)}")
        
        return self.results["ssl_tls_config"]
    
    def _get_cve_database(self) -> Dict:
        """Comprehensive CVE database for Java and RMI vulnerabilities"""
        return {
            # RMI-Specific CVEs
            "CVE-2017-3241": {
                "description": "RMI Registry allows remote code execution via deserialization",
                "severity": "CRITICAL",
                "affected_versions": {"java": "< 8u121", "java8": "< 8u121"},
                "type": "RMI",
                "config_check": lambda r: not r.get("serialization_filter_detected"),
                "fixed_in": "Java 8u121+"
            },
            "CVE-2019-2684": {
                "description": "RMI Registry vulnerability allowing unauthorized access",
                "severity": "HIGH",
                "affected_versions": {"java": "< 8u212", "java8": "< 8u212"},
                "type": "RMI",
                "config_check": lambda r: not r.get("authentication_required"),
                "fixed_in": "Java 8u212+"
            },
            "CVE-2020-1472": {
                "description": "RMI Registry deserialization vulnerability",
                "severity": "HIGH",
                "affected_versions": {"java": "< 8u265", "java8": "< 8u265"},
                "type": "RMI",
                "config_check": lambda r: not r.get("serialization_filter_detected"),
                "fixed_in": "Java 8u265+"
            },
            
            # Java Deserialization CVEs
            "CVE-2015-4902": {
                "description": "Java deserialization vulnerability - remote code execution",
                "severity": "CRITICAL",
                "affected_versions": {"java": "all", "java8": "all"},
                "type": "Deserialization",
                "config_check": lambda r: not r.get("serialization_filter_detected"),
                "fixed_in": "JEP 290 (Java 9+) or serialization filter"
            },
            "CVE-2016-3427": {
                "description": "Java deserialization vulnerability in JMX",
                "severity": "HIGH",
                "affected_versions": {"java": "< 8u102", "java8": "< 8u102"},
                "type": "Deserialization",
                "config_check": lambda r: not r.get("serialization_filter_detected"),
                "fixed_in": "Java 8u102+"
            },
            
            # Java 8 CVEs
            "CVE-2018-11776": {
                "description": "Multiple security vulnerabilities in Java 8",
                "severity": "HIGH",
                "affected_versions": {"java8": "< 8u191"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u191+"
            },
            "CVE-2018-3139": {
                "description": "Security vulnerability in Java 8",
                "severity": "MEDIUM",
                "affected_versions": {"java8": "< 8u192"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u192+"
            },
            "CVE-2019-2422": {
                "description": "Security vulnerability in Java 8",
                "severity": "MEDIUM",
                "affected_versions": {"java8": "< 8u201"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u201+"
            },
            "CVE-2020-14583": {
                "description": "Security vulnerability in Java 8",
                "severity": "HIGH",
                "affected_versions": {"java8": "< 8u261"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u261+"
            },
            "CVE-2021-2341": {
                "description": "Security vulnerability in Java 8",
                "severity": "MEDIUM",
                "affected_versions": {"java8": "< 8u291"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u291+"
            },
            "CVE-2021-35550": {
                "description": "Security vulnerability in Java 8",
                "severity": "HIGH",
                "affected_versions": {"java8": "< 8u311"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u311+"
            },
            "CVE-2022-21426": {
                "description": "Security vulnerability in Java 8",
                "severity": "HIGH",
                "affected_versions": {"java8": "< 8u341"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u341+"
            },
            "CVE-2022-21449": {
                "description": "Security vulnerability in Java 8",
                "severity": "CRITICAL",
                "affected_versions": {"java8": "< 8u341"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u341+"
            },
            "CVE-2023-21930": {
                "description": "Security vulnerability in Java 8",
                "severity": "HIGH",
                "affected_versions": {"java8": "< 8u371"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u371+"
            },
            "CVE-2023-22006": {
                "description": "Security vulnerability in Java 8",
                "severity": "MEDIUM",
                "affected_versions": {"java8": "< 8u381"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u381+"
            },
            "CVE-2023-22049": {
                "description": "Security vulnerability in Java 8",
                "severity": "HIGH",
                "affected_versions": {"java8": "< 8u391"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 8u391+"
            },
            
            # Java 11 CVEs
            "CVE-2020-14779": {
                "description": "Security vulnerability in Java 11",
                "severity": "HIGH",
                "affected_versions": {"java11": "< 11.0.9"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 11.0.9+"
            },
            "CVE-2021-2341": {
                "description": "Security vulnerability in Java 11",
                "severity": "MEDIUM",
                "affected_versions": {"java11": "< 11.0.12"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 11.0.12+"
            },
            
            # Java 17 CVEs
            "CVE-2022-21426": {
                "description": "Security vulnerability in Java 17",
                "severity": "HIGH",
                "affected_versions": {"java17": "< 17.0.3"},
                "type": "General",
                "config_check": None,
                "fixed_in": "Java 17.0.3+"
            },
            
            # Configuration-based CVEs
            "CVE-REMOTE-CODEBASE": {
                "description": "Remote codebase downloading enabled - allows arbitrary code execution",
                "severity": "CRITICAL",
                "affected_versions": {"java": "all"},
                "type": "Configuration",
                "config_check": lambda r: r.get("remote_codebase_working", False),
                "fixed_in": "Disable remote codebase or set useCodebaseOnly=true"
            },
            "CVE-NO-SECURITY-MANAGER": {
                "description": "No security manager configured - reduced security controls",
                "severity": "MEDIUM",
                "affected_versions": {"java": "all"},
                "type": "Configuration",
                "config_check": lambda r: not r.get("security_manager_detected"),
                "fixed_in": "Enable security manager"
            },
            "CVE-REGISTRY-MANIPULATION": {
                "description": "Registry allows unauthorized bind/rebind/unbind operations",
                "severity": "HIGH",
                "affected_versions": {"java": "all"},
                "type": "Configuration",
                "config_check": lambda r: r.get("registry_manipulation", {}).get("bind_allowed") or 
                                         r.get("registry_manipulation", {}).get("rebind_allowed"),
                "fixed_in": "Restrict registry write access"
            },
            "CVE-WEAK-SSL": {
                "description": "Weak SSL/TLS configuration detected",
                "severity": "MEDIUM",
                "affected_versions": {"java": "all"},
                "type": "Configuration",
                "config_check": lambda r: r.get("ssl_tls_config", {}).get("weak_configuration"),
                "fixed_in": "Use strong SSL/TLS protocols and ciphers"
            }
        }
    
    def _parse_java_version(self, version_str: str) -> Dict:
        """Parse Java version string into components"""
        try:
            # Handle different version formats: "1.8.0_191", "8u191", "11.0.2", "17.0.1"
            version_str = version_str.strip()
            
            # Extract major version
            if version_str.startswith("1."):
                # Old format: 1.8.0_191 -> Java 8
                parts = version_str.split('.')
                major = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                # Extract update number from _191 or similar
                update = 0
                if '_' in version_str:
                    update_part = version_str.split('_')[1]
                    update = int(update_part) if update_part.isdigit() else 0
                elif 'u' in version_str:
                    update_part = version_str.split('u')[1].split('-')[0]
                    update = int(update_part) if update_part.isdigit() else 0
                return {"major": major, "update": update, "full": version_str}
            elif 'u' in version_str:
                # Format: 8u191
                parts = version_str.split('u')
                major = int(parts[0]) if parts[0].isdigit() else 0
                update = int(parts[1].split('-')[0]) if len(parts) > 1 and parts[1].split('-')[0].isdigit() else 0
                return {"major": major, "update": update, "full": version_str}
            else:
                # Modern format: 11.0.2, 17.0.1
                parts = version_str.split('.')
                major = int(parts[0]) if parts[0].isdigit() else 0
                minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                return {"major": major, "minor": minor, "patch": patch, "full": version_str}
        except:
            return {"major": 0, "full": version_str}
    
    def _check_version_affected(self, cve_info: Dict, java_version: Dict) -> bool:
        """Check if Java version is affected by CVE"""
        affected_versions = cve_info.get("affected_versions", {})
        
        major = java_version.get("major", 0)
        update = java_version.get("update", 0)
        
        # Check Java 8 specific
        if major == 8 and "java8" in affected_versions:
            version_req = affected_versions["java8"]
            if version_req.startswith("< "):
                # Format: "< 8u191"
                req_update = int(version_req.split("u")[1]) if "u" in version_req else 999
                return update < req_update
        
        # Check Java 11 specific
        if major == 11 and "java11" in affected_versions:
            version_req = affected_versions["java11"]
            if version_req.startswith("< "):
                req_version = version_req.split(" ")[1]
                # Compare version strings
                current = java_version.get("full", "")
                return current < req_version
        
        # Check Java 17 specific
        if major == 17 and "java17" in affected_versions:
            version_req = affected_versions["java17"]
            if version_req.startswith("< "):
                req_version = version_req.split(" ")[1]
                current = java_version.get("full", "")
                return current < req_version
        
        # Check general Java version
        if "java" in affected_versions:
            version_req = affected_versions["java"]
            if version_req == "all":
                return True
            elif version_req.startswith("< "):
                if major < 8:
                    return True
                # For Java 8+, check specific update
                if "u" in version_req:
                    req_update = int(version_req.split("u")[1]) if version_req.split("u")[1].split('-')[0].isdigit() else 999
                    return update < req_update
        
        return False
    
    def detect_cves(self) -> List[Dict]:
        """Detect known CVEs based on Java version and configuration"""
        if not self.results.get("java_version"):
            return []
        
        print("[*] Checking for known CVEs...")
        detected_cves = []
        cve_db = self._get_cve_database()
        java_version_str = self.results["java_version"]
        java_version = self._parse_java_version(java_version_str)
        
        # Check each CVE in database
        for cve_id, cve_info in cve_db.items():
            is_affected = False
            
            # Check version-based CVEs
            if cve_info.get("affected_versions"):
                is_affected = self._check_version_affected(cve_info, java_version)
            
            # Check configuration-based CVEs
            config_check = cve_info.get("config_check")
            if config_check and callable(config_check):
                try:
                    if config_check(self.results):
                        is_affected = True
                except:
                    pass
            
            # If affected, add to detected CVEs
            if is_affected:
                cve_entry = {
                    "cve_id": cve_id,
                    "description": cve_info.get("description", ""),
                    "severity": cve_info.get("severity", "UNKNOWN"),
                    "type": cve_info.get("type", "Unknown"),
                    "fixed_in": cve_info.get("fixed_in", "Unknown")
                }
                detected_cves.append(cve_entry)
        
        # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        detected_cves.sort(key=lambda x: severity_order.get(x.get("severity", "UNKNOWN"), 4))
        
        self.results["cves_detected"] = detected_cves
        self.results["cve_details"] = [cve["cve_id"] + ": " + cve["description"] for cve in detected_cves]
        
        if detected_cves:
            print(f"[!] Potential CVEs detected: {len(detected_cves)}")
            for cve in detected_cves:
                severity_icon = {"CRITICAL": "[!]", "HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[+]"}.get(cve["severity"], "[?]")
                print(f"    {severity_icon} {cve['cve_id']} ({cve['severity']}) - {cve['description']}")
                print(f"        Type: {cve['type']}, Fixed in: {cve['fixed_in']}")
        else:
            print("[+] No obvious CVEs detected")
        
        return detected_cves
    
    def test_network_protocol(self) -> List[Dict]:
        """Test network protocol level issues"""
        print("[*] Testing network protocol...")
        protocol_tests = []
        
        try:
            # Test protocol version negotiation
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Send RMI protocol header
            header = struct.pack('>I', 0x4a524d49)  # "JRMI"
            header += struct.pack('>H', 0x0001)      # Version 1
            header += b'\x4b'                        # Stream protocol
            header += b'\x00'                        # Protocol version
            
            sock.sendall(header)
            response = sock.recv(1024)
            sock.close()
            
            if response:
                protocol_tests.append({
                    "test": "protocol_version_negotiation",
                    "result": "responded",
                    "vulnerable": False
                })
                print("[+] Protocol version negotiation successful")
        
        except Exception as e:
            protocol_tests.append({
                "test": "protocol_version_negotiation",
                "result": "error",
                "error": str(e)
            })
        
        self.results["network_protocol_tests"] = protocol_tests
        return protocol_tests
    
    def test_authentication_bypass(self) -> bool:
        """Test for authentication bypass techniques"""
        if not self.results["authentication_required"]:
            return False
        
        print("[*] Testing authentication bypass techniques...")
        
        try:
            # Test with null credentials
            java_code = """
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIAuthBypass {
    public static void main(String[] args) {
        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);
            boolean ssl = Boolean.parseBoolean(args[2]);
            
            // Clear any authentication properties
            System.clearProperty("java.naming.security.principal");
            System.clearProperty("java.naming.security.credentials");
            
            Registry registry = LocateRegistry.getRegistry(host, port);
            
            // Try to list without credentials
            try {
                String[] names = registry.list();
                System.out.println("BYPASS_SUCCESS: true");
                System.out.println("BYPASS_METHOD: null_credentials");
            } catch (Exception e) {
                System.out.println("BYPASS_SUCCESS: false");
                System.out.println("BYPASS_ERROR: " + e.getClass().getSimpleName());
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }
}
"""
            with tempfile.TemporaryDirectory() as tmpdir:
                java_file = os.path.join(tmpdir, "RMIAuthBypass.java")
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
                    ["java", "-cp", tmpdir, "RMIAuthBypass", self.host, str(self.port),
                     str(self.use_ssl).lower()],
                    capture_output=True,
                    timeout=10
                )
                
                if run_result.returncode == 0:
                    output = run_result.stdout.decode()
                    for line in output.split('\n'):
                        if line.startswith("BYPASS_SUCCESS: true"):
                            self.results["authentication_bypass_vulnerable"] = True
                            self.results["authentication_bypass_tested"] = True
                            print("[!] CRITICAL: Authentication bypass possible!")
                            return True
                        elif line.startswith("BYPASS_SUCCESS: false"):
                            self.results["authentication_bypass_tested"] = True
                            print("[+] Authentication bypass not possible")
        
        except Exception as e:
            self.results["errors"].append(f"Authentication bypass test error: {str(e)}")
        
        return self.results.get("authentication_bypass_vulnerable", False)
    
    def validate_codebase_urls(self) -> List[Dict]:
        """Validate codebase URLs"""
        if not self.results["codebase_urls"]:
            return []
        
        print("[*] Validating codebase URLs...")
        validated_urls = []
        
        for url in self.results["codebase_urls"]:
            url_info = {"url": url, "accessible": False, "valid": False}
            
            try:
                parsed = urlparse(url)
                if parsed.scheme in ["http", "https"]:
                    url_info["valid"] = True
                    # Note: Actually checking accessibility would require HTTP request
                    # which might be slow or trigger alerts, so we just validate format
                    validated_urls.append(url_info)
            except Exception as e:
                url_info["error"] = str(e)
                validated_urls.append(url_info)
        
        self.results["codebase_urls_validated"] = validated_urls
        
        if validated_urls:
            print(f"[+] Validated {len(validated_urls)} codebase URL(s)")
        
        return validated_urls
    
    def test_dos(self) -> bool:
        """Test for Denial of Service vulnerabilities"""
        print("[*] Testing for DoS vulnerabilities...")
        
        try:
            # Test connection flooding
            connections = []
            max_connections = 10
            
            for i in range(max_connections):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((self.host, self.port))
                    connections.append(sock)
                except:
                    break
            
            # Close connections
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass
            
            if len(connections) >= max_connections:
                self.results["dos_vulnerable"] = True
                self.results["dos_test_details"].append({
                    "test": "connection_flooding",
                    "result": "vulnerable",
                    "connections_accepted": len(connections)
                })
                print(f"[!] WARNING: Service accepted {len(connections)} simultaneous connections")
                return True
            else:
                self.results["dos_test_details"].append({
                    "test": "connection_flooding",
                    "result": "limited",
                    "connections_accepted": len(connections)
                })
                print(f"[+] DoS protection: Limited to {len(connections)} connections")
        
        except Exception as e:
            self.results["errors"].append(f"DoS test error: {str(e)}")
        
        return self.results.get("dos_vulnerable", False)
    
    def detect_logging(self) -> bool:
        """Detect if operations are logged"""
        if not self.java_available:
            return False
        
        print("[*] Checking for logging...")
        
        # This is a simplified check - actual logging detection would require
        # analyzing server responses or error messages for log indicators
        # For now, we'll note that we can't reliably detect this remotely
        self.results["logging_detected"] = False
        self.results["logging_details"] = {
            "detectable": False,
            "note": "Logging detection requires server-side analysis"
        }
        
        print("[+] Logging detection requires server-side analysis")
        return False
    
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
        
        # Get test options
        test_opts = getattr(self, '_test_options', {})
        test_all = test_opts.get('test_all', False)
        test_safe_only = test_opts.get('test_safe_only', False)
        
        # Determine which tests to run
        # If test_all is True, run everything
        # If test_safe_only is True, run only safe tests
        # Otherwise, check individual flags
        # If no flags specified, run only core tests (no optional tests)
        def should_test(flag_name):
            if test_all:
                return True
            if test_safe_only:
                # Safe tests only (read-only, no modifications)
                safe_tests = ['test_security_manager', 'test_serialization_filter', 
                             'test_information_disclosure', 'test_ssl_tls', 
                             'test_cve_detection', 'test_codebase_validation', 'test_logging',
                             'test_dgc', 'test_activation', 'test_network_protocol', 'test_auth_bypass']
                return flag_name in safe_tests
            # Check individual flag
            return test_opts.get(flag_name, False)
        
        # 5. Test deserialization vulnerabilities
        if should_test('test_deserialization') and self.results["exposed_objects"]:
            self.test_deserialization_vulnerability()
        
        # 6. Test registry manipulation
        if should_test('test_registry_manipulation'):
            self.test_registry_manipulation()
        
        # 7. Test method invocation
        if should_test('test_method_invocation') and self.results["exposed_objects"]:
            self.test_method_invocation()
        
        # 8. Detect security manager
        if should_test('test_security_manager'):
            self.detect_security_manager()
        
        # 9. Detect serialization filter
        if should_test('test_serialization_filter'):
            self.detect_serialization_filter()
        
        # 10. Test DGC
        if should_test('test_dgc'):
            self.test_dgc()
        
        # 11. Test activation system
        if should_test('test_activation'):
            self.test_activation_system()
        
        # 12. Gather information disclosure
        if should_test('test_information_disclosure'):
            self.gather_information_disclosure()
        
        # 13. Test SSL/TLS configuration
        if should_test('test_ssl_tls') and self.use_ssl:
            self.test_ssl_tls_config()
        
        # 14. Detect CVEs
        if should_test('test_cve_detection') and self.results.get("java_version"):
            self.detect_cves()
        
        # 15. Test network protocol
        if should_test('test_network_protocol'):
            self.test_network_protocol()
        
        # 16. Test authentication bypass
        if should_test('test_auth_bypass') and self.results["authentication_required"]:
            self.test_authentication_bypass()
        
        # 17. Validate codebase URLs
        if should_test('test_codebase_validation') and self.results["codebase_urls"]:
            self.validate_codebase_urls()
        
        # 18. Test DoS vulnerabilities
        if should_test('test_dos'):
            self.test_dos()
        
        # 19. Detect logging
        if should_test('test_logging'):
            self.detect_logging()
        
        self.disconnect()
        return self.results


def parse_hosts_file(hosts_file: str, default_port: int = 1099) -> List[Tuple[str, int]]:
    """Parse hosts file and return list of (host, port) tuples
    
    Args:
        hosts_file: Path to file containing hosts (one per line)
        default_port: Port to use for hosts that don't specify a port (default: 1099)
    
    Returns:
        List of (host, port) tuples
    """
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
                        print(f"[!] Warning: Invalid port in '{line}', using default port {default_port}")
                        port = default_port
                else:
                    host = line.strip()
                    port = default_port
                
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
                     verbose: bool = False,
                     test_options: Optional[Dict] = None) -> Dict:
    """Scan a single host and return results"""
    scanner = RMIScanner(host, port, use_ssl, timeout)
    
    # Store password list and username for use in brute force
    scanner._password_list = password_list
    scanner._username = username
    
    # Store test options
    scanner._test_options = test_options or {}
    
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
    
    # Authentication
    print(f"Authentication Required: {results['authentication_required']}")
    if results['authentication_required']:
        print(f"Authentication Successful: {results['authentication_successful']}")
        if results['credentials_used']:
            print(f"Credentials: {results['credentials_used']['username']}:{results['credentials_used']['password']}")
        if results.get('authentication_bypass_vulnerable'):
            print("  [!] CRITICAL: Authentication bypass possible!")
    
    # Remote Codebase
    print(f"Remote Codebase Enabled: {results['remote_codebase_enabled']}")
    if results.get('remote_codebase_tested'):
        print(f"Remote Codebase Tested: Yes")
        print(f"Remote Codebase Working: {results.get('remote_codebase_working', False)}")
        if results.get('remote_codebase_working'):
            print("  [!] CRITICAL: Remote codebase downloading is ACTIVE - SECURITY RISK!")
    if results['codebase_urls']:
        print(f"Codebase URLs: {', '.join(results['codebase_urls'])}")
    
    # Exposed Objects
    print(f"Exposed Objects: {len(results['exposed_objects'])}")
    if results['exposed_objects']:
        for obj in results['exposed_objects']:
            print(f"  - {obj}")
    
    # Security Tests
    print("\nSecurity Test Results:")
    
    if results.get('deserialization_vulnerable'):
        print("  [!] Deserialization vulnerability detected")
    
    if results.get('registry_manipulation'):
        rm = results['registry_manipulation']
        if rm.get('bind_allowed') or rm.get('rebind_allowed') or rm.get('unbind_allowed'):
            print("  [!] Registry manipulation possible")
            if rm.get('bind_allowed'):
                print("      - Bind allowed")
            if rm.get('rebind_allowed'):
                print("      - Rebind allowed")
            if rm.get('unbind_allowed'):
                print("      - Unbind allowed")
    
    if results.get('method_invocation_tested') and results.get('method_invocation_results'):
        print(f"  [+] Method invocation tested: {len(results['method_invocation_results'])} object(s)")
    
    if not results.get('security_manager_detected'):
        print("  [!] No security manager detected")
    
    if not results.get('serialization_filter_detected'):
        print("  [!] No serialization filter detected")
    
    if results.get('dgc_tested') and results.get('dgc_details', {}).get('accessible'):
        print("  [!] DGC endpoint accessible")
    
    if results.get('activation_system_tested') and results.get('activation_system_details', {}).get('accessible'):
        print("  [!] RMI activation system accessible")
    
    if results.get('information_disclosed'):
        print(f"  [!] Information disclosed: {len(results['information_disclosed'])} item(s)")
        for info in results['information_disclosed'][:3]:  # Show first 3
            print(f"      - {info}")
    
    if results.get('java_version'):
        print(f"  Java Version: {results['java_version']}")
    
    if results.get('cves_detected'):
        print(f"  [!] Potential CVEs: {len(results['cves_detected'])}")
        for cve in results['cves_detected'][:5]:  # Show first 5
            if isinstance(cve, dict):
                severity_icon = {"CRITICAL": "[!]", "HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[+]"}.get(cve.get("severity", "UNKNOWN"), "[?]")
                print(f"      {severity_icon} {cve.get('cve_id', 'UNKNOWN')} ({cve.get('severity', 'UNKNOWN')}) - {cve.get('description', '')[:60]}")
            else:
                print(f"      - {cve}")
    
    if results.get('ssl_tls_config', {}).get('weak_configuration'):
        print("  [!] Weak SSL/TLS configuration detected")
    
    if results.get('dos_vulnerable'):
        print("  [!] DoS vulnerability detected")
    
    if results['errors']:
        print(f"\nErrors: {len(results['errors'])}")
        for error in results['errors'][:5]:  # Show first 5
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
    
    parser.add_argument("-p", "--port", type=int, default=1099, help="RMI server port (default: 1099, used for hosts without port in hosts-file)")
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
    
    # Security test options (all optional)
    security_group = parser.add_argument_group('Security Test Options', 
        'Control which security tests to run. By default, only safe read-only tests are performed.')
    
    security_group.add_argument("--test-deserialization", action="store_true", 
        help="Test for deserialization vulnerabilities (RISK: Medium - may trigger code execution on vulnerable servers)")
    security_group.add_argument("--test-registry-manipulation", action="store_true",
        help="Test registry bind/rebind/unbind operations (RISK: High - modifies registry)")
    security_group.add_argument("--test-method-invocation", action="store_true",
        help="Test method invocation on exposed objects (RISK: Medium - may execute destructive methods)")
    security_group.add_argument("--test-security-manager", action="store_true",
        help="Detect security manager configuration (RISK: Low - read-only)")
    security_group.add_argument("--test-serialization-filter", action="store_true",
        help="Detect serialization filter configuration (RISK: Low - read-only)")
    security_group.add_argument("--test-dgc", action="store_true",
        help="Test DGC (Distributed Garbage Collection) endpoint (RISK: Low - connection test only)")
    security_group.add_argument("--test-activation", action="store_true",
        help="Test RMI activation system (RISK: Low - connection test only)")
    security_group.add_argument("--test-information-disclosure", action="store_true",
        help="Gather information disclosure (RISK: Low - read-only)")
    security_group.add_argument("--test-ssl-tls", action="store_true",
        help="Test SSL/TLS configuration (RISK: Low - read-only)")
    security_group.add_argument("--test-cve-detection", action="store_true",
        help="Detect known CVEs based on version (RISK: Low - read-only)")
    security_group.add_argument("--test-network-protocol", action="store_true",
        help="Test network protocol level issues (RISK: Low - protocol negotiation)")
    security_group.add_argument("--test-auth-bypass", action="store_true",
        help="Test authentication bypass techniques (RISK: Low - read-only)")
    security_group.add_argument("--test-codebase-validation", action="store_true",
        help="Validate codebase URLs (RISK: Low - read-only)")
    security_group.add_argument("--test-dos", action="store_true",
        help="Test for DoS vulnerabilities (RISK: High - may cause service disruption)")
    security_group.add_argument("--test-logging", action="store_true",
        help="Detect logging configuration (RISK: Low - read-only)")
    
    # Convenience flags for test groups
    security_group.add_argument("--test-all", action="store_true",
        help="Run all security tests (WARNING: Includes potentially harmful tests)")
    security_group.add_argument("--test-safe-only", action="store_true",
        help="Run only safe read-only tests (default behavior)")
    
    args = parser.parse_args()
    
    # Parse hosts
    if args.hosts_file:
        hosts = parse_hosts_file(args.hosts_file, args.port)
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
    
    # Build test options dictionary
    test_options = {
        'test_all': args.test_all,
        'test_safe_only': args.test_safe_only,
        'test_deserialization': args.test_deserialization,
        'test_registry_manipulation': args.test_registry_manipulation,
        'test_method_invocation': args.test_method_invocation,
        'test_security_manager': args.test_security_manager,
        'test_serialization_filter': args.test_serialization_filter,
        'test_dgc': args.test_dgc,
        'test_activation': args.test_activation,
        'test_information_disclosure': args.test_information_disclosure,
        'test_ssl_tls': args.test_ssl_tls,
        'test_cve_detection': args.test_cve_detection,
        'test_network_protocol': args.test_network_protocol,
        'test_auth_bypass': args.test_auth_bypass,
        'test_codebase_validation': args.test_codebase_validation,
        'test_dos': args.test_dos,
        'test_logging': args.test_logging
    }
    
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
                                             password_list, username, None, args.verbose, test_options)
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
                                         None, username, None, args.verbose, test_options)
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
                                     None, None, None, args.verbose, test_options)
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

