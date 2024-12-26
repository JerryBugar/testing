import subprocess
import os
import json
import urllib.parse

def setup_environment():
    """Setup environment dan install dependencies"""
    print("[*] Setting up environment...")
    
    try:
        # Install Python dependencies
        print("[*] Installing Python packages...")
        subprocess.run(['pip', 'install', 'beautifulsoup4', 'requests', 'tqdm', 'pyjwt', 'aiohttp', 'asyncio'], check=True)
        
        # Install Node.js dan npm
        print("[*] Installing Node.js and npm...")
        subprocess.run(['apt-get', 'update'], check=True)
        subprocess.run(['apt-get', 'install', '-y', 'nodejs', 'npm'], check=True)
        subprocess.run(['npm', 'install', '-g', 'wappalyzer'], check=True)
        
        # Install Rust
        print("[*] Installing Rust...")
        subprocess.run(['apt-get', 'install', '-y', 'curl'], check=True)
        subprocess.run(['curl', '--proto', '=https', '--tlsv1.2', '-sSf', 'https://sh.rustup.rs', '-o', 'rustup.sh'], check=True)
        subprocess.run(['chmod', '+x', 'rustup.sh'], check=True)
        subprocess.run(['./rustup.sh', '-y'], check=True)
        
        # Setup Go environment
        print("[*] Setting up Go environment...")
        subprocess.run(['apt-get', 'install', '-y', 'golang-go'], check=True)
        os.environ['GO111MODULE'] = 'on'
        
        # Create Go module
        subprocess.run(['go', 'mod', 'init', 'scanner'], check=True)
        subprocess.run(['go', 'get', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder'], check=True)
        
        print("[+] Environment setup completed successfully!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Error during setup: {str(e)}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")
        return False

def create_js_scanner():
    """Membuat script JavaScript untuk teknologi detection"""
    js_code = """
    const Wappalyzer = require('wappalyzer');
    
    async function detectTechnologies(url) {
        const wappalyzer = new Wappalyzer();
        
        try {
            await wappalyzer.init()
            const site = await wappalyzer.open(url);
            const results = await site.analyze();
            return results;
        } catch (error) {
            console.error(error);
            return null;
        } finally {
            await wappalyzer.destroy();
        }
    }
    
    const url = process.argv[2];
    detectTechnologies(url).then(results => {
        console.log(JSON.stringify(results));
    });
    """
    
    with open('tech_detector.js', 'w') as f:
        f.write(js_code)

def create_go_scanner():
    """Membuat script Go untuk subdomain enumeration"""
    go_code = """
    package main

    import (
        "fmt"
        "os"
        "github.com/projectdiscovery/subfinder/v2/pkg/runner"
    )

    func main() {
        if len(os.Args) < 2 {
            fmt.Println("Please provide a domain")
            return
        }

        domain := os.Args[1]
        options := &runner.Options{
            Threads: 10,
            Timeout: 30,
            Silent: true,
        }

        subfinder, err := runner.NewRunner(options)
        if err != nil {
            fmt.Printf("Error creating subfinder: %v\\n", err)
            return
        }

        results, err := subfinder.EnumerateMultipleDomains([]string{domain})
        if err != nil {
            fmt.Printf("Error enumerating domain: %v\\n", err)
            return
        }

        for result := range results {
            fmt.Println(result)
        }
    }
    """
    
    with open('subdomain_enum.go', 'w') as f:
        f.write(go_code)

def create_rust_scanner():
    """Membuat script Rust untuk port scanning"""
    rust_code = """
    use std::net::{TcpStream, SocketAddr};
    use std::time::Duration;
    use std::env;
    use std::str::FromStr;
    
    fn main() {
        let args: Vec<String> = env::args().collect();
        if args.len() < 2 {
            println!("Please provide a target");
            return;
        }
    
        let target = &args[1];
        let ports = vec![21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080];
    
        for port in ports {
            let addr = format!("{}:{}", target, port);
            match SocketAddr::from_str(&addr) {
                Ok(socket_addr) => {
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(1)) {
                        Ok(_) => println!("Port {} is open", port),
                        Err(_) => continue,
                    }
                }
                Err(_) => continue,
            }
        }
    }
    """
    
    with open('port_scanner.rs', 'w') as f:
        f.write(rust_code)

class AdvancedScanner:
    def __init__(self):
        if not setup_environment():
            raise Exception("Failed to setup environment")
            
        print("[*] Creating scanners...")
        create_js_scanner()
        create_go_scanner()
        create_rust_scanner()
        
        # Compile Rust scanner with error handling
        try:
            subprocess.run(['source', '$HOME/.cargo/env'], shell=True)
            subprocess.run(['rustc', 'port_scanner.rs'], check=True)
            print("[+] Rust scanner compiled successfully")
        except subprocess.CalledProcessError:
            print("[!] Failed to compile Rust scanner, falling back to Python implementation")
            self.use_rust = False
        else:
            self.use_rust = True
        
        # Original Python scanner
        self.python_scanner = BugBountyScanner(strict_mode=True)
    
    def fallback_port_scan(self, target):
        """Port scanning fallback menggunakan Python"""
        import socket
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(f"Port {port} is open")
            sock.close()
        
        return open_ports
    
    def scan_with_all_tools(self, url):
        """Menjalankan semua scanner dengan error handling"""
        results = {
            'python_scan': None,
            'js_tech_detect': None,
            'go_subdomains': None,
            'ports': None
        }
        
        # Python scan
        try:
            print("[*] Running Python vulnerability scanner...")
            self.python_scanner.scan_website(url)
            results['python_scan'] = self.python_scanner.results
        except Exception as e:
            print(f"[!] Error in Python scanner: {str(e)}")
        
        # JavaScript technology detection
        try:
            print("[*] Running JavaScript technology detection...")
            js_result = subprocess.run(['node', 'tech_detector.js', url], 
                                     capture_output=True, text=True, check=True)
            results['js_tech_detect'] = json.loads(js_result.stdout)
        except Exception as e:
            print(f"[!] Error in JavaScript scanner: {str(e)}")
        
        # Go subdomain enumeration
        try:
            print("[*] Running Go subdomain enumeration...")
            go_result = subprocess.run(['go', 'run', 'subdomain_enum.go', url],
                                     capture_output=True, text=True, check=True)
            results['go_subdomains'] = go_result.stdout.splitlines()
        except Exception as e:
            print(f"[!] Error in Go scanner: {str(e)}")
        
        # Port scanning (Rust or Python fallback)
        print("[*] Running port scanner...")
        try:
            if self.use_rust:
                rust_result = subprocess.run(['./port_scanner', url],
                                           capture_output=True, text=True, check=True)
                results['ports'] = rust_result.stdout.splitlines()
            else:
                print("[*] Using Python port scanner fallback...")
                results['ports'] = self.fallback_port_scan(urllib.parse.urlparse(url).netloc)
        except Exception as e:
            print(f"[!] Error in port scanner: {str(e)}")
        
        return results
    
    def generate_comprehensive_report(self, url, results):
        """Membuat laporan komprehensif dari semua scanner"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = {
            "target": url,
            "scan_date": timestamp,
            "vulnerabilities": results['python_scan'],
            "technology_stack": results['js_tech_detect'],
            "subdomains": results['go_subdomains'],
            "open_ports": results['ports']
        }
        
        # Save JSON report
        json_filename = f"comprehensive_report_{hashlib.md5(url.encode()).hexdigest()[:8]}_{timestamp.replace(' ','_')}.json"
        with open(json_filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        # Generate HTML report
        html = f"""
        <html>
        <head>
            <title>Comprehensive Security Report - {url}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #000000; }}
                .high {{ border-left: 5px solid #dc3545; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #28a745; }}
                .info {{ border-left: 5px solid #17a2b8; }}
                pre {{ background: #f8f9fa; padding: 10px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Comprehensive Security Report</h1>
                <p>Target: {url}</p>
                <p>Scan Date: {timestamp}</p>
            </div>
            
            <div class="section">
                <h2>Technology Stack</h2>
                <pre>{json.dumps(results['js_tech_detect'], indent=4)}</pre>
            </div>
            
            <div class="section">
                <h2>Subdomains</h2>
                <pre>{json.dumps(results['go_subdomains'], indent=4)}</pre>
            </div>
            
            <div class="section">
                <h2>Open Ports</h2>
                <pre>{json.dumps(results['ports'], indent=4)}</pre>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities</h2>
                <pre>{json.dumps(results['python_scan'], indent=4)}</pre>
            </div>
        </body>
        </html>
        """
        
        html_filename = f"comprehensive_report_{hashlib.md5(url.encode()).hexdigest()[:8]}_{timestamp.replace(' ','_')}.html"
        with open(html_filename, 'w') as f:
            f.write(html)
            
        return json_filename, html_filename

def main():
    print("""
    ╔═══════════════════════════════════════════╗
    ║   Advanced Bug Bounty Scanner - Multi-Lang ║
    ║     Created by: Professional Pentester    ║
    ╚═══════════════════════════════════════════╝
    """)
    
    url = input("\nMasukkan URL target (contoh: http://example.com): ")
    
    scanner = AdvancedScanner()
    results = scanner.scan_with_all_tools(url)
    
    json_report, html_report = scanner.generate_comprehensive_report(url, results)
    
    print(f"\n[+] Laporan JSON tersimpan di: {json_report}")
    print(f"[+] Laporan HTML tersimpan di: {html_report}")

if __name__ == "__main__":
    main() 