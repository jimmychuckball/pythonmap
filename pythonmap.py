import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def attempt_version_detection(s):
    """Attempt to send a generic version command."""
    try:
        # This is a naive and generic 'version' command; most services will not respond to this.
        s.sendall(b'VERSION\r\n')
        return s.recv(1024).decode('utf-8', 'ignore').strip()
    except Exception as e:
        print(f"Error attempting version detection: {e}")
        return ''

def scan_port(ip, port, callback=None, retries=5, timeout=3):
    """Try to connect to a specified port on a specified IP address and attempt to identify service version."""
    service_info = None
    while retries > 0:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    try:
                        service_info = attempt_version_detection(s)
                    except Exception as e:
                        print(f"Error getting version information for port {port}: {e}")

                    # Try to determine the service name if possible
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except socket.error:
                        service = 'unknown'

                    if callback:
                        callback(port, service, service_info)

                    return (port, service, service_info)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            retries -= 1
    return None

def report_open_port(port, service, response):
    """The callback function to report an open port and any version info."""
    print(f"Port {port} is open! (Service: {service})")
    print(f"Response: {response}")
    print(flush=True)

def scan_ports(ip, ports, callback=None):
    """Scan ports in parallel and call the callback function if an open port is found."""
    total_ports = len(ports)
    ports_scanned = 0
    status_interval = max(total_ports // 20, 1)  # 5% of total ports or at least 1

    results = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, callback): port for port in ports}
        for future in as_completed(future_to_port):
            ports_scanned += 1
            if ports_scanned % status_interval == 0 or ports_scanned == total_ports:
                print(f"{(ports_scanned / total_ports) * 100:.2f}% complete", flush=True)

            result = future.result()
            if result:
                results.append(result)

    return results

if __name__ == "__main__":
    target = input("Enter the IP to scan: ").strip()
    range_input = input("Enter port range (e.g. '20-100'): ")
    start_port, end_port = map(int, range_input.split('-'))

    file_name = input("Enter the filename to save the results: ")

    ports = range(start_port, end_port + 1)
    print(f"Starting scan on {target} for ports {start_port} to {end_port}")

    open_ports = scan_ports(target, ports, callback=report_open_port)

    with open(file_name, 'w') as file:
        for port, service, response in open_ports:
            file.write(f"Port {port} is open! (Service: {service})\n")
            file.write(f"Response: {response}\n\n")

    print(f"Scan complete. Results saved to {file_name}")
