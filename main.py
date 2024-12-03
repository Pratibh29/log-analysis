import csv

# Function to read the log file
def read_log_file(filename):
    try:
        with open(filename, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return []

# Function to count requests per IP
def count_requests_by_ip(log_lines):
    ip_counts = {}
    for line in log_lines:
        parts = line.split()
        if parts:  # Ensure the line is not empty
            ip = parts[0]
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    return ip_counts

# Function to find the most accessed endpoint
def find_most_accessed_endpoint(log_lines):
    endpoint_counts = {}
    for line in log_lines:
        if '"' in line: 
            parts = line.split('"')
            if len(parts) > 1:
                request = parts[1]  
                if request.startswith("GET") or request.startswith("POST"):  
                    endpoint = request.split()[1]  
                    endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
    if endpoint_counts:
        most_accessed = max(endpoint_counts, key=endpoint_counts.get)
        return most_accessed, endpoint_counts[most_accessed]
    return None, 0


def find_suspicious_ips(log_lines, threshold=10):
    failed_login_ips = {}
    for line in log_lines:
        # Check for failed login attempts explicitly
        if '401' in line and 'Invalid credentials' in line:
            parts = line.split()
            if parts:
                ip = parts[0]  # First element is the IP address
                failed_login_ips[ip] = failed_login_ips.get(ip, 0) + 1
    
    # Filter suspicious IPs based on the threshold
    # If threshold is not met, we'll return all failed login IPs to show in CSV
    suspicious_ips = failed_login_ips
    
    print("Failed Login IPs:", failed_login_ips)
    
    return suspicious_ips

# Function to save results to a CSV file
def save_results_to_csv(ip_requests, most_accessed, suspicious_ips, filename="log_analysis_results.csv"):
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        writer.writerow([])  
        
        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        
        writer.writerow([])  
        
        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    log_filename = "sample.log"  # Log file name
    log_lines = read_log_file(log_filename)
    
    if not log_lines:
        return  
    
    # Analyze log file
    ip_requests = count_requests_by_ip(log_lines)
    most_accessed = find_most_accessed_endpoint(log_lines)
    suspicious_ips = find_suspicious_ips(log_lines)
    
    # Display results
    print("Requests per IP Address:")
    for ip, count in ip_requests.items():
        print(f"{ip}: {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed[0]:
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    else:
        print("No endpoints found.")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip}: {count} failed login attempts")
    else:
        print("No suspicious activity detected.")
    
    # Save results to a CSV file
    save_results_to_csv(ip_requests, most_accessed, suspicious_ips)
    print("\nResults saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()

