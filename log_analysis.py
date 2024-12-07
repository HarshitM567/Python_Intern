import re
import csv
from collections import Counter, defaultdict

# Configuration for suspicious activity threshold
FAILED_LOGIN_THRESHOLD = 10


# Function to parse log file
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs


# Function to count requests per IP
def count_requests_by_ip(logs):
    ip_counter = Counter()
    for log in logs:
        match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', log)
        if match:
            ip_counter[match.group(1)] += 1
    return ip_counter


# Function to identify the most accessed endpoint
def find_most_accessed_endpoint(logs):
    endpoint_counter = Counter()
    for log in logs:
        match = re.search(r'\"(?:GET|POST|PUT|DELETE) (/\S*)', log)
        if match:
            endpoint_counter[match.group(1)] += 1
    most_accessed = endpoint_counter.most_common(1)
    return most_accessed[0] if most_accessed else None


# Function to detect suspicious activity
def detect_suspicious_activity(logs):
    failed_logins = defaultdict(int)
    for log in logs:
        if '401' in log or 'Invalid credentials' in log:
            match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', log)
            if match:
                failed_logins[match.group(1)] += 1
    return {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}


# Function to save results to CSV
def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        # Write IP requests
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])  # Blank line for separation

        # Write most accessed endpoint
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        if most_accessed_endpoint:
            writer.writerow(most_accessed_endpoint)
        writer.writerow([])  # Blank line for separation

        # Write suspicious activity
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


# Main function to process the log and display results
def main():
    log_file = 'sample.log'
    output_csv = 'log_analysis_results.csv'

    logs = parse_log_file(log_file)

    # Count requests by IP
    ip_counts = count_requests_by_ip(logs)
    print("IP Address           Request Count")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20}{count}")

    # Identify most accessed endpoint
    most_accessed_endpoint = find_most_accessed_endpoint(logs)
    if most_accessed_endpoint:
        print(
            f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(logs)
    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count}")

    # Save results to CSV
    save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips, output_csv)
    print(f"\nResults saved to {output_csv}")


# Entry point
if __name__ == '__main__':
    main()
