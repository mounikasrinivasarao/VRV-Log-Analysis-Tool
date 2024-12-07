import os
import csv
from collections import defaultdict

# Configuration
LOG_FILE = "vrv_log_analysis\sample.log"  # Name of the log file to analyze
OUTPUT_DIR = os.path.join(os.getcwd(), "results")  # Directory to save the CSV file
OUTPUT_CSV = "log_analysis_results.csv"  # Name of the CSV file
FAILED_LOGIN_THRESHOLD = 10  # Configurable threshold for failed logins


def parse_log_file(file_path):
    """
    Parses the log file and extracts necessary information.
    """
    ip_requests = defaultdict(int)
    endpoint_count = defaultdict(int)
    suspicious_activity = defaultdict(int)

    try:
        with open(file_path, "r") as file:
            for line in file:
                parts = line.split()
                if len(parts) < 9:
                    continue

                ip_address = parts[0]
                endpoint = parts[6]
                status_code = parts[8]

                # Count requests per IP address
                ip_requests[ip_address] += 1

                # Count requests per endpoint
                endpoint_count[endpoint] += 1

                # Check for suspicious activity (e.g., failed login attempts)
                if status_code.startswith("4"):  # Client-side errors
                    if "login" in endpoint.lower():
                        suspicious_activity[ip_address] += 1

    except FileNotFoundError:
        print(f"Log file {file_path} not found.")
        return None, None, None, None

    return ip_requests, endpoint_count, suspicious_activity


def analyze_data(ip_requests, endpoint_count, suspicious_activity):
    """
    Performs analysis on the parsed data.
    """
    # Find the most accessed endpoint
    most_accessed_endpoint = max(endpoint_count.items(), key=lambda x: x[1])

    # Detect IP addresses exceeding the failed login threshold
    suspicious_ips = {
        ip: count
        for ip, count in suspicious_activity.items()
        if count > FAILED_LOGIN_THRESHOLD
    }

    return most_accessed_endpoint, suspicious_ips


def write_to_csv(ip_requests, endpoint_count, most_accessed_endpoint, suspicious_activity):
    """
    Writes the analysis results to a CSV file.
    """
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    output_file_path = os.path.join(OUTPUT_DIR, OUTPUT_CSV)

    with open(output_file_path, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)

        # Write requests per IP address
        writer.writerow(["IP Address", "Number of Requests"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        writer.writerow([])  # Blank row for separation

        # Write most accessed endpoint
        writer.writerow(["Most Frequently Accessed Endpoint", "Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])  # Blank row for separation

        # Write suspicious activity
        writer.writerow(["Suspicious IPs", "Failed Login Attempts"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

    print(f"Analysis results saved to {output_file_path}")


def main():
    """
    Main function to orchestrate the log analysis process.
    """
    print("Starting log analysis...\n")

    # Step 1: Parse the log file
    ip_requests, endpoint_count, suspicious_activity = parse_log_file(LOG_FILE)

    if ip_requests is None:
        return

    # Step 2: Analyze the data
    most_accessed_endpoint, suspicious_ips = analyze_data(
        ip_requests, endpoint_count, suspicious_activity
    )

    # Step 3: Display results
    print("Requests per IP Address:")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count} failed login attempts")
    else:
        print("No suspicious activity detected.")

    # Step 4: Write results to CSV
    write_to_csv(ip_requests, endpoint_count, most_accessed_endpoint, suspicious_ips)


if __name__ == "__main__":
    main()