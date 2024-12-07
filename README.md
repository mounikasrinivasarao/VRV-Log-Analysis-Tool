 # **VRV-Log-Analysis-Tool**

This Python-based tool is designed to process and analyze server log files for key metrics, helping system administrators and cybersecurity professionals monitor network activity. The tool parses log files to:

# **Count Requests by IP Address:** 
Identifies how many requests were made by each IP address.

# **Track Accessed Endpoints:** 
Determines which server endpoints are accessed the most.

# **Detect Suspicious Activity:** 
Flags suspicious behaviors, such as multiple failed login attempts within a short time frame.

# **Generate CSV Reports:** 
Outputs analysis results in a CSV file, making it easier for further review and reporting.

The project aims to provide insights into server traffic and potential security threats, making it an essential tool for server log analysis and cybersecurity monitoring.

# **Features:**
- Logs analysis for request counts and most accessed endpoints.
- Suspicious activity detection based on login attempts.
- Outputs results to a CSV file in a dedicated directory.
- Automatically handles directory creation for results storage.

# **Installation and Usage:**
1. Clone the repository and install Python (v3.7+).
2. Place your log file in the project folder or update the script with the correct file path.
3. Run the script to analyze the log file and generate results.

This tool is ideal for small to medium-scale server environments looking to track user activity and identify potential threats.

# **VRV Log Analysis Tool**

# **Overview**
The **VRV Log Analysis Tool** is a Python script designed to process server log files, analyze them for key metrics, and detect potential suspicious activity. The tool provides insights into:
- **Request frequency** by IP addresses
- **Most frequently accessed endpoints**
- **Suspicious activity detection** (such as multiple failed login attempts)

It is suitable for system administrators and cybersecurity analysts who need to quickly analyze server logs and detect potential malicious activity.

# **Features**
- **IP Address Requests**: Count the number of requests made by each IP address.
- **Endpoint Access**: Track which server endpoints are most frequently accessed.
- **Suspicious Activity**: Identify IP addresses that make multiple failed login attempts within a short time frame.
- **CSV Output**: Export results to a CSV file for easy viewing and further analysis.
- **Dynamic Directory Creation**: Automatically creates an output directory for storing results.

# **Requirements**
- Python 3.7 or above
- A log file formatted in a way similar to the example provided.

# **Python Libraries Used**
- Python's built-in libraries (no external dependencies):
  - `os`
  - `csv`
  - `collections`
  - `datetime`

# **Installation**
To get started with the project, follow the steps below:

1. **Clone the Repository**
Clone this project to your local machine by using Git:
git clone https://github.com/mounikasrinivasarao/VRV-Log-Analysis-Tool


2. **Navigate to Project Folder**
Change to the project directory:
cd vrv-log-analysis

3. **Ensure Python is Installed**
This project requires Python 3.7 or above. Check your Python version:
python --version

# **Folder Structure**
The project directory is organized as follows:
vrv_log_analysis/
├── log_analysis.py  # Main script that performs log analysis
├── sample.log       # Sample log file for testing
├── results/         # Folder where CSV output is stored
└── README.md        # Documentation file (you are here)

- **log_analysis.py**: This is the main script that analyzes the logs.
- **sample.log**: A sample log file that can be used for testing the tool.
- **results/**: This folder is automatically created when you run the tool. It will store the results in a CSV file.

# **Configuration**

- **Log File Path**: By default, the tool looks for a log file named `sample.log` in the project directory. You can update the `LOG_FILE` variable in the script if your log file has a different name or location.

- **Failed Login Threshold**: The script will flag an IP address as suspicious if it exceeds the specified `FAILED_LOGIN_THRESHOLD` for failed login attempts. This value can be adjusted in the script.

# **Default Settings**
- **LOG_FILE** = 'sample.log'  # Log file name
- **FAILED_LOGIN_THRESHOLD** = 5  # Threshold for failed login attempts
- **OUTPUT_DIR** = 'results'  # Directory where output CSV will be saved

# **Usage**
To use the VRV Log Analysis Tool, follow these steps:

1. **Update the Log File**
Place your log file in the project directory and name it `sample.log` (or update the script with the correct file name).

2. **Run the Script**
Run the Python script using the following command:
python log_analysis.py

The script will read the log file, analyze it, and print the following information to the console:
  - The number of requests made by each IP address.
  - The most frequently accessed endpoint.
  - Any suspicious activity based on failed login attempts.

3. **View the Results**
The analysis results will also be saved in a CSV file inside the `results/` directory. This CSV file contains:
  - IP Address
  - Number of Requests
  - Most Frequently Accessed Endpoint
  - Suspicious Activity (if detected)

# **Output Example**
**Sample Console Output:**
Starting log analysis...
Requests per IP Address:
203.0.113.5          8
198.51.100.23        8
192.168.1.1          7
10.0.0.2             6
192.168.1.100        5

Most Frequently Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
203.0.113.5          12 failed login attempts

**Generated CSV File:**

In the `results/` folder, you'll find a CSV file named `log_analysis_results.csv`:
IP Address,Number of Requests
203.0.113.5,8
198.51.100.23,8
192.168.1.1,7
...

**CSV Columns:**
- **IP Address**: The IP address that made the request.
- **Number of Requests**: The total number of requests made by that IP.
- **Most Frequently Accessed Endpoint**: The endpoint with the most hits.
- **Suspicious Activity**: Any suspicious activity detected for that IP (e.g., multiple failed login attempts).
