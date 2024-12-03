# Log Analysis Script

This Python script processes log files to extract and analyze key information. The primary objectives of the script are:
1. **Count Requests per IP Address**: It parses the log file to count requests made by each IP address and displays the results in descending order.
2. **Identify the Most Frequently Accessed Endpoint**: The script identifies the endpoint that is accessed the most times in the log.
3. **Detect Suspicious Activity**: It detects potential brute force login attempts by identifying IP addresses that have failed login attempts exceeding a set threshold.

## Features
- **Count Requests per IP Address**: 
    - Extracts and counts the number of requests made by each IP address.
    - Sorts the IP addresses based on the request count in descending order.
  
- **Identify the Most Frequently Accessed Endpoint**:
    - Extracts the endpoints from the log file and determines which one is accessed the most.

- **Detect Suspicious Activity**:
    - Identifies failed login attempts (status code `401` or invalid credentials message) and flags IP addresses with failed attempts exceeding a threshold (default: 10).

- **Results Export**: 
    - The results are displayed on the terminal and also saved to a CSV file (`log_analysis_results.csv`) containing:
        - Requests per IP address
        - Most accessed endpoint
        - Suspicious activity (IP address with failed login attempts)

## Requirements
- Python 3.x
- `csv` (For saving results in CSV format)

## How to Use

1. **Download the log file**: Ensure you have a log file (e.g., `sample.log`) that follows a similar format as described.
2. **Run the script**:
    - Clone the repository or download the script.
    - Ensure your log file is placed in the same directory or provide the path to the log file.
    - Execute the script by running:
      ```bash
      python main.py
      ```
3. **View results**: The results will be displayed in the terminal and saved to a CSV file (`log_analysis_results.csv`).


