# Pysnort - A Simplified Snort Management Tool

## Overview

Pysnort is a Python-based tool designed to simplify the management of the Snort intrusion detection system. It provides a user-friendly interface for common Snort tasks, such as installation, configuration, rule updates, and log management. This tool is intended for educational purposes and to assist network engineers and IT professionals in managing Snort deployments.

**Disclaimer:** This tool is for educational purposes only. Do not use it for malicious activities.

## Features

-   **Snort Installation:** Automates the installation process using the system's package manager.
-   **Configuration:** Sets up a basic Snort configuration with predefined rules.
-   **Start/Stop Snort:** Easily start and stop the Snort service.
-   **Rule Management:**
    -   Update Snort rules using Oinkmaster.
    -   Create custom Snort rules and add them to `local.rules`.
    -   List, view, and delete Snort rules from `local.rules`.
-   **Log Management:**
    -   View the last few lines of the Snort log file.
    -   Search the Snort log file for specific strings.
-   **Configuration Testing:** Tests the Snort configuration file for errors.
-   **AI Assistance:** Provides AI-powered help using Google Gemini for troubleshooting.
-   **Command-Line Options:** Supports standard Snort command-line options.

## Prerequisites

-   Python 3.6+
-   Root privileges (for installation, configuration, and rule updates)
-   `colorama` library: `pip install colorama`
-   `google-generativeai` library: `pip install google-generativeai`
-   Snort (if not installing via this script)
-   Oinkmaster (for rule updates)
-   A Google Gemini API key

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Sayyad-N/pysnort.git
    cd Pysnort
    ```

2.  **Install dependencies:**

    ```bash
    pip install -r reqirements.txt 
    ```

3.  **Set up Google Gemini API Key:**

    -   Obtain a Google Gemini API key from [Google AI Studio](https://makersuite.google.com/).
    -   Set the `api_key` variable (Already Added ) in the `pysnort.py` file:

        ```python
        GenAI.configure(api_key="YOUR_API_KEY") 
        ```

## Usage

1.  **Run the script:**

    ```bash
    sudo python pysnort.py
    ```

2.  **Interact with the menu:**

    The script presents a menu with the following options:

    ```
    Snort Intrusion Detection System - Made by SayyadN

    This script simplifies Snort management for network engineers and IT professionals.

    Usage:
        1. Install Snort (Requires Root)
        2. Configure Snort (Requires Root) - Sets up basic config and local rules.
        3. Start Snort (Requires Root) - Starts Snort with specified options.
        4. Stop Snort (Requires Root) - Stops Snort.
        5. Update Snort rules (Requires Root) - Uses Oinkmaster to update rules.
        6. Test Snort Configuration (Requires Root) - Tests the Snort configuration file.
        7. Help - Displays this help message.
        8. Create Snort Rule - Create a custom snort rule and add it to local.rules
        9. View Snort Logs - Displays the last 10 lines of the Snort log file.
        10. Search Snort Logs - Searches the Snort log file for a specific string.
        11. Rule Management - List, view, and delete Snort rules from local.rules. (Requires Root)
        0. Exit
    ```

3.  **Command-Line Arguments:**

    You can also use command-line arguments to pass Snort options:

    ```
    usage: pysnort.py [-h] [-A ALERT_MODE] [-b] [-c RULES_FILE] [-C] [-d]
                       [-D] [-e] [-i INTERFACE] [-l LOG_DIR] [-s] [-T] [-v]
                       [-V] [-x] [-n PACKET_COUNT] [-q] [-Q] [-r PCAP_FILE]

    Snort Intrusion Detection System - Made by SayyadN

    options:
      -h, --help            show this help message and exit
      -A ALERT_MODE, --alert-mode ALERT_MODE
                            Set alert mode
      -b, --tcpdump         Log packets in tcpdump format
      -c RULES_FILE, --rules RULES_FILE
                            Use Rules File
      -C, --character-data  p out payloads with character data only
      -d, --dump-app-layer  Dump the Application Layer
      -D, --daemon          Run Snort in background (daemon) mode
      -e, --second-layer    Display the second layer header info
      -i INTERFACE, --interface INTERFACE
                            Listen on interface
      -l LOG_DIR, --log-dir LOG_DIR
                            Log to directory
      -s, --syslog          Log alert messages to syslog
      -T, --test-config     Test and report on the current Snort configuration
      -v, --verbose         Be verbose
      -V, --version         Show version number
      -x, --conf-error-out  Exit if Snort configuration problems occur
      -n PACKET_COUNT, --count PACKET_COUNT
                            Number of packets to process
      -q, --quiet           Quiet mode
      -Q, --queue-event     Include queue event
      -r PCAP_FILE, --pcap PCAP_FILE
                            Read packets from pcap file
    ```

    Example:

    ```bash
    sudo python pysnort.py -D -l /var/log/snort -i eth0
    ```

## Detailed Functionality

### 1. Install Snort

-   Detects the system's package manager (apt, dnf, yum, zypper, pacman, apk).
-   Installs Snort using the detected package manager.
-   Requires root privileges.

### 2. Configure Snort

-   Creates a basic Snort configuration file (`/etc/snort/snort.conf`).
-   Sets up basic local rules in `/etc/snort/rules/local.rules` to detect ICMP traffic.
-   Requires root privileges.

### 3. Start Snort

-   Starts Snort in IDS mode with the specified options.
-   Uses the configuration file `/etc/snort/snort.conf` and listens on the `eth0` interface by default.
-   Supports additional command-line options.
-   Requires root privileges.

### 4. Stop Snort

-   Stops the Snort process using `pkill`.
-   Requires root privileges.

### 5. Update Snort Rules

-   Prompts for an Oinkmaster URL.
-   Updates Snort rules using Oinkmaster.
-   Requires root privileges.

### 6. Test Snort Configuration

-   Tests the Snort configuration file for errors.
-   Requires root privileges.

### 7. Help

-   Displays the help message.

### 8. Create Snort Rule

-   Prompts for rule components (action, protocol, IP addresses, ports, message, SID, revision).
-   Validates the rule format.
-   Appends the new rule to `/etc/snort/rules/local.rules`.

### 9. View Snort Logs

-   Displays the last N lines of the Snort log file (`/var/log/snort/snort.log`).
-   Prompts for the number of lines to display.

### 10. Search Snort Logs

-   Searches the Snort log file for a specific string using `grep`.

### 11. Rule Management

-   Provides options to list, view, and delete Snort rules from `local.rules`.
-   Requires root privileges.

## Error Handling and AI Assistance

-   The script includes comprehensive error handling for common issues, such as missing dependencies, incorrect permissions, and invalid input.
-   In case of an error, the script attempts to provide AI-powered assistance using the Google Gemini API.
-   The AI assistance can help troubleshoot the issue and provide potential solutions.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues to suggest improvements or report bugs.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

SayyadN

## Version

1.0 (Date: 2025-04-01)
