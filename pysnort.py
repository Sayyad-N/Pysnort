# Code Written By SayyadN
# Code Written For Educational Purposes Only
# Do Not Use This Code For Malicious Purposes
# This code is a base of a Snort intrusion detection system using Python.
# Version 1.0
# Date: 2025-04-01

# Import necessary libraries
import subprocess
import shutil
import sys
import google.generativeai as GenAI
import logging
from colorama import Fore, Back, init
import argparse
import os
import time  # For animations
import re # Regular expressions for rule validation

# Initialize colorama
init(autoreset=True)

# Define aliases for p and input
p = print
i = input
run = subprocess.run

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define package manager commands
pm_commands = {
    "apt": {
        "install": ["apt", "install", "-y"]
    },
    "dnf": {
        "install": ["dnf", "install", "-y"]
    },
    "yum": {
        "install": ["yum", "install", "-y"]
    },
    "zypper": {
        "install": ["zypper", "install", "-y"]
    },
    "pacman": {
        "install": ["pacman", "-S", "--noconfirm"]
    },
    "apk": {
        "install": ["apk", "add"]
    },
}

# Function to detect the package manager
def detect_package_manager():
    for pm in pm_commands:
        if shutil.which(pm):
            return pm
    return None

# Function to install Snort using the detected package manager
def install_snort():
    try:
        # Detect the package manager
        package_manager = detect_package_manager()
        if not package_manager:
            p(Fore.RED + "No supported package manager found on this system.")
            ai_help("No supported package manager found.")
            sys.exit(1)

        # Check if Snort is already installed
        if shutil.which("snort") is not None:
            p("Snort is already installed.")
            return

        # Install Snort using the detected package manager
        p(f"Installing Snort using {package_manager}...")
        if os.geteuid() != 0:
            p("Please run as root to install Snort.")
            return

        run_package_manager_command(package_manager, "install", "snort")

        p("Snort installed successfully.")
    except subprocess.CalledProcessError as e:
        p(f"Error installing Snort: {e}")
        ai_help(str(e))
        sys.exit(1)
    except Exception as e:
        p(f"An unexpected error occurred: {e}")
        ai_help(str(e))
        sys.exit(1)
    finally:
        p("Installation process completed.")

# Function to execute package manager commands
def run_package_manager_command(package_manager, command, package_name):
    try:
        if package_manager not in pm_commands:
            raise ValueError(f"Unsupported package manager: {package_manager}")

        if command not in pm_commands[package_manager]:
            raise ValueError(f"Unsupported command: {command}")

        cmd = pm_commands[package_manager][command] + [package_name]
        p(f"Executing: {' '.join(cmd)}")
        run(cmd, check=True, capture_output=True, text=True)
        p(f"{command.capitalize()}ed {package_name} successfully using {package_manager}.")

    except subprocess.CalledProcessError as e:
        p(f"Error executing command: {e}")
        ai_help(str(e))
        sys.exit(1)
    except ValueError as e:
        p(e)
        ai_help(str(e))
        sys.exit(1)
    except Exception as e:
        p(f"An unexpected error occurred: {e}")
        ai_help(str(e))
        sys.exit(1)

# Function to get AI help for package management
def ai_help(error_message):
    try:
        GenAI.configure(api_key="AIzaSyCD9b_cGg1Aw0yI_Awt6ufO80V88OlkdbY")
        model = GenAI.GenerativeModel("gemini-2.0-flash")
        while True:
            response = model.generate_content(error_message)
            p(Fore.GREEN + Back.WHITE + response.text + "\nPowered By SayyadN")
            user_input = i("You can exit by typing 'exit'. Do you need more help? (Y/N): ").lower()
            if user_input in ["exit", "n"]:
                break
            elif user_input == "y":
                error_message = i("Please provide more details about the issue: ")
            else:
                p(Fore.RED + "Invalid input, please try again.")
    except Exception as ex:
        p(Fore.RED + f"AI help is currently unavailable: {ex}")

# Function to configure Snort
def snort_config():
    try:
        # Check if Snort is installed
        if shutil.which("snort") is None:
            p("Snort is not installed. Please install it first.")
            return

        # Create a basic Snort configuration file
        p("Configuring Snort...")
        if os.geteuid() != 0:
            p("Please run as root to configure Snort.")
            return
        config_content = """
# Basic Snort configuration file
var HOME_NET 192.168.1.0/24
var EXTERNAL_NET any
var RULE_PATH /etc/snort/rules
include $RULE_PATH/local.rules
output unified2: filename snort.log, limit 128
output alert_fast: stdout
"""
        with open("/etc/snort/snort.conf", "w") as config_file:
            config_file.write(config_content)
        p("Snort configured successfully.")
        # Configure local.rules
        local_rules_content = """
alert icmp any any -> $HOME_NET any (msg:"ICMP traffic detected"; sid:1000001; rev:1;)
        """
        with open("/etc/snort/rules/local.rules", "w") as local_rules_file:
            local_rules_file.write(local_rules_content)
        p("Basic local rules configured.")
    except PermissionError as e:
        p("Permission denied. Please run as root.")
        ai_help(str(e))
    except FileNotFoundError as e:
        p("Snort configuration file not found.")
        ai_help(str(e))
    except Exception as e:
        p(f"An unexpected error occurred: {e}")
        ai_help(str(e))
    finally:
        p("Configuration process completed.")

# Function to start Snort
def start_snort(options=None):
    try:
        # Check if Snort is installed
        if shutil.which("snort") is None:
            p("Snort is not installed. Please install it first.")
            return

        # Build Snort command
        command = ["snort", "-c", "/etc/snort/snort.conf", "-i", "eth0"]
        if options:
            command.extend(options)

        # Start Snort in IDS mode
        p("Starting Snort...")
        p(f"Executing Snort command: {' '.join(command)}")  # p the full command
        if os.geteuid() != 0:
            p("Please run as root to start Snort.")
            return
        run(command, check=True)
        p("Snort started successfully.")
    except subprocess.CalledProcessError as e:
        p(f"Error starting Snort: {e}")
        ai_help(str(e))
    except Exception as e:
        p(f"An unexpected error occurred: {e}")
        ai_help(str(e))
    finally:
        p("Start process completed.")

# Function to stop Snort
def stop_snort():
    try:
        # Check if Snort is running
        if shutil.which("snort") is None:
            p("Snort is not installed. Please install it first.")
            return

        # Stop Snort
        p("Stopping Snort...")
        if os.geteuid() != 0:
            p("Please run as root to stop Snort.")
            return
        run(["pkill", "snort"], check=True)
        p("Snort stopped successfully.")
    except subprocess.CalledProcessError as e:
        p(f"Error stopping Snort: {e}")
        ai_help(str(e))
    except Exception as e:
        p(f"An unexpected error occurred: {e}")
        ai_help(str(e))
    finally:
        p("Stop process completed.")

# Function to update Snort rules
def update_snort_rules():
    try:
        # Check if Snort is installed
        if shutil.which("snort") is None:
            p("Snort is not installed. Please install it first.")
            return

        # Update Snort rules
        p("Updating Snort rules...")
        if os.geteuid() != 0:
            p("Please run as root to update Snort rules.")
            return
        # Prompt the user for the Oinkmaster URL
        oinkmaster_url = input("Enter your Oinkmaster rule URL: ").strip()
        run(["oinkmaster", "-o", "/etc/snort/rules", "-u", oinkmaster_url], check=True)
        p("Snort rules updated successfully.")
    except subprocess.CalledProcessError as e:
        p(f"Error updating Snort rules: {e}")
        ai_help(str(e))
    except Exception as e:
        p(f"An unexpected error occurred: {e}")
        ai_help(str(e))
    finally:
        p("Update process completed.")

# Function to test Snort configuration
def test_snort_config():
    try:
        # Check if Snort is installed
        if shutil.which("snort") is None:
            p("Snort is not installed. Please install it first.")
            return

        # Test Snort configuration
        p("Testing Snort configuration...")
        if os.geteuid() != 0:
            p("Please run as root to test Snort configuration.")
            return
        run(["snort", "-T", "-c", "/etc/snort/snort.conf"], check=True)
        p("Snort configuration test completed successfully.")
    except subprocess.CalledProcessError as e:
        p(f"Error testing Snort configuration: {e}")
        ai_help(str(e))
    except Exception as e:
        p(f"An unexpected error occurred: {e}")
        ai_help(str(e))
    finally:
        p("Configuration test process completed.")

# Function to validate a Snort rule
def validate_snort_rule(rule):
    # This is a basic regex, you might need a more complex one
    pattern = r"^(alert|log|pass|drop|reject|sdrop) (tcp|udp|icmp|ip) any any -> any any \(msg:\"[^\"]*\"; sid:\d+; rev:\d+;\)$"
    return bool(re.match(pattern, rule))

# Function to create a new Snort rule
def create_snort_rule():
    try:
        p("Creating a new Snort rule...")
        action = input("Enter the action (e.g., alert, log, pass): ").strip()
        protocol = input("Enter the protocol (e.g., tcp, udp, icmp): ").strip()
        source_ip = input("Enter the source IP (e.g., any, 192.168.1.0/24): ").strip()
        source_port = input("Enter the source port (e.g., any, 80): ").strip()
        direction = input("Enter the direction (e.g., ->, <>): ").strip()
        dest_ip = input("Enter the destination IP (e.g., any, 192.168.1.0/24): ").strip()
        dest_port = input("Enter the destination port (e.g., any, 80): ").strip()
        msg = input("Enter the message (e.g., \"Traffic detected\"): ").strip()
        sid = input("Enter the Snort ID (SID): ").strip()
        rev = input("Enter the revision (rev): ").strip()

        rule = f'{action} {protocol} {source_ip} {source_port} {direction} {dest_ip} {dest_port} (msg:"{msg}"; sid:{sid}; rev:{rev};)'

        # Validate the rule before writing it
        if not validate_snort_rule(rule):
            p(Fore.RED + "Invalid Snort rule format. Please check your input." + Fore.RESET)
            return

        with open("/etc/snort/rules/local.rules", "a") as local_rules_file:
            local_rules_file.write(rule + "\n")

        p("Snort rule created successfully.")

    except Exception as e:
        p(f"An unexpected error occurred: {e}")
        ai_help(str(e))
    finally:
        p("Rule creation process completed.")

# Function to display help
def display_help():
    help_text = f"""
    {Fore.CYAN}{Back.BLACK}Snort Intrusion Detection System - Made by SayyadN{Fore.RESET}{Back.RESET}

    {Fore.YELLOW}This script simplifies Snort management for network engineers and IT professionals.{Fore.RESET}

    {Fore.GREEN}Usage:{Fore.RESET}
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

    {Fore.BLUE}Additional Snort Command-Line Options:{Fore.RESET}
        You can pass standard Snort command-line options using the -A, -b, -c, etc. arguments.
        For example:
            -A <alert_mode> : Set alert mode (e.g., console, fast, full)
            -b : Log packets in tcpdump format
            -c <rules_file> : Use a specific rules file
            -i <interface> : Listen on a specific interface (e.g., eth0, wlan0)
            -l <log_dir> : Specify the log directory
            -T : Test the Snort configuration
            -n <number> : Number of packets to process (added feature)
            -q : Quiet mode (added feature)
            -Q : Include queue event (added feature)
            -r <pcap_file> : Read packets from pcap file (added feature)

    {Fore.MAGENTA}Example Usage:{Fore.RESET}
        To start Snort in daemon mode, logging to /var/log/snort, use:
        `python pysnort.py -D -l /var/log/snort`

    {Fore.RED}Note: Most operations require root privileges.  Run the script with `sudo`.{Fore.RESET}
    """
    p(help_text)

# Function to view Snort logs
def view_snort_logs():
    try:
        log_file = "/var/log/snort/snort.log"  # Adjust path if needed
        if not os.path.exists(log_file):
            p(Fore.RED + "Snort log file not found." + Fore.RESET)
            return

        num_lines = input("Enter the number of lines to display (default is 10): ").strip()
        if not num_lines:
            num_lines = "10"  # Default value
        if not num_lines.isdigit():
            p(Fore.RED + "Invalid input. Please enter a number." + Fore.RESET)
            return

        p(f"Displaying last {num_lines} lines of Snort log:")
        run(["tail", "-n", num_lines, log_file], check=True)

    except subprocess.CalledProcessError as e:
        p(f"Error viewing Snort logs: {e}")
        ai_help(str(e))
    except Exception as e:
        p(f"An unexpected error occurred: {e}")
        ai_help(str(e))
    finally:
        p("Log viewing process completed.")

# Function to search Snort logs
def search_snort_logs():
    try:
        log_file = "/var/log/snort/snort.log"  # Adjust path if needed
        if not os.path.exists(log_file):
            p(Fore.RED + "Snort log file not found." + Fore.RESET)
            return

        search_string = input("Enter the string to search for in the logs: ").strip()
        p(f"Searching Snort logs for '{search_string}':")
        run(["grep", search_string, log_file], check=True)

    except subprocess.CalledProcessError as e:
        p(f"Error searching Snort logs: {e}")
        ai_help(str(e))
    except Exception as e:
        p(f"An unexpected error occurred: {e}")
        ai_help(str(e))
    finally:
        p("Log searching process completed.")

# Function for rule management (list, view, delete)
def manage_snort_rules():
    rules_file = "/etc/snort/rules/local.rules"
    if not os.path.exists(rules_file):
        p(Fore.RED + "Snort local rules file not found." + Fore.RESET)
        return

    if os.geteuid() != 0:
        p("Please run as root to manage Snort rules.")
        return

    while True:
        p("\nRule Management Options:")
        p("1. List Rules")
        p("2. View Rule")
        p("3. Delete Rule")
        p("4. Back to Main Menu")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            list_snort_rules(rules_file)
        elif choice == "2":
            view_snort_rule(rules_file)
        elif choice == "3":
            delete_snort_rule(rules_file)
        elif choice == "4":
            break
        else:
            p(Fore.RED + "Invalid choice. Please try again." + Fore.RESET)

# Function to list Snort rules
def list_snort_rules(rules_file):
    try:
        with open(rules_file, "r") as f:
            rules = f.readlines()
            if not rules:
                p("No rules found in local.rules.")
                return

            p("\nListing Snort Rules:")
            for i, rule in enumerate(rules):
                p(f"{i+1}. {rule.strip()}")

    except Exception as e:
        p(f"Error listing Snort rules: {e}")
        ai_help(str(e))

# Function to view a specific Snort rule
def view_snort_rule(rules_file):
    try:
        list_snort_rules(rules_file)  # Display rules with index numbers
        rule_number = input("Enter the rule number to view: ").strip()
        if not rule_number.isdigit():
            p(Fore.RED + "Invalid input. Please enter a number." + Fore.RESET)
            return

        rule_number = int(rule_number)
        with open(rules_file, "r") as f:
            rules = f.readlines()
            if 1 <= rule_number <= len(rules):
                p("\nViewing Snort Rule:")
                p(rules[rule_number - 1].strip())
            else:
                p(Fore.RED + "Invalid rule number." + Fore.RESET)

    except Exception as e:
        p(f"Error viewing Snort rule: {e}")
        ai_help(str(e))

# Function to delete a Snort rule
def delete_snort_rule(rules_file):
    try:
        list_snort_rules(rules_file)  # Display rules with index numbers
        rule_number = input("Enter the rule number to delete: ").strip()
        if not rule_number.isdigit():
            p(Fore.RED + "Invalid input. Please enter a number." + Fore.RESET)
            return

        rule_number = int(rule_number)
        with open(rules_file, "r") as f:
            rules = f.readlines()

        if 1 <= rule_number <= len(rules):
            del rules[rule_number - 1]  # Delete the selected rule

            with open(rules_file, "w") as f:
                f.writelines(rules)  # Write the updated rules back to the file

            p(Fore.GREEN + "Snort rule deleted successfully." + Fore.RESET)
        else:
            p(Fore.RED + "Invalid rule number." + Fore.RESET)

    except Exception as e:
        p(f"Error deleting Snort rule: {e}")
        ai_help(str(e))

# Function for a loading animation
def loading_animation(message):
    chars = "/—\|"
    for char in chars:
        p(f"\r{message} {char}", end="")
        time.sleep(0.1)
    p("\r" + " " * len(message + " " + chars) + "\r", end="")  # Clear the line

# Main function to handle command line arguments
def main():
    parser = argparse.ArgumentParser(description="Snort Intrusion Detection System - Made by SayyadN")
    parser.add_argument("-A", "--alert-mode", dest="alert_mode", help="Set alert mode")
    parser.add_argument("-b", "--tcpdump", action="store_true", help="Log packets in tcpdump format")
    parser.add_argument("-c", "--rules", dest="rules_file", help="Use Rules File")
    parser.add_argument("-C", "--character-data", action="store_true", help="p out payloads with character data only")
    parser.add_argument("-d", "--dump-app-layer", action="store_true", help="Dump the Application Layer")
    parser.add_argument("-D", "--daemon", action="store_true", help="Run Snort in background (daemon) mode")
    parser.add_argument("-e", "--second-layer", action="store_true", help="Display the second layer header info")
    parser.add_argument("-i", "--interface", dest="interface", help="Listen on interface")
    parser.add_argument("-l", "--log-dir", dest="log_dir", help="Log to directory")
    parser.add_argument("-s", "--syslog", action="store_true", help="Log alert messages to syslog")
    parser.add_argument("-T", "--test-config", action="store_true", help="Test and report on the current Snort configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Be verbose")
    parser.add_argument("-V", "--version", action="store_true", help="Show version number")
    parser.add_argument("-x", "--conf-error-out", action="store_true", help="Exit if Snort configuration problems occur")
    parser.add_argument("-n", "--count", dest="packet_count", type=int, help="Number of packets to process")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-Q", "--queue-event", action="store_true", help="Include queue event")
    parser.add_argument("-r", "--pcap", dest="pcap_file", help="Read packets from pcap file")
    args = parser.parse_args()

    snort_options = []
    if args.alert_mode:
        snort_options.extend(["-A", args.alert_mode])
    if args.tcpdump:
        snort_options.append("-b")
    if args.rules_file:
        snort_options.extend(["-c", args.rules_file])
    if args.character_data:
        snort_options.append("-C")
    if args.dump_app_layer:
        snort_options.append("-d")
    if args.daemon:
        snort_options.append("-D")
    if args.second_layer:
        snort_options.append("-e")
    if args.interface:
        snort_options.extend(["-i", args.interface])
    if args.log_dir:
        snort_options.extend(["-l", args.log_dir])
    if args.syslog:
        snort_options.append("-s")
    if args.test_config:
        snort_options.append("-T")
    if args.verbose:
        snort_options.append("-v")
    if args.version:
        snort_options.append("-V")
    if args.conf_error_out:
        snort_options.append("-x")
    if args.packet_count:
        snort_options.extend(["-n", str(args.packet_count)])
    if args.quiet:
        snort_options.append("-q")
    if args.queue_event:
        snort_options.append("-Q")
    if args.pcap_file:
        snort_options.extend(["-r", args.pcap_file])

    while True:
        display_help()
        choice = input("Enter your choice: ").strip()

        if choice == "0":
            p("Exiting...")
            sys.exit(0)
        elif choice == "1":
            install_snort()
        elif choice == "2":
            snort_config()
        elif choice == "3":
            start_snort(snort_options)
        elif choice == "4":
            stop_snort()
        elif choice == "5":
            update_snort_rules()
        elif choice == "6":
            test_snort_config()
        elif choice == "7":
            display_help()
        elif choice == "8":
            create_snort_rule()
        elif choice == "9":
            view_snort_logs()
        elif choice == "10":
            search_snort_logs()
        elif choice == "11":
            manage_snort_rules()
        else:
            p(f"Unknown command: {choice}")

if __name__ == "__main__":
    main()
