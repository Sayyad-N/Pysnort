#!/bin/bash

# Banner to display
banner() {
    echo "8888888                   888             888 888       888      d8b 888                       "
    echo "  888                     888             888 888       888      Y8P 888                       "
    echo "  888                     888             888 888       888          888                       "
    echo "  888   88888b.  .d8888b  888888  8888b.  888 888       888      888 88888b.  .d8888b         "
    echo "  888   888 \"88b 88K      888        \"88b 888 888       888      888 888 \"88b 88K              "
    echo "  888   888  888 \"Y8888b. 888    .d888888 888 888       888      888 888  888 \"Y8888b.        "
    echo "  888   888  888      X88 Y88b.  888  888 888 888       888      888 888 d88P      X88        "
    echo "8888888 888  888  88888P'  \"Y888 \"Y888888 888 888       88888888 888 88888P\"   88888P'        "
    echo "888888b.                   .d8888b.                                           888 888b    888      "
    echo "888  \"88b                 d88P  Y88b                                          888 8888b   888      "
    echo "888  .88P                 Y88b.                                               888 88888b  888      "
    echo "8888888K.  888  888        \"Y888b.    8888b.  888  888 888  888  8888b.   .d88888 888Y88b 888  "
    echo "888  \"Y88b 888  888           \"Y88b.     \"88b 888  888 888  888     \"88b d88\" 888 888 Y88b888 "
    echo "888    888 888  888             \"888 .d888888 888  888 888  888 .d888888 888  888 888  Y88888 "
    echo "888   d88P Y88b 888       Y88b  d88P 888  888 Y88b 888 Y88b 888 888  888 Y88b 888 888   Y8888  "
    echo "8888888P\"   \"Y88888        \"Y8888P\"  \"Y888888  \"Y88888  \"Y88888 \"Y888888  \"Y88888 888    Y888 "
    echo "                888                                888      888                                "
    echo "           Y8b d88P                           Y8b d88P Y8b d88P                                "
    echo "            \"Y88P\"                             \"Y88P\"   \"Y88P\"                                 "
}
# Function to check for package manager and install Snort and Required Libraries
install_snort_dependencies() {
    # Check for package manager
    if command -v apt &>/dev/null; then
        echo "Using apt package manager (Debian/Ubuntu)..."
        sudo apt update
        sudo apt install -y snort
    elif command -v dnf &>/dev/null; then
        echo "Using dnf package manager (Fedora)..."
        sudo dnf install -y snort
    elif command -v zypper &>/dev/null; then
        echo "Using zypper package manager (openSUSE)..."
        sudo zypper install -y snort
    elif command -v pacman &>/dev/null; then
        echo "Using pacman package manager (Arch Linux)..."
        sudo pacman -Sy --noconfirm snort
    else
        echo "Package manager not found. Please install Snort manually."
        exit 1
    fi
}
# Install required Python libraries
install_python_libraries() {
    echo "Installing required Python libraries..."
    pip3 install  google-generativeai colorama psutil google-genai
}

# Function to run script with admin privileges
run_as_admin() {
    if [ "$(id -u)" != "0" ]; then
        echo "This script needs to be run as root. Re-running with sudo..."
        sudo bash "$0"
        exit
    fi
}

# Main execution starts here
run_as_admin
banner
install_dependencies
install_python_libraries

echo "Installation completed successfully."
echo "Powered By SayyadN"
echo "If you encounter any issues, please alert me at this email : mohammed_sayyad@keemail.me"
