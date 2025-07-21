# 🛡️ VulnScan Reporter

A lightweight, automated, and interactive vulnerability scanner designed for home lab environments and educational purposes. Built with Python, Nmap, and Streamlit, this tool helps you quickly identify open ports, running services, and potential security misconfigurations on target machines, providing actionable recommendations.

## ✨ Features

* **Customizable Nmap Scans:** Choose from various Nmap options (Aggressive, All Ports, Vuln Scripts, Discovery, Safe Scripts) via an intuitive web interface.
* **Additional Nmap Arguments:** Advanced users can input custom Nmap flags and options for highly specific scans.
* **Detailed Scan Reports:** Generates human-readable Markdown reports with:
    * Scan Summary (Hosts Scanned, Online, Open Ports)
    * Host Details (IP, Hostname, Status, OS Guesses)
    * Open Ports & Services (Port ID, Protocol, State, Service, Product, Version, Extra Info)
    * Nmap Script Output
    * **AI-like Recommendations:** Provides actionable security recommendations based on common Nmap script findings (e.g., anonymous FTP, weak SSH config, exposed server banners).
* **Report Download:** Download the full report as a Markdown file.
* **Reset Scan:** Clear the interface and start a new scan with ease.
* **User-Friendly Interface:** Powered by Streamlit for a simple and interactive web experience.

## 🚀 Getting Started: How to Use the Solution

Follow these steps to download and run the VulnScan Reporter in your home lab environment.

### Prerequisites

* **Two Ubuntu Virtual Machines:**
    * `Ubuntu-Scanner`: This VM will host the `VulnScan Reporter` application.
    * `Ubuntu-Target`: This VM will be the target of your scans.
* **Network Connectivity:** Ensure both VMs are on the **same virtual network** (e.g., using a "NAT Network" or "Internal Network" setting in VirtualBox/VMware) and can communicate.
* **Target IP Address:** You will need the IP address of your `Ubuntu-Target` VM. You can find this by running `ip a` or `ifconfig` in its terminal.

### Installation and Setup on Your `Ubuntu-Scanner` VM

1.  **Update System Packages:**
    Open a terminal on your `Ubuntu-Scanner` VM and run:
    ```bash
    sudo apt update && sudo apt upgrade -y
    ```

2.  **Install Git and Python Virtual Environment Tools:**
    ```bash
    sudo apt install git python3-venv -y
    ```

3.  **Clone the Repository:**
    Navigate to your desired directory (e.g., your home directory) and clone the `VulnScan Reporter` repository from GitHub:
    ```bash
    cd ~
    git clone [https://github.com/phemtech-solutions/VulnScan-Reporter.git](https://github.com/phemtech-solutions/VulnScan-Reporter.git)
    cd VulnScan-Reporter
    ```
    *(Note: Replace `phemtech-solutions/VulnScan-Reporter.git` with the actual path to your GitHub repository if it's different.)*

4.  **Create a Python Virtual Environment:**
    ```bash
    python3 -m venv venv
    ```

5.  **Activate the Virtual Environment:**
    ```bash
    source venv/bin/activate
    ```
    (You'll see `(venv)` in your terminal prompt when active.)

6.  **Install Required Python Libraries:**
    The project includes a `requirements.txt` file that lists all necessary Python libraries. Install them using pip:
    ```bash
    pip install -r requirements.txt
    ```

7.  **Configure `app.py` (One-Time Adjustment):**
    The `app.py` file has a default target IP. You might want to adjust this to match your `Ubuntu-Target` VM's IP address.
    * Open `app.py` for editing:
        ```bash
        nano app.py
        ```
    * Locate the line setting the default IP address (e.g., `st.session_state.target_input_value = "192.168.10.8"`) and update it to your `Ubuntu-Target` VM's actual IP.
    * Optionally, you can also update the LinkedIn profile URL in the sidebar of the `app.py` file.
    * Save and exit (`Ctrl+X`, then `Y`, then `Enter`).

### Running the Application

1.  **Ensure VMs are Running:** Both your `Ubuntu-Scanner` and `Ubuntu-Target` VMs should be powered on and connected to the same virtual network.
2.  **Activate Virtual Environment:** If you closed your terminal or opened a new one, navigate to the `VulnScan-Reporter` directory and activate the virtual environment:
    ```bash
    cd ~/VulnScan-Reporter # Or wherever you cloned the repo
    source venv/bin/activate
    ```
3.  **Start the Streamlit App:**
    ```bash
    streamlit run app.py
    ```
4.  **Access the Web UI:** Streamlit will start a local web server and display URLs in your terminal. Look for the "Network URL" (e.g., `http://192.168.X.X:8501`). Open this URL in a web browser on your host machine (e.g., your Mac).
5.  **Perform a Scan:**
    * In the web interface, the target IP address field will be pre-filled (e.g., `192.168.10.8`). You can change this to any other IP address or range on your network.
    * Select your desired Nmap scan options using the checkboxes (e.g., "Aggressive Scan", "Scan All Ports").
    * Optionally, add custom Nmap arguments in the "Additional Nmap Arguments" text box (e.g., `-F` for a fast scan, `--script=ftp-anon` for specific script checks).
    * Click the "Start Scan" button.
    * The scan results and recommendations will appear on the page. You can click "Download Full Report" to save the report as a Markdown file.
    * Click "Reset Scan" to clear the interface and start a new scan.

## 📄 Report Explanation

The generated report provides a clear overview of the scanned host(s):

* **Scan Summary:** Quick statistics about the scan.
* **Host Details:** Information about each discovered host, including its IP, hostname, and operating system guesses.
* **Open Ports & Services:** Lists all detected open ports, their protocols (TCP/UDP), current state, and identified services (e.g., HTTP, SSH, FTP) along with their product and version.
* **Nmap Script Output:** Displays detailed results from Nmap Scripting Engine (NSE) scripts that run during the scan. These scripts help identify specific vulnerabilities or gather more information about services.
* **AI-like Recommendations:** Based on the script output, the tool provides practical security recommendations to help you address potential issues (e.g., "Disable Anonymous FTP Access", "Ensure SSH keys are properly managed").

## 🌐 Global Accessibility (Optional)

If this application is deployed to a public platform (like Streamlit Community Cloud), it can be accessed from anywhere in the world via a web browser.

**Important Note for Cloud Deployment:** When hosted in the cloud, the application runs on remote servers and **will NOT have direct access to your private home lab VMs** (e.g., 192.168.10.8). You would only be able to scan publicly accessible IP addresses or domains from a cloud-deployed version.

## 🤝 Contribution & License

This project is open-source. For information on contributing to its development or licensing details, please refer to the project's GitHub repository.
