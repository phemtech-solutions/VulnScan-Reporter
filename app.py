# app.py
# Streamlit web application for VulnScan Reporter
# This file imports core logic from vuln_scan_core.py

import streamlit as st
import nmap
import sys
import datetime # Added for datetime.datetime.now()
from vuln_scan_core import run_nmap_scan, analyze_scan_results, generate_report

# --- Streamlit UI ---
st.set_page_config(layout="centered", page_title="VulnScan Reporter", initial_sidebar_state="expanded")

st.title("🛡️ VulnScan Reporter")
st.markdown("A lightweight automated vulnerability scanner for your home lab environment.")
st.markdown("---")

# Initialize session state for managing report visibility and input resets
if 'show_report' not in st.session_state:
    st.session_state.show_report = False
if 'target_input_value' not in st.session_state:
    st.session_state.target_input_value = "INPUT THE TARGET IP i.e. 192.168.10.8" # Default IP as requested

# Input for target IP or range
target_input = st.text_input(
    "Enter Target IP Address(es) or Range (e.g., 192.168.100.11, 192.168.100.0/24)", 
    value=st.session_state.target_input_value, # Use session state for value
    key="target_ip_input" # Unique key for this widget
)

st.subheader("Scan Options")
col1, col2, col3 = st.columns(3)

with col1:
    aggressive_scan = st.checkbox("Aggressive Scan (-A)", value=False, key="chk_aggressive", help="Enables OS detection, version detection, script scanning, and traceroute. Can be noisy.")
with col2:
    all_ports_scan = st.checkbox("Scan All Ports (-p-)", value=False, key="chk_all_ports", help="Scans all 65535 TCP ports. WARNING: This will significantly increase scan time!")
with col3:
    vuln_scripts_scan = st.checkbox("Run Vuln Scripts (--script=vuln)", value=False, key="chk_vuln_scripts", help="Runs all Nmap vulnerability detection scripts. WARNING: This can be very slow, noisy, and may trigger alarms!")

col4, col5 = st.columns(2)
with col4:
    discovery_scripts = st.checkbox("Run Discovery Scripts (--script=discovery)", value=False, key="chk_discovery", help="Runs scripts for service discovery and information gathering.")
with col5:
    safe_scripts = st.checkbox("Run Safe Scripts (--script=safe)", value=False, key="chk_safe", help="Runs scripts that are considered safe and non-intrusive.")

# New: Additional Nmap Arguments text input
additional_nmap_args = st.text_input(
    "Additional Nmap Arguments (e.g., -Pn -F --exclude 192.168.1.1)",
    value="", # Default empty
    key="additional_args_input",
    help="Enter any other Nmap arguments you wish to include. These will be appended to the selected options above."
)

# Store scan options in a dictionary
scan_options = {
    'aggressive': aggressive_scan,
    'all_ports': all_ports_scan,
    'vuln_scripts': vuln_scripts_scan,
    'discovery_scripts': discovery_scripts,
    'safe_scripts': safe_scripts,
    'additional_args': additional_nmap_args # Include additional args
}

# --- Action Buttons ---
col_buttons = st.columns(2)

with col_buttons[0]:
    if st.button("Start Scan", key="start_scan_button"):
        st.session_state.show_report = True # Set flag to show report area
        if not target_input:
            st.warning("Please enter a target IP or range to scan.")
            st.session_state.show_report = False # Don't show report if no target
        # Check if any scan option is selected or additional args are provided
        elif not any(scan_options[k] for k in ['aggressive', 'all_ports', 'vuln_scripts', 'discovery_scripts', 'safe_scripts']) and not additional_nmap_args.strip():
            st.warning("Please select at least one scan option or provide additional Nmap arguments before starting the scan.")
            st.session_state.show_report = False # Don't show report if no options
        else:
            # Initialize PortScanner for this session
            nm = nmap.PortScanner() 
            
            # Use a placeholder for the report content initially
            st.session_state.report_content = "" 
            st.session_state.scanned_hosts_status = [] # To store status of scanned hosts

            with st.spinner("Initiating Nmap scan... This may take a while depending on options selected."):
                try:
                    # Call the core scanning function, passing scan_options
                    scanned_hosts = run_nmap_scan(target_input, nm, scan_options) 
                    st.session_state.scanned_hosts_status = scanned_hosts # Store for later check
                    
                    if scanned_hosts:
                        # Update spinner for analysis phase
                        st.text("Scan completed. Analyzing results and generating report...")
                        findings = analyze_scan_results(scanned_hosts, nm)
                        report_content = generate_report(findings, nm) 
                        st.session_state.report_content = report_content
                    else:
                        st.error("Nmap scan returned no active hosts or encountered an error. "
                                 "Please check the target IP, network connectivity, and ensure the target VM is running.")
                        st.session_state.show_report = False # Hide report if scan failed
                except nmap.PortScannerError as e:
                    st.error(f"Nmap Scan Error: {e}. Please ensure Nmap is correctly installed and permissions are set.")
                    st.session_state.show_report = False
                except Exception as e:
                    st.error(f"An unexpected error occurred during the scan: {e}")
                    st.session_state.show_report = False

with col_buttons[1]:
    # Reset button logic
    if st.button("Reset Scan", key="reset_scan_button"):
        st.session_state.show_report = False
        st.session_state.target_input_value = "INPUT THE TARGET IP i.e. 192.168.10.8" # Reset to default IP
        # To reset checkboxes and text inputs, we need to rerun the app
        # This is a common Streamlit pattern to force widget reset
        st.rerun()


# --- Display Report (Conditional) ---
if st.session_state.show_report:
    if st.session_state.report_content:
        st.subheader("Scan Report")
        
        # Display report content with expanders for each host
        report_sections = st.session_state.report_content.split('### Host:')
        
        # Display the summary section first
        st.markdown(report_sections[0]) 

        # Display each host in an expander
        for i, section in enumerate(report_sections[1:]):
            host_line = section.split('\n')[0].strip() 
            with st.expander(f"Host: {host_line.replace('`', '')}", expanded=False): 
                st.markdown("### Host:" + section) 

        # Add a download button for the report
        st.download_button(
            label="Download Full Report",
            data=st.session_state.report_content.encode('utf-8'),
            file_name=f"vuln_scan_report_{st.session_state.target_input_value.replace('.', '_').replace('/', '-')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown"
        )
    # If show_report is true but report_content is empty, it means an error occurred and was displayed above
    # No need for an else here, as the error message is already handled in the scan logic.


st.markdown("---")
st.sidebar.header("About This Tool")
st.sidebar.info(
    "**VulnScan Reporter** is designed for educational and home lab use. "
    "It leverages the powerful Nmap tool and Python to perform basic network "
    "scans and identify common service configurations and potential vulnerabilities. "
    "The goal is to provide clear, actionable insights from raw scan data, "
    "acting as an 'AI-like' explanation engine for security findings."
)
st.sidebar.markdown("---")
st.sidebar.markdown("Developed by: Ajijola Oluwafemi Blessing")
st.sidebar.markdown("[LinkedIn Profile](https://www.linkedin.com/in/your-linkedin-profile/)") # Replace with your actual LinkedIn URL
