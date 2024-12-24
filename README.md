# NETSHIELD IDS

**NETSHIELD IDS** is a robust Python-based Intrusion Detection System designed to monitor network traffic and detect potential security threats in real time. This tool identifies various attacks such as DoS, SQL injections, malware, and unauthorized access attempts. With customizable detection rules, secure login features, and comprehensive logging, NETSHIELD IDS ensures your network remains protected from evolving cyber threats while providing insightful security analytics.

---
## Overview

**NETSHIELD IDS** is a comprehensive intrusion detection system (IDS) designed to monitor network traffic for various types of attacks. It provides real-time network traffic analysis, detects suspicious activities, and allows users to secure their systems by identifying vulnerabilities such as DoS attacks, SQL injections, XSS, and more.

This tool is highly customizable, with adjustable detection rules and thresholds, ensuring that it adapts to new and emerging threats.

---

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation Instructions](#installation-instructions)
4. [Usage Examples](#usage-examples)
5. [Security Considerations](#security-considerations)
6. [Troubleshooting](#troubleshooting)
7. [Contributing](#contributing)
8. [Legal Disclaimer](#legal-disclaimer)
9. [License](#license)
10. [Acknowledgements](#acknowledgements)
11. [Conclusion](#conclusion)
12. [Contact](#contact)

---

## Features

- **Real-Time Network Monitoring**: Monitors network traffic to detect malicious activities.
- **Comprehensive Attack Detection**: Detects a variety of attacks such as:
    DoS (Denial of Service)
    SQL Injection
    XSS (Cross-Site Scripting)
    Port Scanning
    Unauthorized Access Attempts
- **Customizable Detection Rules**: Users can edit detection patterns and thresholds in the configuration file.
- **Logging**: System events and attack detection logs are saved separately for easy monitoring.
- **Secure Authentication**: Users can set and authenticate passwords for secure access.


---

## Requirements

- **Python 3**: Ensure you have Python 3 or later installed.
- **Scapy Library**: This tool requires Scapy for network packet crafting.


---

## Installation Instructions

1. **Clone the Repository**:  
   ```bash
   git clone https://github.com/Pawar-Tushar/NetShield-IDS.git

2. **Navigate to the project directory:**
    ```bash
    cd NetShield-IDS
    ```

3. **Install the required dependencies using pip**:
    ```bash
    pip install -r requirements.txt
    ```
3. **Run the Application**:
    ```bash
    python Main.py  
    ```
---

## Usage Examples

1. **Run the application:**
   ```bash
   python main.py
   
- **Set a password**: If it's your first time, you'll be prompted to set a new password.
- **Login**: Enter the password to access the system.
- **Start monitoring**: The application will start sniffing network traffic to detect any potential attacks.
---

## Security Considerations

- Ensure the `password_hash.txt` file is properly secured to prevent unauthorized access.
- Regularly update the attack detection patterns and thresholds in the `signature_rules.json` file to address new types of threats.
- Avoid running the system with elevated privileges unless absolutely necessary.
---

## Troubleshooting

- **If the application fails to start:** Verify that all dependencies are installed correctly. Use `pip list` to check the installed packages.
- **If the network interface is not recognized:** Ensure your network interface is active and properly configured for sniffing.
- **Incorrect password issues:** If you forget the password, delete the `password_hash.txt` file and reconfigure it by setting a new password.

---

## Contributing

We welcome contributions to enhance NETSHIELD IDS. If you'd like to contribute, please follow these steps:

- Fork the repository.
- Create a new branch for your feature or bug fix.
- Submit a pull request for review.

Please ensure your code adheres to the project’s style and passes all tests before submitting.

---

## Legal Disclaimer

NETSHIELD IDS is designed for educational and ethical purposes only. The developers are not responsible for any misuse or illegal activities conducted using this software. Ensure you have appropriate authorization before using this tool on any network.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgements

- **Scapy**: For providing powerful functionality for packet crafting and sending.
- **Python 3.x**: For the simplicity and flexibility it offers for network programming.

---

## Conclusion

NETSHIELD IDS provides an essential tool for monitoring and protecting networks from a wide range of attacks. Its real-time detection capabilities, customizable rules, and logging features make it a valuable tool for security professionals and network administrators.

---

## Contact

For any queries or issues, feel free to reach out via GitHub Issues or email me at [tusharpawar@749963.com].
