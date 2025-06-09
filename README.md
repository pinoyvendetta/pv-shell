# PV Advanced Toolkit v1.0.0

A comprehensive, single-file, PHP-based web shell and server management interface. It's designed for server administrators and security professionals to facilitate system inspection, management, and basic network operations through a user-friendly, retro-themed web interface.

![image](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExNjZwdGpicmw2bmZwcHpmcDg1ZGZuZ2t5cWh1cGI0Y2lzdDB6aGh0ZCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9cw/xxlo1yG0pvhJqNhhtj/giphy.gif)

## Features

### Security
* **Secure Authentication:** Password-protected login to prevent unauthorized access. The default password is `myp@ssw0rd`.
* **IP & User-Agent Whitelisting:** Optional security layers to restrict access based on IP address or the browser/tool user-agent string.

### Core Modules
* **Interactive Terminal Emulator:**
    * Execute shell commands directly on the server.
    * Command history navigation using Up/Down arrow keys.
    * Maintains the current working directory throughout the session.
    * Renders HTML from server errors (e.g., HTTP 500) directly within the terminal for easier debugging.

* **Advanced File Manager:**
    * Browse server directories and view detailed file/folder information (name, type, human-readable size, owner/group, octal permissions, last modified date).
    * Remembers the last visited directory across page refreshes.
    * **File Operations:**
        * View/Edit text-based files in a modal editor.
        * Download any file directly to your local machine.
        * Rename files and folders.
        * Change file/folder permissions (chmod).
        * Update file timestamps (touch).
        * Delete files and folders (with recursive deletion for non-empty folders).
    * **Creation Tools:** Create new empty files and folders.
    * **File Uploads:** Upload single or multiple files to the current directory via a simple interface.
    * **Easy Navigation:** Navigate using an address bar, a "Go" button, and a "Home" button to return to the script's directory.
    * **Visual Icons:** Unique icons for dozens of file types for quick identification.

* **Server Information Panel:**
    * Displays a comprehensive overview of the server environment.
    * Includes details on server software, PHP version, OS, CPU info, user info, and critical PHP configurations (`safe_mode`, `disable_functions`, `memory_limit`, etc.).
    * Shows enabled extensions (cURL, mailer, databases), disk space usage, network details, and more.

* **Network Tools:**
    * **PHP Foreground Port Bind Shell:** Listens on a specified port for incoming connections, providing an interactive shell upon successful password authentication.
    * **PHP Foreground Back Connect Shell:** Connects back to a specified IP and port to provide an interactive shell.
    * **Ping Utility:** Sends ICMP echo requests to a specified host.
    * **DNS Lookup Utility:** Retrieves DNS records for a specified host.
    * *(Note: Foreground shells will cause the web page to hang while the connection is active.)*

* **PHP Info Display:**
    * Shows the full output of `phpinfo()` in an isolated iframe for detailed PHP environment inspection without cluttering the main interface.

## Usage

1.  **Deployment:**
    * Upload the single `pv-shell.php` file to your target web server.
    * Access the file through your web browser.

2.  **Configuration (Optional):**
    * Edit the PHP file to set your own security parameters.
    * **Password:** Change the default password by modifying the `$default_password_hash`.
        ```php
        // Default password hash using MD5 for 'myp@ssw0rd'
        $default_password_hash = '2ebba5cd75576c408240e57110e7b4ff';
        ```
    * **IP Whitelisting:** To restrict access to specific IP addresses, populate the `$WHITELISTED_IPS` array.
        ```php
        $WHITELISTED_IPS = ['192.168.1.10', '127.0.0.1'];
        ```
    * **User-Agent Whitelisting:** To restrict access to specific browsers or tools, populate the `$WHITELISTED_USER_AGENTS` array.
        ```php
        $WHITELISTED_USER_AGENTS = ['MyCustomBrowser', 'SpecialToolAgent'];
        ```

3.  **Login:**
    * Navigate to the URL of the script.
    * Enter the configured password to authenticate and access the toolkit.

## Disclaimer

**FOR ETHICAL USE ONLY.**

This tool is provided for educational and legitimate system administration purposes only. The user is solely responsible for any actions performed using this tool. The author is not responsible or liable for any damage, misuse, or illegal activity caused by this tool. Use at your own risk and ensure you have proper authorization before using it on any system.

