import netifaces, ipaddress, nmap, time, pymysql, subprocess, datetime, tzlocal, dotenv, pymysql, os

def get_previous_os(mac):
    """
    Fetches the previously guessed OS for a device with the given MAC address from the database.
    
    Args:
        mac (str): The MAC address of the device.
        
    Returns:
        os_guess (str): The previously guessed OS or 'Unknown' if not found.
    """
    connection = connect_db()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT os_guess FROM devices WHERE mac=%s ORDER BY scan_id DESC LIMIT 1", (mac,))
        row = cursor.fetchone()
        if row:
            return row['os_guess'] or 'Unknown'
        else:
            return 'Unknown'
    finally:
        connection.close()

def get_known_macs():
    """
    Fetches all known MAC addresses from the database.
    Returns:
        macs (set): A set of known MAC addresses.
    """
    connection = connect_db()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT DISTINCT mac FROM devices WHERE mac IS NOT NULL")
        rows = cursor.fetchall()
        macs = set(row['mac'] for row in rows if row['mac'])
        return macs
    finally:
        connection.close()

def sudo_cached():
    """Return True if sudo password is cached."""
    
    result = subprocess.run(
        ["sudo", "-n", "true"],  # -n = non-interactive
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0

def save_scan(devices):
    """
    Saves the scan results to a MySQL database.
    
    Args:
        devices (list): A list of devices found on the network. Each device is
                        represented as a dictionary with the following keys:
                        - 'ip': str, the IPv4 address of the device
                        - 'mac': str, the MAC address of the device or 'Unknown'
                        - 'vendor': str, the manufacturer/vendor or 'Unknown'
                        - 'OS': str, the guessed operating system or 'Unknown'
                        
    Returns:
        scan_id (int): The scan ID of the newly inserted scan record.
    """
    
    # get current local time with timezone
    local_tz = tzlocal.get_localzone()
    local_time = datetime.datetime.now(local_tz)
    
    # connect to database
    connection = connect_db()
    
    # insert scan and device data
    try:
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO scans (scan_time) VALUES (%s)",
            (local_time.strftime('%Y-%m-%d %H:%M:%S'),)
        )
        scan_id = cursor.lastrowid
        
        for device in devices:
            cursor.execute("""
                INSERT INTO devices (scan_id, ip, mac, vendor, os_guess)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE ip=%s, os_guess=%s
            """, (scan_id, device['ip'], device['mac'], device['vendor'], device['OS'], device['ip'], device['OS']))
            
        connection.commit()
        
    finally:
        connection.close()
        return scan_id

def read_scan():
    """
    Fetches the most recent network scan entry and retrieves all associated device records from the database.

    Returns:
        devices (list): A list of devices from the latest scan. Each device is
                        represented as a dictionary with keys corresponding to
                        the database columns (e.g., 'ip', 'mac', 'vendor', 'os_guess').
                        Returns an empty list if no scans are found.
    """
    
    # connect to database
    connection = connect_db()

    # fetch latest scan and associated devices
    try:
        devices = []
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM scans ORDER BY scan_id DESC LIMIT 1")
        latest_scan = cursor.fetchone()
        if not latest_scan:
            return devices
        
        scan_id = latest_scan['scan_id']
        cursor.execute("SELECT * FROM devices WHERE scan_id=%s", (scan_id,))
        devices = cursor.fetchall()
        return devices
        
    finally:
        connection.close()

def connect_db():
    """
    Establishes a connection to the MySQL database using credentials from the .env file.
    
    Returns:
        connection (Connection): A connection object to the MySQL database.
    """
    dotenv.load_dotenv()
    timeout = 10
    try:
        connection = pymysql.connect(
            charset='utf8mb4',
            connect_timeout=timeout,
            cursorclass=pymysql.cursors.DictCursor,
            read_timeout=timeout,
            write_timeout=timeout,
            database='defaultdb',
            host='mysql-cybersentinel-cybersentinel.g.aivencloud.com',
            user='avnadmin',
            password=os.getenv("AIVEN_DB_PASSWORD"),
            port=13067,
            ssl_ca='certificates/ca.pem',
        )
        return connection
    except pymysql.MySQLError as e:
        print(f"Error connecting to database: {e}")
        return None

def get_nw_cidr():
    """
    Detects and calculates the local network range (subnet) of the default network interface in CIDR notation.

    Returns:
        str: The network range in CIDR notation for the default interface.
             Example: '192.168.1.0/24'
    """
        
    # get default gateway interface
    gws = netifaces.gateways()
    default_iface = gws['default'][netifaces.AF_INET][1]
    
    # get first ipv4 address of default interface
    address = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
    
    # calculate network CIDR
    ip = address['addr']
    netmask = address['netmask']
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    
    return str(network)

def scan_nw(network="192.168.1.0/24", known_macs=None):
    """
    Scans the specified network for live devices and gathers basic information.

    Args:
        network (str): The subnet to scan in CIDR notation.
                        Defaults to "192.168.1.0/24".
        known_macs (set): A set of known MAC addresses within the network.
                        Defaults to None.

    Returns:
        devices (list): A list of devices found on the network. Each device is
                        represented as a dictionary with the following keys:
                        - 'ip': str, the IPv4 address of the device
                        - 'mac': str, the MAC address of the device or 'Unknown'
                        - 'vendor': str, the manufacturer/vendor or 'Unknown'
                        - 'OS': str, the guessed operating system or 'Unknown'
    """
    if known_macs is None:
        known_macs = set()
    
    # ask for sudo password upfront
    if not sudo_cached():
        print("\nPlease enter your sudo password below.\n")
        try:
            subprocess.run(['sudo', '-v'], check=True)
        except subprocess.CalledProcessError:
            print("\nSUDO AUTHENTICATION FAILED. Exiting to main menu...\n")
            return []
    
    print(f"\nScanning network ({network}) for devices...\n")
    start = time.time() #start scan timer

    # nmap scan network for live hosts
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn -T4', sudo=True)
    
    devices = []
    
    # gather device info for each host
    for host in nm.all_hosts():
        addresses = nm[host].get('addresses', {})
        ip = addresses.get('ipv4') or host
        mac = addresses.get('mac')
        vendor = nm[host]['vendor'].get(mac, 'Unknown') if mac else 'Unknown'
        
        # only run OS detection if this is a new device
        if mac and mac not in known_macs:
            # print(f"Running OS detection on {ip} (MAC: {mac})...")
            os_scanner = nmap.PortScanner()
            try:
                os_scanner.scan(hosts=ip, arguments='-O', sudo=True)
            except nmap.PortScannerError as e:
                print(f"Error during OS detection on {ip}: {e}")
                os_guess = 'Unknown'
            if ip in os_scanner.all_hosts() and os_scanner[ip].get('osmatch'):
                os_guess = os_scanner[ip]['osmatch'][0]['name']
            else:
                os_guess = 'Unknown'
            known_macs.add(mac)
        # known device
        elif mac:
            previous_os = get_previous_os(mac)
            
            # only run OS detection if OS is 'Unknown' or None
            if previous_os == 'Unknown' or previous_os is None:
                # run OS detection for this known device
                # print(f"Running OS detection on {ip} (MAC: {mac})...")
                os_scanner = nmap.PortScanner()
                try:
                    os_scanner.scan(hosts=ip, arguments='-O', sudo=True)
                    if ip in os_scanner.all_hosts() and os_scanner[ip].get('osmatch'):
                        os_guess = os_scanner[ip]['osmatch'][0]['name']
                    # scan failed or no OS match found
                    else:
                        os_guess = 'Unknown'
                except nmap.PortScannerError as e:
                    print(f"Error during OS detection on {ip}: {e}")
                    os_guess = 'Unknown'
            # OS is known
            else:
                os_guess = previous_os
        # no MAC address found
        else:
            # print(f"Skipping OS detection on {ip} (no MAC address found)...")
            os_guess = 'Unknown'
        
        devices.append({
            'ip': ip,
            'mac': mac or 'Unknown',
            'vendor': vendor or 'Unknown',
            'OS': os_guess
        })

    print(f"\n\nDevices found on network {network}:\n")
    for i, device in enumerate(devices, 1):
        print(f"{i}. IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}, OS: {device['OS']}")
    end = time.time()
    print(f"\nScan completed in {end - start:.1f} seconds.\n")
    save_scan(devices)
    
    return devices

def nw_monitor():
    """
    Main function to run the network monitor.
    """
    network = get_nw_cidr()
    known_macs = get_known_macs()
    scan_nw(network, known_macs)
    return