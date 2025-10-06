import hashlib, main, readchar, zxcvbn, re, requests

def sha1_hash(password):
    """
    Takes a password and returns its SHA-1 hash in uppercase hexadecimal format.
    
    Args:
        password (str): The password to hash.
        
    Returns:
        str: The SHA-1 hash of the password.
    """
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

def strength_analyzer(password):
    """
    Analyzes the strength of a given password using the zxcvbn library and prints a detailed report.
    
    Args:
        password (str): The password to analyze.
    """
    SCORE_LABELS = ["VERY WEAK", "WEAK", "FAIR", "STRONG", "VERY STRONG"]
    result = zxcvbn.zxcvbn(password) # analyze password
    
    score = result['score']
    warning = result['feedback']['warning']
    suggestions = result['feedback']['suggestions']
    pw = result['password']
    guesses = result['guesses']
    sequence = result['sequence']
    calc_time = result['calc_time']
    crack_times_online_throttling = result['crack_times_display']['online_throttling_100_per_hour']
    crack_times_online_no_throttling = result['crack_times_display']['online_no_throttling_10_per_second']
    crack_times_offline_slow_hashing_1e4_per_second = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    crack_times_offline_fast_hashing_1e10_per_second = result['crack_times_display']['offline_fast_hashing_1e10_per_second']
    
    # print report
    print("\nPASSWORD STRENGTH ANALYSIS REPORT\n")
    print("-" * 34)
    print(f"Password: {pw}")
    print(f"Password Strength: {SCORE_LABELS[score]} (Score: {score}/4)\n")
    print(f"~{guesses} guesses to crack")
    print(f"~{crack_times_online_throttling} to crack using online throttling (100/hour)")
    print(f"~{crack_times_online_no_throttling} to crack using online no throttling (10/second)")
    print(f"~{crack_times_offline_slow_hashing_1e4_per_second} to crack using offline slow throttling (10k/second)")
    print(f"~{crack_times_offline_fast_hashing_1e10_per_second} to crack using offline fast throttling (10B/second)\n")
    
    if warning:
        print(f"Warning: {warning}\n")
    else:
        print("No warnings.")
        
    if suggestions:
        print("Suggestions:")
        for suggestion in suggestions:
            print(f" - {suggestion}")
    else:
        print("No suggestions.")

def validate_pw(password):
    """
    Validates the given password against specific criteria.
    
    Args:
        password (str): The password to validate.
    
    Returns:
        bool: True if the password is valid.
    
    Raises:
        ValueError: If an invalid password is entered.
    """
    pw = re.sub(r'[\t\n\r\f\v]+', '', password) # remove whitespace characters but not spaces
    
    # empty check
    if pw == "":
        raise ValueError("\n\nPASSWORD ENTRY FAILED\n\nPassword cannot be empty.")
    # length check
    if len(pw) < 6:
        raise ValueError("\n\nPASSWORD ENTRY FAILED\n\nPassword must be at least 6 characters long.")
    # space check
    if " " in pw:
        raise ValueError("\n\nPASSWORD ENTRY FAILED\n\nPassword cannot contain spaces.")
    
    # upper = any(char.isupper() for char in pw)
    # lower = any(char.islower() for char in pw)
    # num = any(char.isdigit() for char in pw)
    # special = any(char in "!@#$%^&*()-_=+[]}{;:,./?" for char in pw)
    
    # if not (upper and lower and num and special):
    #     raise ValueError("\n\nPASSWORD ENTRY FAILED\n\nPassword must contain one uppercase, one lowercase letter, one number, and one special character.")
    else:
        return True

def pw_menu(password):
    """
    Displays password analysis options for a validated password.
    
    Args:
        password (str): The validated password to analyze.
    
    Raises:
        ValueError: If an invalid choice is chosen.
    """
    while True:
        try:
            print("\nSelect an option (1-3):\n\n1. Strength Analyzer\n2. Breach Checker\n3. Quit")
            key = readchar.readkey()
            print("")
            if key == '1':
                main.boxed("Strength Analyzer")
                strength_analyzer(password)
            elif key == '2':
                main.boxed("Breach Checker")
                breach_check(password)
            elif key == '3':
                print("Exiting to main menu...\n")
                return
            else:
                raise ValueError("\nInvalid choice. Please select a valid option.")
        except ValueError as e:
            print(e)
    
def check_pwned(password):
    """
    Checks whether a given password has appeared in known data breaches using the Have I Been Pwned (HIBP) Pwned Passwords API with k-anonymity.
    
    Args:
        password (str): The password to check.
    
    Returns:
        int: The number of times the password was found in data breaches. Returns 0 if the password has not been seen in any known breaches.

    Raises:
        RuntimeError: If the API request fails or returns a non-200 status code.
    """
    
    # SHA-1 hash password and seperate prefix
    hash = sha1_hash(password)
    prefix, suffix = hash[:5], hash[5:]
    
    # Send only the first 5 chars of the hash to the HIBP API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError("Error fetching from HIBP API")
    
    # Compare each returned suffix with ours
    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
        
    # Return 0 if no match was found
    return 0

def breach_check(password):
    """
    Checks if the password has been found in known data breaches and prints the result.
    
    Args:
        password (str): The validated password to analyze.
        
    Raises:
        RuntimeError: If the API request fails or returns a non-200 status code.
    """
    try:
        count = check_pwned(password)
        if count:
            print(f"\nWARNING: This password has appeared in {count} known data breaches. It is NOT safe to use.\n")
        else:
            print("\nGood news! This password was NOT found in any known data breaches.\n")
    except RuntimeError as e:
        print(f"\nError checking password breach status: {e}\n")

def pw_analyzer():
    """
    Main function to run the password monitor.
    """
    pw = input("\nEnter the password to analyze: \n")

    try:
        validate_pw(pw)
    except ValueError as e:
        print(f"\n\nPASSWORD ENTRY FAILED\n\n{e}\n")
        return

    pw_menu(pw)