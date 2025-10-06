import breach_checker, pw_analyzer, nw_monitor, phishing_analyzer, readchar

def boxed(text):
    """
    Prints the given text inside a box made of ASCII characters.
    
    Args:
        text (str): The text to be boxed.
    """
    width = len(text) + 4  # 2 spaces + 2 borders
    print("\n\n+" + "-" * (width - 2) + "+")
    print(f"| {text} |")
    print("+" + "-" * (width - 2) + "+")

def display_menu():
    """
    Displays the main menu and handles user input."""
    try:
        boxed("Main Menu")
        print("\nSelect an option (1-5):\n\n1. Email Breach Check\n2. Password Monitor\n3. Network Monitor\n4. Phishing Analyzer\n5. Quit")
        key = readchar.readkey()
        print("")
        # email breach check
        if key == '1':
            boxed("Email Breach Check")
            raise NotImplementedError("\nEmail breach check is currently under development.\n")
            breach_checker()
        # password analyzer
        elif key == '2':
            boxed("Password Analyzer")
            pw_analyzer.pw_analyzer()
        # network monitor
        elif key == '3':
            boxed("Network Monitor")
            nw_monitor.nw_monitor()
        # phishing analyzer
        elif key == '4':
            boxed("Phishing Analyzer")
            raise NotImplementedError("\nPhishing analyzer is currently under development.\n")
            phishing_analyzer()
        # exit
        elif key == '5':
            print("Exiting application...\n\nStay safe!")
            exit()
        else:
            raise ValueError("\nInvalid choice. Please select a valid option.")
    except NotImplementedError as e:
        print(e)
    except ValueError as e:
        print(e)
    
def menu():
    """
    Main function to run the menu loop."""
    boxed("Welcome to CyberSentinel!")
    
    while True:
        display_menu()
        
if __name__ == '__main__':
    menu()