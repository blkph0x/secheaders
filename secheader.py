import requests
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Define OWASP-recommended security headers and their descriptions
RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS and protects against SSL stripping attacks.",
        "required": True,
        "validate": lambda value: "max-age" in value and "includeSubDomains" in value,
        "failure": "Ensure 'max-age' and 'includeSubDomains' are set."
    },
    "Content-Security-Policy": {
        "description": "Defines approved sources of content to prevent XSS and injection attacks.",
        "required": True,
        "validate": lambda value: "default-src" in value and "'unsafe-inline'" not in value and "*'" not in value,
        "failure": "Avoid 'unsafe-inline', wildcards (*), and ensure 'default-src' is defined."
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME sniffing.",
        "required": True,
        "validate": lambda value: value.lower() == "nosniff",
        "failure": "Set the value to 'nosniff'."
    },
    "X-Frame-Options": {
        "description": "Controls whether the browser should allow framing to prevent clickjacking.",
        "required": True,
        "validate": lambda value: value.lower() in ["deny", "sameorigin"],
        "failure": "Use 'DENY' or 'SAMEORIGIN'."
    },
    "Referrer-Policy": {
        "description": "Regulates the amount of referrer information sent with requests.",
        "required": True,
        "validate": lambda value: value.lower() in ["no-referrer", "strict-origin", "strict-origin-when-cross-origin"],
        "failure": "Use 'no-referrer', 'strict-origin', or 'strict-origin-when-cross-origin'."
    },
    "Permissions-Policy": {
        "description": "Manages access to browser features like geolocation and camera.",
        "required": True,
        "validate": lambda value: len(value.strip()) > 0,
        "failure": "Define policies to restrict access to browser features."
    },
}

# Define deprecated headers
DEPRECATED_HEADERS = {
    "X-XSS-Protection": "Deprecated. Set to '0' or remove entirely."
}

def format_section_title(title):
    line = "-" * len(title)
    return f"{Style.BRIGHT}{line}\n{title}\n{line}\n"

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        print(f"\n{format_section_title(f'Checking Security Headers for: {url}')}")
        
        # Check recommended headers
        print(format_section_title("Recommended Headers"))
        for header, config in RECOMMENDED_HEADERS.items():
            if header in headers:
                value = headers[header]
                if config["validate"](value):
                    print(f"{Fore.GREEN}[+] {header:<25} Present and Valid")
                    print(f"    {Style.DIM}Value: {value}")
                else:
                    print(f"{Fore.RED}[-] {header:<25} Present but Misconfigured")
                    print(f"    {Style.DIM}Value: {value}")
                    print(f"    {Style.DIM}Recommendation: {config['failure']}")
            else:
                print(f"{Fore.RED}[-] {header:<25} Missing")
                print(f"    {Style.DIM}{config['description']}")

        # Check deprecated headers
        print(format_section_title("Deprecated Headers"))
        for header, recommendation in DEPRECATED_HEADERS.items():
            if header in headers:
                value = headers[header]
                print(f"{Fore.RED}[-] {header:<25} Present")
                print(f"    {Style.DIM}Value: {value}")
                print(f"    {Style.DIM}Recommendation: {recommendation}")
            else:
                print(f"{Fore.GREEN}[+] {header:<25} Not Present (Good)")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error: Unable to fetch the URL. Details: {e}")

def main():
    print("Choose input method:")
    print("1. Enter a list of URLs separated by commas.")
    print("2. Provide a file containing a list of hosts (one per line).")
    
    choice = input("Enter your choice (1/2): ").strip()

    urls = []
    if choice == "1":
        input_urls = input("Enter URLs separated by commas (e.g., https://example.com,https://test.com): ")
        urls = [url.strip() for url in input_urls.split(",") if url.strip()]
    elif choice == "2":
        file_path = input("Enter the file path containing the list of hosts: ").strip()
        try:
            with open(file_path, "r") as file:
                urls = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File not found at {file_path}.")
            return
    else:
        print(f"{Fore.RED}Invalid choice. Please enter 1 or 2.")
        return

    # Check headers for each URL
    for url in urls:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url  # Default to HTTPS if no scheme is provided
        check_security_headers(url)

if __name__ == "__main__":
    main()
