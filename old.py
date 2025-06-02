#!/usr/bin/env python3
import subprocess
import sys
import os
import re

def clean_curl_command(curl_command):
    """
    Clean curl command by removing line breaks and fixing shell syntax
    """
    # Remove line breaks and backslashes used for line continuation
    cleaned = curl_command.replace('\\\n', ' ').replace('\n', ' ')
    
    # Remove extra spaces
    cleaned = ' '.join(cleaned.split())
    
    # Replace $'...' syntax with regular quotes for Windows compatibility
    cleaned = re.sub(r"\$'([^']*)'", r'"\1"', cleaned)
    
    return cleaned

def read_curl_from_file(filename):
    """
    Read curl command from a text file and clean it
    """
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            curl_command = file.read().strip()
            # Clean the command to handle line breaks and shell syntax
            cleaned_command = clean_curl_command(curl_command)
            return cleaned_command
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        return None

def execute_curl(curl_command):
    """
    Execute a curl command and return the response
    """
    try:
        # Clean the command in case it has line breaks or shell syntax
        cleaned_command = clean_curl_command(curl_command)
        
        # Execute the curl command
        result = subprocess.run(cleaned_command, shell=True, capture_output=True, text=True)
        
        # Print the response
        print("=== CURL RESPONSE ===")
        print("Status Code:", result.returncode)
        print("\n=== STDOUT ===")
        print(result.stdout)
        
        if result.stderr:
            print("\n=== STDERR ===")
            print(result.stderr)
            
        return result.stdout, result.stderr, result.returncode
        
    except Exception as e:
        print(f"Error executing curl command: {e}")
        return None, str(e), -1

# Example usage
if __name__ == "__main__":
    # Check if curl.txt file exists and read from it
    curl_file = "curl.txt"
    
    if os.path.exists(curl_file):
        print(f"Reading curl command from {curl_file}...")
        curl_cmd = read_curl_from_file(curl_file)
        
        if curl_cmd:
            print(f"Executing curl command from file...")
            stdout, stderr, status = execute_curl(curl_cmd)
        else:
            print("Failed to read curl command from file.")
    else:
        print(f"File '{curl_file}' not found. Using built-in example...")
        # Your example curl command (fixed for Windows)
        curl_cmd = 'curl --path-as-is -i -s -k -X POST -H "Host: altoro.testfire.net" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: en-US,en;q=0.5" -H "Accept-Encoding: gzip, deflate, br" -H "Content-Type: application/x-www-form-urlencoded" -H "Content-Length: 77" -H "Origin: http://altoro.testfire.net" -H "Connection: keep-alive" -H "Referer: http://altoro.testfire.net/bank/transfer.jsp" -H "Upgrade-Insecure-Requests: 1" -H "Priority: u=0, i" -b "JSESSIONID=FD011FA2A6B46FDA3CE7143B2F7AD6BC; AltoroAccounts=ODAwMDAwfkNvcnBvcmF0ZX4tMS4xMTA3MjI2MTYwNzM5RTExfDgwMDAwMX5DaGVja2luZ34xLjExMTI0NzIxNTAxNDRFMTF8" --data-binary "fromAccount=800000&toAccount=800001&transferAmount=10&transfer=Transfer+Money" "http://altoro.testfire.net/bank/doTransfer"'
        
        # Execute the curl command
        stdout, stderr, status = execute_curl(curl_cmd)
    
    # You can also pass a curl command as a command line argument
    if len(sys.argv) > 1:
        if sys.argv[1].endswith('.txt'):
            # If argument is a .txt file, read from it
            print(f"\n\n=== READING FROM FILE: {sys.argv[1]} ===")
            file_curl = read_curl_from_file(sys.argv[1])
            if file_curl:
                execute_curl(file_curl)
        else:
            # Otherwise treat as curl command
            custom_curl = " ".join(sys.argv[1:])
            print("\n\n=== EXECUTING CUSTOM CURL COMMAND ===")
            execute_curl(custom_curl)