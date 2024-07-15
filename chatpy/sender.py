import os

import requests


def send_to_server(content, is_file=False):
    url = "http://127.0.0.1:5000/"
    proxies = {"http": "http://127.0.0.1:3128", "https": "http://127.0.0.1:3128"}

    try:
        if is_file:
            # Check if the file exists in the current working directory
            if not os.path.isfile(content):
                print(f"Error: File '{content}' not found.")
                return  # Exit the function if the file doesn't exist
            with open(content, "rb") as f:
                files = {"file": (content, f)}
                response = requests.post(url, files=files, proxies=proxies, timeout=2)
        else:
            response = requests.post(url, data=content.encode("utf-8"), proxies=proxies, timeout=2)
        response.raise_for_status()  # Raise an exception if the request failed
        print("Sent successfully")
        print("Server response:")
        print(response.json())
    except requests.exceptions.Timeout:
        print("Error: Request timed out. The server may be down or unresponsive.")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        print(f"Headers: {response.headers}")
        print(f"Content: {response.content}")


mode = input("Enter 't' to send text, 'f' to send a file, or 'q' to exit: ")

while True:
    if mode == "t":
        text_input = input("Enter your text: ")
        os.system("cls" if os.name == "nt" else "clear")
        print(f"Text Send: {text_input}")
        if text_input == "f":
            mode = "f"
            continue
        send_to_server(text_input)
    elif mode == "f":
        filename = input("Enter file path: ")
        os.system("cls" if os.name == "nt" else "clear")
        if filename == "t":
            mode = "t"
            continue
        send_to_server(filename, is_file=True)
    elif mode == "q":
        break
    else:
        os.system("cls" if os.name == "nt" else "clear")
        print("Invalid input.")
        break
