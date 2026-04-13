import subprocess

def handle_request(args):
    # This is user input
    subprocess.run(["git", *args], check=False, capture_output=True, text=True)

