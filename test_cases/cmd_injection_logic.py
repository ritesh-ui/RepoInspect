import subprocess
import os

def safe_list_execution(user_input):
    # This should NOT be flagged (list-based, shell=False)
    subprocess.run(["ls", "-l", user_input])
    subprocess.Popen(["git", "commit", "-m", user_input])

def safe_constant_execution():
    # This should NOT be flagged (no user input, no shell)
    subprocess.call(["whoami"])

def vulnerable_shell_true(user_input):
    # This SHOULD be flagged (shell=True)
    subprocess.run(f"ls {user_input}", shell=True)
    subprocess.check_call("echo " + user_input, shell=True)

def vulnerable_os_system(user_input):
    # This SHOULD be flagged (os.system is always risky)
    os.system(f"rm -rf {user_input}")
    os.popen(f"cat {user_input}")

def vulnerable_eval_exec(user_input):
    # This SHOULD be flagged
    eval(user_input)
    exec("print(" + user_input + ")")
