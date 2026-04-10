import os
import subprocess
import sqlite3
from langchain_openai import ChatOpenAI

def vulnerable_command_execution(user_input):
    # Data flow: user_input -> cmd -> subprocess.run
    # This should be caught by AST Taint Analysis
    cmd = "echo " + user_input
    subprocess.run(cmd, shell=True)

def safe_usage(name):
    # Regex might flag this because of "execute", 
    # but AST should see no user-controlled data flow to a database.
    query = "SELECT * FROM users WHERE name = 'fixed_name'"
    db = sqlite3.connect("users.db")
    db.execute(query)

def prompt_injection_flow(api_key, raw_prompt):
    # AI Security Risk: raw_prompt -> final_prompt -> llm.invoke
    client = ChatOpenAI(openai_api_key=api_key)
    final_prompt = f"Summarize this: {raw_prompt}"
    return client.invoke(final_prompt)
