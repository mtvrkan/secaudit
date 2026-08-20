# INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
from langchain.agents import load_tools
from langchain_experimental.tools import PythonREPLTool


# V49 — Dangerous execution explicitly enabled (CWE-94): the guard the library ships with is
# switched off, so model output is executed.
def build_chain(llm, db):
    from langchain_experimental.sql import SQLDatabaseChain
    return SQLDatabaseChain.from_llm(llm, db, allow_dangerous_requests=True)


# V50 — Code-execution tool exposed to the model (CWE-94): a Python REPL is arbitrary code
# execution with the agent's credentials.
def tools_for(llm):
    return [PythonREPLTool()]


# V51 — Shell tool exposed to the model (CWE-78): excessive agency; anything the model is
# talked into typing, the host runs.
def shell_tools(llm):
    return load_tools(["terminal"], llm=llm)


# V52 — Model output flows into a code-execution sink (CWE-94): the completion is treated as
# code rather than as untrusted data.
def run_plan(llm, question):
    response = llm.invoke(question)
    return eval(response.content)
