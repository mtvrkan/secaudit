# SECURE COUNTERPART — SecAudit negative-control fixture. Not real code.
import json


# S49 — Dangerous execution left off (CWE-94 fixed): the chain runs read-only against a
# restricted role, and the library's own guard stays where it is.
def build_chain(llm, db):
    from langchain_experimental.sql import SQLDatabaseChain
    return SQLDatabaseChain.from_llm(llm, db, return_direct=True)


# S50 — No arbitrary-code tool (CWE-94 fixed): the agent gets a narrow, typed calculator
# instead of an interpreter, so the worst case is a wrong number.
def tools_for(llm):
    return [_calculator()]


def _calculator():
    def add(a: float, b: float) -> float:
        return a + b

    return add


# S51 — No shell (CWE-78 fixed): the two operations the agent actually needs are exposed as
# named functions with validated arguments, which is the allowlist a terminal cannot have.
ALLOWED = {"list_reports", "fetch_report"}


def shell_tools(llm):
    return [name for name in sorted(ALLOWED)]


# S52 — Model output parsed as data (CWE-94 fixed): a schema-checked structure, never code.
def run_plan(llm, question):
    response = llm.invoke(question)
    plan = json.loads(response.content)
    if not isinstance(plan, dict) or plan.get("action") not in ALLOWED:
        raise ValueError("model proposed an action outside the allowlist")
    return plan
