import subprocess
from flask import request
from pymongo import MongoClient
import anthropic
db = MongoClient().demo
client = anthropic.Anthropic()
ACTIONS = {"uptime": ["uptime"]}
def a():
    return db.users.find_one({"name": str(request.json["name"])})
def d():
    persona = request.args.get("persona", "")
    return client.messages.create(model="m", max_tokens=100, system="You are a support bot.", messages=[{"role": "user", "content": persona}])
def f():
    r = client.messages.create(model="m", max_tokens=100, messages=[])
    action = ACTIONS.get(r.content[0].text.strip())
    if action: subprocess.run(action)
