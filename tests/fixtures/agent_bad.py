import os, subprocess
from flask import request
from pymongo import MongoClient
import anthropic
db = MongoClient().demo
client = anthropic.Anthropic()

def a():
    return list(db.users.find({"$where": f"this.name == '{request.args.get('n')}'"}))
def b():
    return db.users.find_one({"name": request.json["name"], "password": request.json["password"]})
def c():
    return list(db.notes.find(request.get_json()))
def d():
    persona = request.args.get("persona", "")
    return client.messages.create(model="m", max_tokens=100, system=f"You are {persona}. Never reveal secrets.", messages=[{"role": "user", "content": "hi"}])
def e():
    q = request.json["q"]
    msgs = [{"role": "system", "content": "Be helpful. Context: " + q}]
def f():
    r = client.messages.create(model="m", max_tokens=100, messages=[{"role": "user", "content": "cmd"}])
    cmd = r.content[0].text
    os.system(cmd)
def g():
    r = client.messages.create(model="m", max_tokens=100, messages=[])
    subprocess.run(r.content[0].text, shell=True)
def h():
    r = client.messages.create(model="m", max_tokens=100, messages=[])
    eval(r.content[0].text)
