import subprocess
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)


@app.route("/greet")
def greet():
    # The name is HTML-escaped before it is placed in the template source.
    name = escape(request.args.get("name", "guest"))
    return render_template_string("<h1>Hello " + str(name) + "</h1>")


@app.route("/archive")
def archive():
    target = request.args.get("path", ".")
    return subprocess.check_output("tar -czf /tmp/out.tgz " + target, shell=True)
