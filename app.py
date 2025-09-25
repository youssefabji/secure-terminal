from flask import Flask, render_template, request, session, redirect, url_for
import subprocess
import bcrypt
import os
 

app = Flask(__name__)
app.secret_key = 'clé_secrète_sécurisée'

mot_de_passe = b"youssefhanae2027"
hashed_password = bcrypt.hashpw(mot_de_passe, bcrypt.gensalt())

allowed_commands = ["ls", "pwd", "whoami", "date", "uptime", "mkdir", "rm", "chmod", "sudo su"]

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "").encode()
        if bcrypt.checkpw(password, hashed_password):
            session["auth"] = True
            return redirect(url_for("terminal"))
        else:
            return render_template("login.html", error="Mot de passe incorrect")
    return render_template("login.html")

@app.route("/terminal", methods=["GET", "POST"])
def terminal():
    if not session.get("auth"):
        return redirect(url_for("login"))

    output = ""
    if request.method == "POST":
        cmd = request.form.get("command", "")
        cmd_base = cmd.split()[0]
        if cmd_base in allowed_commands:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                output = result.stdout or result.stderr
            except Exception as e:
                output = f"Erreur d'exécution : {str(e)}"
        else:
            output = "Commande non autorisée."
    return render_template("terminal.html", output=output)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)