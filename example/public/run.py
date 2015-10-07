from flask import Flask, send_file
app = Flask(__name__)


@app.route('/')
def man():
    return 'Hi, man'


@app.route('/<filename>')
def flag(filename):
    return send_file(filename)

if __name__ == '__main__':
    app.run()