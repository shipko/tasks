from flask import Flask, send_file
app = Flask(__name__)


@app.route('/')
def man():
    return 'Hi, man'


@app.route('/flag')
def flag():
    return send_file('static/flag.txt')

if __name__ == '__main__':
    app.run()