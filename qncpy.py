#! venv/bin/python3

from datetime import datetime
import os
import re
import requests
import socket
import sys
from time import perf_counter
requests.packages.urllib3.disable_warnings()


def config_file_check():
    """Checks for existence of qncpy.conf file """
    if not os.path.exists('qncpy.conf'):
        print("config file qncpy.conff not found")
        sys.exit()


def read_config_file():
    """Import host, socket type and ports from config_data file"""
    """Ignore comments #, lines that start with spaces, and blank lines"""
    r_lines = []
    with open('qncpy.conf', 'r') as f:
        raw_lines = f.readlines()
        for line in raw_lines:
            if line.startswith("#") or line.startswith(" ") or not line.strip():
                pass
            else:
                 r_lines.append(line) 
    return r_lines


def port_check(hostname, port):
    """Validate port is an integer and in port range """
    port = port.strip()
    port_format = re.compile(r'^[1-9][0-9]*$')
    match = re.match(port_format, port)
    if not match:
        print(f"Ports error in line {hostname} {port} exiting")
        sys.exit()
    else:
        port = int(port)
    if port not in range(1,65536):
        print(f"{port} not in range 1 - 65535")
        sys.exit()


def check_config_data(config):
    """Validate data is valid and ready to process """
    hostname, check_type, ports = config.split('::')
    for port in ports.split(','):
        port_check(hostname, port)
    if dns_host_check(hostname) != None:
        return(hostname, check_type, ports)   
    else:
        return None


def time_stamp():
    """Current time stamp"""
    ts = datetime.now()
    return ts.strftime('%d-%b-%Y %H:%M:%S')


def today_gen():
    """Create string for date format"""
    timestamp = datetime.now()
    return timestamp.strftime('%d')


def today_write_filename_gen():
    """Create filename to write to"""
    return f'qncpy_{today_gen()}.txt'


def dict_insert(dict_name, key_name, value_name):
    """Insert if new, append if exists"""
    if key_name not in dict_name:
        dict_name.update({key_name: [value_name]})
    else:
        dict_name[key_name].append(value_name)


def http_port_check(url, ports):
    """Use requests to test for http response"""
    for port in ports.split(','):
        http_request = f'{url}:{port}'
        try:
            http_response = requests.get(http_request, timeout=3, verify=False)
            if http_response.status_code in range(100, 500):
                dict_insert(http_up, url, port.strip(' ') + f' :{http_response.status_code}')
            elif http_response.status_code in range(500, 600):
                dict_insert(http_down, url, port.strip(' ') + f' :{http_response.status_code}')
        except Exception as http_err:
            dict_insert(http_down, url, port.strip(' ') + f' :No Response')


def tcp_port_check(host, ports):
    """Use socket to test for tcp port """
    for port in ports.split(","):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            socket.setdefaulttimeout(3)
            result = sock.connect_ex((host, int(port)))    # host + port must be a tuple
            if result == 0:
                dict_insert(tcp_up, host, port.strip(' '))
            else:
                dict_insert(tcp_down, host, port.strip(' '))


def dns_host_check(hostname):
    """Validate the hostname resolves, skip if not"""
    if 'http' in hostname:
        hostname = hostname.split('//')[1]     # split off http:// etc
    if '/' in hostname:
        hostname = hostname.split('/')[0]   # split off any trailing characters after /
    try:
       dns_ip = socket.gethostbyname(hostname)
       return dns_ip
    except:
        return None


def direct_by_type(hostname, check_type, ports):
    """Send request to correct type checker """
    try:
        if check_type == 'tcp':
            tcp_port_check(hostname, ports)
        elif check_type == 'http':
            http_port_check(hostname, ports)
        else:
            dict_insert(errors, hostname, check_type + f' Unknown type detected')
    except (AttributeError, TypeError) as e:
        print("Error occurred:", e)
        sys.exit()


def run_config_data(config_data):
    for config in config_data:
        hostname, check_type, ports = config.strip().split('::')
        if check_config_data(config) != None:
            direct_by_type(hostname, check_type, ports) 
        elif check_config_data(config) == None:
            dict_insert(errors, hostname, f'{hostname} failed DNS check')


def check_parse_config(config_data):
    """Check config data is able to be parsed """
    try:
        for config in config_data:
            hostname, check_type, ports = config.strip().split('::')
    except:
        print(f"Unable to parse line {config} in qncpy.conf, exiting....")
        sys.exit()


def dict_writer(dict_name, output_file):
    if len(dict_name.items()) == 0:
        output_file.write(f"None found\n")
    else:
        for host, port in dict_name.items():
            output_file.write(f"{host:<30} {port}\n")


def dict_printer(dict_name, output_file):
    if len(dict_name.items()) == 0:
        print(f"None found\n")
    else:
        for host, port in dict_name.items():
            print(f"{host:<30} {port}")


def write_report(start_time):
    with open(today_write_filename_gen(), "w") as f:
        stop_time = perf_counter()
        f.write(f"{time_stamp()}  ")
        f.write(f"Total run time: {stop_time - start_time:.2f}s")
        f.write(f"\nhttp hosts NOT responding or 500+ response\n{'-' * 50}\n")
        dict_writer(http_down, f)
        f.write(f"\ntcp host ports NOT responding\n{'-' * 50}\n")
        dict_writer(tcp_down, f)
        f.write(f"\nhttp hosts reporting 100-499 [port :response code]\n{'-' * 50}\n")
        dict_writer(http_up, f)
        f.write(f"\ntcp hosts responding OK\n{'-' * 50}\n")
        dict_writer(tcp_up, f)
        f.write(f"\nErrors detected in config_file\n{'-' * 50}\n")
        dict_writer(errors, f)
        print("\nReport written to", today_write_filename_gen())
        print("\nversion = 0.8013") 


def print_report(start_time):
    with open(today_write_filename_gen(), "w") as f:
        stop_time = perf_counter()
        print(f"\n{time_stamp()}  ")
        print(f"Total run time: {stop_time - start_time:.2f}s")
        print(f"\nhttp hosts NOT responding or 500+ response\n{'-' * 50}\n")
        dict_printer(http_down, f)
        print(f"\ntcp host ports NOT responding\n{'-' * 50}\n")
        dict_printer(tcp_down, f)
        print(f"\nhttp hosts reporting 100-499 [port :response code]\n{'-' * 50}\n")
        dict_printer(http_up, f)
        print(f"\ntcp hosts responding OK\n{'-' * 50}\n")
        dict_printer(tcp_up, f)
        print(f"\nErrors detected in config_file\n{'-' * 50}\n")
        dict_printer(errors, f)


def main():
    config_file_check()                    # validate qncpy.conf file exists, else nothing to check
    start_time = perf_counter()            # perf counter starting
    config_data = read_config_file()       # read in config data for processing
    check_parse_config(config_data)        # validate qncpy.conf is able to be parsed successfully
    run_config_data(config_data)           # process http & tcp checks
    print_report(start_time)               # print report to screen
    write_report(start_time)               # write out to report file


if __name__ == "__main__":
    errors, tcp_up, tcp_down, http_up, http_down = {}, {}, {}, {}, {}
    main()
