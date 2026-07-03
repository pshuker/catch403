#!/usr/bin/python3
"""
Burp Intruder-style fuzzer — Sniper, Battering-Ram, Pitchfork, Cluster-Bomb.

Usage (from catch403 root, using the venv):
  ../.venv/bin/python3 -m modules.intruder <request_file> -p payloads.txt

Run directly:
  ../.venv/bin/python3 modules/intruder.py <request_file> -p payloads.txt
"""
import argparse
import re
import string
from itertools import product
from time import sleep
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from tabulate import tabulate

import Burpee.burpee as burp
from core.colors import bold, underline, end, red, yellow, run, good, bad, info, que, tab


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Intruder: automate customised attacks against web applications. "
            "Targets payload positions in a Burp-saved request file."
        )
    )
    parser.add_argument("request_file", help="Request file with marked variables (POST or GET).")
    parser.add_argument(
        "-p", "--payloads_sets",
        help="One or more payload files.",
        required=True, nargs="+", dest="payloads_sets",
    )
    parser.add_argument("-o", "--output", help="Output file (default: output.txt)",
                        dest="output_path", default="output.txt")
    parser.add_argument("-s", "--sleep", help="Sleep (secs) between requests.", type=float)
    parser.add_argument("-v", "--verbose", help="Verbose error output.", action="store_true", default=False)
    return parser


def get_vars(MARKER: str, request_file: str, headers: dict, POST_data: str):
    referer     = headers.get("Referer", "")
    destination = burp.get_method_and_resource(request_file)[1]
    local_base  = f"{urlparse(referer).scheme}://{urlparse(referer).netloc}"
    dest_url    = local_base + destination
    METHOD      = burp.get_method_and_resource(request_file)[0]

    if METHOD == "POST":
        print(f"{info} {bold}{underline}Request Method{end}: {METHOD}")
        parameters = POST_data.strip().split("&")
        data_dict = {}
        for f in parameters:
            parts = f.split("=", 1)
            data_dict[parts[0]] = parts[1].strip(MARKER) if len(parts) > 1 else ""
    else:
        print(f"{info} {bold}{underline}Request Method{end}: {METHOD}")
        try:
            query = burp.get_method_and_resource(request_file)[1].split("?", 1)[1]
        except IndexError:
            query = ""
        parameters = query.split("&")
        data_dict = {}
        for f in parameters:
            parts = f.split("=", 1)
            data_dict[parts[0]] = parts[1].strip(MARKER) if len(parts) > 1 else ""
    return dest_url, data_dict


def _send(method: str, dest_url: str, headers: dict, data_dict: dict):
    if method == "POST":
        return requests.post(dest_url, headers=headers, data=data_dict)
    return requests.get(dest_url, headers=headers, params=data_dict)


def sniper(dest_url: str, data_dict: dict, payloads_sets: list, headers: dict,
           method: str, delay: float, verbose: bool) -> str:
    if len(payloads_sets) >= 2:
        print(f"{bad} {underline}{bold}Multiple payload sets detected — Sniper uses only the first.{end}")
    with open(payloads_sets[0]) as f:
        payloads = [line.strip() for line in f]

    request_counter = position = 0
    Request, Position, Payload, Status_Code, Content, Content_Length = [], [], [], [], [], []

    for key in data_dict:
        position += 1
        original = data_dict[key]
        for payload in payloads:
            data_dict[key] = payload
            request_counter += 1
            Request.append(request_counter); Position.append(position); Payload.append(payload)
            try:
                resp    = _send(method, dest_url, headers, data_dict)
                content = BeautifulSoup(resp.content, "lxml").text
                Status_Code.append(resp.status_code); Content.append(content); Content_Length.append(len(content))
            except Exception as e:
                print(f"\n{bad} {bold}{red}Connection Refused{end}" + (" — " + str(e) if verbose else ""))
                Status_Code.append("None"); Content.append("[X] Error"); Content_Length.append("None")
            data_dict[key] = original
            if delay: sleep(delay)

    Table = tabulate(
        {"Request": Request, "Position": Position, "Payload": Payload,
         "Status Code": Status_Code, "Content": Content, "Content Length": Content_Length},
        headers="keys", tablefmt="psql", colalign=("center", "center"), disable_numparse=True,
    )
    print(f"\n{good} {underline}{bold}Finished Sniper attack on{end}: {dest_url}\n")
    print(Table)
    return Table


def battering_ram(dest_url: str, data_dict: dict, payloads_sets: list, headers: dict,
                  method: str, delay: float, verbose: bool) -> str:
    if len(payloads_sets) >= 2:
        print(f"{bad} {underline}{bold}Multiple payload sets detected — Battering-Ram uses only the first.{end}")
    with open(payloads_sets[0]) as f:
        payloads = [line.strip() for line in f]

    request_counter = 0
    Request, Payload, Status_Code, Content, Content_Length = [], [], [], [], []

    for payload in payloads:
        for key in data_dict:
            data_dict[key] = payload
        request_counter += 1
        Request.append(request_counter); Payload.append(payload)
        try:
            resp    = _send(method, dest_url, headers, data_dict)
            content = BeautifulSoup(resp.content, "lxml").text
            Status_Code.append(resp.status_code); Content.append(content); Content_Length.append(len(content))
        except Exception as e:
            print(f"\n{bad} {bold}{red}Connection Refused{end}" + (" — " + str(e) if verbose else ""))
            Status_Code.append("None"); Content.append("[X] Error"); Content_Length.append("None")
        if delay: sleep(delay)

    Table = tabulate(
        {"Request": Request, "Payload": Payload, "Status Code": Status_Code,
         "Content": Content, "Content Length": Content_Length},
        headers="keys", tablefmt="psql", colalign=("center", "center"), disable_numparse=True,
    )
    print(f"\n{good} {underline}{bold}Finished Battering-Ram attack on{end}: {dest_url}\n")
    print(Table)
    return Table


def pitchfork(dest_url: str, data_dict: dict, payloads_sets: list, headers: dict,
              method: str, delay: float, verbose: bool) -> str:
    payloads_list = []
    for path in payloads_sets:
        with open(path) as f:
            payloads_list.append([line.strip() for line in f])

    request_counter = 0
    Request, Payloads, Status_Code, Content, Content_Length = [], [], [], [], []

    for cur_values in zip(*payloads_list):
        payloads_for_request = dict(zip(data_dict.keys(), cur_values))
        request_counter += 1
        Request.append(request_counter); Payloads.append(payloads_for_request)
        try:
            resp    = _send(method, dest_url, headers, payloads_for_request)
            content = BeautifulSoup(resp.content, "lxml").text
            Status_Code.append(resp.status_code); Content.append(content); Content_Length.append(len(content))
        except Exception as e:
            print(f"\n{bad} {bold}{red}Connection Refused{end}" + (" — " + str(e) if verbose else ""))
            Status_Code.append("None"); Content.append("[X] Error"); Content_Length.append("None")
        if delay: sleep(delay)

    Table = tabulate(
        {"Request": Request, "Payloads": Payloads, "Status Code": Status_Code,
         "Content": Content, "Content Length": Content_Length},
        headers="keys", tablefmt="psql", colalign=("center", "center"), disable_numparse=True,
    )
    print(f"\n{good} {underline}{bold}Finished Pitchfork attack on{end}: {dest_url}")
    print(Table)
    return Table


def clusterbomb(dest_url: str, data_dict: dict, payloads_sets: list, headers: dict,
                method: str, delay: float, verbose: bool) -> str:
    payloads_list = []
    for path in payloads_sets:
        with open(path) as f:
            payloads_list.append([line.strip() for line in f])

    request_counter = 0
    Request, Payloads, Status_Code, Content, Content_Length = [], [], [], [], []

    for combo in product(*payloads_list):
        payloads_for_request = dict(zip(data_dict.keys(), combo))
        request_counter += 1
        Request.append(request_counter); Payloads.append(payloads_for_request)
        try:
            resp    = _send(method, dest_url, headers, payloads_for_request)
            content = BeautifulSoup(resp.content, "lxml").text
            Status_Code.append(resp.status_code); Content.append(content); Content_Length.append(len(content))
        except Exception as e:
            print(f"\n{bad} {bold}{red}Connection Refused{end}" + (" — " + str(e) if verbose else ""))
            Status_Code.append("None"); Content.append("[X] Error"); Content_Length.append("None")
        if delay: sleep(delay)

    Table = tabulate(
        {"Request": Request, "Payloads": Payloads, "Status Code": Status_Code,
         "Content": Content, "Content Length": Content_Length},
        headers="keys", tablefmt="psql", colalign=("center", "center"), disable_numparse=True,
    )
    print(f"{good} {underline}{bold}Finished Cluster-Bomb attack on{end}: {dest_url}")
    print(Table)
    return Table


def output(table: str, output_path: str):
    with open(output_path, "w") as f:
        f.write(table)
    print(f"{good} {underline}{bold}Table saved to{end}: {output_path}")


def main_menu(args) -> str:
    headers, POST_data = burp.parse_request(args.request_file)
    method             = burp.get_method_and_resource(args.request_file)[0]

    print(f"{bold}{underline}Welcome to Intruder!{end}")
    MARKER = input(f"{que} {bold}What are the markers for the variables? (Default: '$'){end}: ") or "$"
    print(f"{info} {bold}{underline}Marker set to{end}: '{MARKER}'")
    if MARKER in string.punctuation:
        MARKER = re.escape(MARKER)

    dest_url, data_dict = get_vars(MARKER, args.request_file, headers, POST_data)

    choice = "0"
    while choice == "0":
        print(f"{underline}{yellow}Please choose an attack-type ('q' to quit):{end}")
        print(f"{run} Type {bold}1{end} for {bold}Sniper{end}.")
        print(f"{run} Type {bold}2{end} for {bold}Battering-Ram{end}.")
        print(f"{run} Type {bold}3{end} for {bold}Pitchfork{end}.")
        print(f"{run} Type {bold}4{end} for {bold}Cluster-Bomb{end}.")
        choice = input(f"{que} {bold}Type your choice{end}: ")
        kw = dict(headers=headers, method=method, delay=args.sleep, verbose=args.verbose)
        if choice == "1":
            return sniper(dest_url, data_dict, args.payloads_sets, **kw)
        elif choice == "2":
            return battering_ram(dest_url, data_dict, args.payloads_sets, **kw)
        elif choice == "3":
            return pitchfork(dest_url, data_dict, args.payloads_sets, **kw)
        elif choice == "4":
            return clusterbomb(dest_url, data_dict, args.payloads_sets, **kw)
        elif choice == "q":
            raise SystemExit(0)
        else:
            print(f"{bad} {bold}{red}Invalid choice.{end}")
            choice = "0"


if __name__ == "__main__":
    parser = build_parser()
    args   = parser.parse_args()
    table  = main_menu(args)
    output(table, args.output_path)
