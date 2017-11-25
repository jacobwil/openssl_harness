#!/usr/bin/env python3

import argparse
import glob
import gzip
import json
import os
import pprint
import re
import shlex
import shutil
import statistics
import subprocess
import tqdm
import traceback
from collections import defaultdict

signtime_matcher = re.compile(r"^SIGNTIME: (?P<clockcount>\d+) clocks \((?P<clocks_per_second>\d+) clocks per second\)",
                              re.MULTILINE)
kxtime_matcher = re.compile(r"^KXTIME: (?P<clockcount>\d+) clocks \((?P<clocks_per_second>\d+) clocks per second\)."
                            r"*MSG: (?P<additional_msg>[^\n]+)?", re.MULTILINE)

bandwidth_match = re.compile(r"^SSL handshake has read (?P<readbytes>\d+) bytes and written (?P<writebytes>\d+) bytes",
                             re.MULTILINE)

# ECDHE-ECDSA-CHACHA20-POLY1305-OLD TLSv1.2 Kx=ECDH     Au=ECDSA Enc=ChaCha20(256) Mac=AEAD
ciphersuite_list_extracter = re.compile("^(?P<ciphersuite>\S+) +(?P<protocolversion>(TLS|SSL)\S+) +Kx=(?P<kxalg>\S+) +"
                                        "Au=(?P<authalg>\S+) +Enc=(?P<encalg>\S+) +Mac=(?P<macalg>\S+)",
                                        re.MULTILINE)

ciphersuite_matcher = re.compile(r"Cipher\s*:\s*(?P<ciphersuite>[A-Z0-9-]+)")
protocol_matcher = re.compile(r"Protocol\s*:\s*(?P<protocol>(TLS|SSL)v\S+)")

curve_matcher = re.compile(r"^\s*(?P<curve_name>[^ :]+)\s*:", re.MULTILINE)

clocks_per_second = None


def simplify_kxarg(input_kxarg: str) -> str:
    if not input_kxarg or input_kxarg == '':
        return "no_kxarg"
    else:
        return input_kxarg.split()[-1].strip()


def str_if_not_invalid(in_object: object, default_str: str = "") -> str:
    """
    Lazy way to convert bad object references into empty string or default
    """
    try:
        return str(in_object)
    except:
        return default_str


def subprocess_run_get_stdout(command: str, check_return_code: bool = True) -> str:
    """
    Run a command (in the same style it would be typed into a shell) and capture stdout. 
    :param command: The command to run (as a string, how it would be typed into a shell).
    :param check_return_code: If the return code should be checked. If this is set to True and `command` has 
    a non-zero return code then an Exception will be raised. 
    :return: stdout from `command`
    """
    completed_process = subprocess.run(shlex.split(command), stdout=subprocess.PIPE)

    if check_return_code:
        if not 0 == completed_process.returncode:
            raise Exception("Command {} returned non-zero status {}".format(command, completed_process.returncode))
        elif not completed_process.stdout:
            raise Exception("Command {} didn't return output".format(command))

    if completed_process.stdout:
        return completed_process.stdout.decode().strip()
    else:
        return ""


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    argparser.add_argument("-b", "--openssl-binary",
                           help="Path to an openssl binary to use. Must have been modified to print out timing "
                                "information to stderr. \n"
                                "See https://github.com/jacobwil/openssl",
                           type=str,
                           required=True
                           )

    argparser.add_argument("-n", "--iterations",
                           help="How many times should each ciphersuite be evaluated",
                           type=int,
                           default=100
                           )

    argparser.add_argument("-l", "--ciphersuite-list",
                           help="List of ciphersuites to try, ':' separated",
                           type=str,
                           default=None)

    argparser.add_argument("-m", "--curve-list",
                           help="List of curves to try, ':' separated",
                           type=str,
                           default=None)

    argparser.add_argument("-f", "--filter-curve-certs",
                           help="Filter the list of ec certs using the --curve-list argument",
                           default=False,
                           action="store_true")

    argparser.add_argument("-c", "--certificates-directory",
                           help="Path to a directory containing PEM files which each contain both a certificate and "
                                "unencrypted private key. Or a path to a single pem file. "
                                "All filenames to be used must end in '.pem'",
                           required=True,
                           type=str)

    argparser.add_argument("-d", "--dhparam-directory",
                           help="Path to a directory containing PEM files which each contain a DH parameter. "
                                " Or a path to a single pem file. "
                                "All filenames to be used must end in '.pem'",
                           required=True,
                           type=str)

    argparser.add_argument("-p", "--port",
                           help="The port to use for the openssl s_server processes",
                           type=int,
                           default=44330)

    args = argparser.parse_args()

    s_server_port = args.port
    openssl_binary = args.openssl_binary

    if not os.path.isfile(args.openssl_binary):
        raise Exception(
            "'{}' is not an executable. Please provide a valid path to a binary.".format(args.openssl_binary))
    if not os.access(args.openssl_binary, os.X_OK):
        raise Exception(
            "'{}' is not an executable. Please provide a path to a valid binary.".format(args.openssl_binary))

    # Get the openssl version
    openssl_version = subprocess_run_get_stdout("{} version".format(args.openssl_binary))

    print("Using openssl binary at '{}'".format(args.openssl_binary))
    print("\tVersion: {}".format(openssl_version))

    # Get the list of stacked PEMs
    if args.certificates_directory.endswith(".pem"):
        pem_cert_list = [args.certificates_directory]
    else:
        pem_cert_list = list(glob.glob(os.path.join(args.certificates_directory, "*.pem")))
    # print("Using these pem files: \n\t{}".format("\n\t".join(pem_cert_list)))

    # Get the list of dhparams
    if args.certificates_directory.endswith(".pem"):
        dhparam_list = [args.certificates_directory]
    else:
        dhparam_list = list(glob.glob(os.path.join(args.dhparam_directory, "*.pem")))

    dhparam_arg_list = [" -dhparam {} ".format(dh_file) for dh_file in dhparam_list]

    # Get the list of ciphersuites from openssl and parse the output into dicts.
    ciphersuite_list_from_openssl_raw = subprocess_run_get_stdout(f"{args.openssl_binary} ciphers -v")
    ciphersuite_dicts = {e['ciphersuite']: e.groupdict() for e in
                         ciphersuite_list_extracter.finditer(ciphersuite_list_from_openssl_raw)}

    ciphersuite_list_from_openssl = list(ciphersuite_dicts.keys())

    curve_list_from_openssl_raw = subprocess_run_get_stdout(f"{args.openssl_binary} ecparam -list_curves")
    curve_list_from_openssl = curve_matcher.findall(curve_list_from_openssl_raw)

    if args.curve_list:
        raw_arg_curve_list = args.curve_list.split(":")

        not_supported = set(raw_arg_curve_list).difference(curve_list_from_openssl)

        if not_supported:
            print(" ")
            print("WARNING: The following curves are not supported "
                  "by this version of openssl and will be ignored: {}".format(" ".join(not_supported)))
            print(" ")

        curve_list = list(set(raw_arg_curve_list).intersection(curve_list_from_openssl))

        if args.filter_curve_certs:
            # Selected curve set
            curve_set = set(curve_list)

            # Now if we need to filter the certs we need to break out the ec and non-ec segments
            # Depend on filename for now. Someday parse `openssl x509`output
            non_ec_certs = [cert for cert in pem_cert_list if not cert.startswith("ec_")]
            ec_certs = [cert for cert in pem_cert_list if cert.startswith("ec_")]

            # Filter the ec certs now
            ec_certs_filtered = list(filter(lambda n: set(n.split("_")) & curve_set, ec_certs))
            pem_cert_list = non_ec_certs + ec_certs_filtered

            print(f"Filtered to cert list "
                  f"(dropped {len(non_ec_certs + ec_certs) - len(pem_cert_list)}) "
                  f"{pem_cert_list}")
    else:
        curve_list = curve_list_from_openssl

    ec_curve_arg_list_unfiltered = [" -named_curve {} ".format(curve) for curve in curve_list]

    # Now we need to figure out which of these curves is supported for TLS
    # Some of these curves aren't actually supported by openssl it seems
    ec_curve_arg_list = list()  # Will hold valid TLS curves
    pem_cert_file = "basic_certs/ec_server.pem"
    for ec_curve_arg in ec_curve_arg_list_unfiltered:
        try:
            s_server_command = f"{args.openssl_binary} s_server -key {pem_cert_file} " \
                               f"-cert {pem_cert_file} -accept {s_server_port} " \
                               f"{ec_curve_arg} -WWW"
            s_client_command = f"{openssl_binary} s_client -connect localhost:{s_server_port} " \
                               f"-CAfile {pem_cert_file}"

            s_server_popen = subprocess.Popen(shlex.split(s_server_command),
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)

            s_client_completed_process = subprocess.run(shlex.split(s_client_command),
                                                        stdin=subprocess.DEVNULL,
                                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE
                                                        )
            if s_client_completed_process.returncode == 0:
                ec_curve_arg_list.append(ec_curve_arg)
        finally:
            s_server_popen.kill()

    print(ec_curve_arg_list)
    print(f"{len(ec_curve_arg_list)} of {len(ec_curve_arg_list_unfiltered)}")

    if not args.ciphersuite_list:
        # We weren't provided a list of ciphersuites so ask the openssl binary
        ciphersuite_list = ciphersuite_list_from_openssl
    else:
        ciphersuite_list = args.ciphersuite_list.split(":")

        not_supported = set(ciphersuite_list).difference(ciphersuite_list_from_openssl)

        if not_supported:
            print(" ")
            print("WARNING: The following ciphersuites are not supported "
                  "by this version of openssl and will be ignored: {}".format(" ".join(not_supported)))
            print(" ")

        ciphersuite_list = list(set(ciphersuite_list).intersection(ciphersuite_list_from_openssl))

        # Also filter the ciphersuite dictionaries
        ciphersuite_dicts = {k: v for k, v in ciphersuite_dicts.items() if k in ciphersuite_list}

    print("Examining these ciphersuites: ")
    print("\t{}".format(" ".join(ciphersuite_list[:5])), end="")
    if len(ciphersuite_list) > 5:
        print(" and {} more . . . ".format(len(ciphersuite_list) - 5))
    else:
        print(" ")

    # OK, let's start evaluating these ciphersuites
    # TODO: Future feature (maybe): For each certificate figure out what type of public key and how large it is
    # that way we can cleanly note it in the JSON

    # Format of this dictionary: results_dict['CIPHERSUITE']['CERTIFICATE_FILE']['DH_PARAM_FILE'] ->
    #       {'success': boolean, 'timing': ………
    #                                                          {'all_runs' : [(SIGTIME

    # defaultdict of defaultdict of defaultdict of dict.
    results_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
    s_server_popen = None

    full_command_list = []

    for ciphersuite, ciphersuite_dict in tqdm.tqdm(ciphersuite_dicts.items(), unit="ciphersuites"):
        results_dict[ciphersuite]['ciphersuite_info'] = ciphersuite_dict

        # Figure out the correct set of key exchange modifying arguments to use for the server
        if 'ECDH' in ciphersuite_dict['kxalg']:
            # if this is an EC ciphersuite then we're going to select the curve serverside
            this_kxarg_list = ec_curve_arg_list
        elif 'DH' in ciphersuite_dict['kxalg']:
            # otherwise, if it's classical DH then use the dhparam arg list
            this_kxarg_list = dhparam_arg_list
        else:
            # If it is neither a DH nor ECDH ciphersuite then this argument doesn't matter so skip it
            this_kxarg_list = ['']

        # Filter certificates
        # possible values  {'DH', 'DSS', 'ECDH', 'ECDSA', 'PSK', 'RSA', 'SRP'}
        authalg = ciphersuite_dict['authalg']
        if 'RSA' == authalg:
            this_cert_list = filter(lambda c: "rsa" in c, pem_cert_list)
        elif 'ECDSA' == authalg:
            this_cert_list = filter(lambda c: "ec" in c, pem_cert_list)
        elif 'DSS' == authalg:
            this_cert_list = filter(lambda c: "dsa" in c, pem_cert_list)
        else:
            this_cert_list = pem_cert_list

        for pem_cert_file in tqdm.tqdm(this_cert_list, unit="certificate files", desc=f"{ciphersuite[:10]}"):
            for this_kxarg in tqdm.tqdm(this_kxarg_list, desc=f"{pem_cert_file} with ciphersuite {ciphersuite}",
                                        unit="Key Exchange Parameters"):
                # Generate the commands
                s_server_command = f"{args.openssl_binary} s_server -key {pem_cert_file} " \
                                   f"-cert {pem_cert_file} -accept {s_server_port} " \
                                   f"{this_kxarg} -WWW"
                s_client_command = f"{openssl_binary} s_client -connect localhost:{s_server_port} " \
                                   f"-CAfile {pem_cert_file} -cipher {ciphersuite}"

                this_config_result_dict = {
                    "s_server_command": s_server_command,
                    "s_client_command": s_client_command
                }
                # This level of loop is obviously going to generate a lot of nonsense when the ciphersuite is an ECDH
                # ciphersuite. We'll be smarter later. For now let's just ignore it.
                try:
                    # Reset these in case we hit the except block
                    server_stdout = ""
                    server_stderr = ""
                    s_client_completed_process = None

                    full_command_list.append((s_server_command, s_client_command))

                    s_server_popen = subprocess.Popen(shlex.split(s_server_command),
                                                      stdout=subprocess.PIPE,
                                                      stderr=subprocess.PIPE)

                    s_client_command_split = shlex.split(s_client_command)

                    # Trial run to make sure that this certificate/ciphersuite combo works
                    s_client_completed_process = subprocess.run(s_client_command_split,
                                                                stdin=subprocess.DEVNULL,
                                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE
                                                                )

                    # Make sure we got a success return code
                    if 0 != s_client_completed_process.returncode:
                        this_config_result_dict = {
                            **this_config_result_dict,
                            'success': False,
                            'message': f"Got non-0 return code: {s_client_completed_process.returncode}\n"
                                       f"client_stdout:"
                                       f"{str_if_not_invalid(s_client_completed_process.stdout.decode())}\n"
                                       f"client_stderr:"
                                       f"{str_if_not_invalid(s_client_completed_process.stderr.decode())}\n"
                                       f"server_stdout:{server_stdout}\n"
                                       f"server_stderr:{server_stderr}"
                        }
                        continue

                    # Make sure the ciphersuite is what we expected
                    actual_ciphersuite = ciphersuite_matcher.findall(s_client_completed_process.stdout.decode())[0]
                    if ciphersuite != actual_ciphersuite:
                        this_config_result_dict = {
                            **this_config_result_dict,
                            'success': False,
                            'message': f"Got unexpected ciphersuite: {actual_ciphersuite}\n"
                                       f"client_stdout:"
                                       f"{str_if_not_invalid(s_client_completed_process.stdout.decode())}\n"
                                       f"client_stderr:"
                                       f"{str_if_not_invalid(s_client_completed_process.stderr.decode())}\n"
                                       f"server_stdout:{server_stdout}\n"
                                       f"server_stderr:{server_stderr}"
                        }
                        continue

                    s_client_all_client_stdout = [s_client_completed_process.stdout.decode()]

                    # The successful run above will be the first iteration
                    for __ in tqdm.tqdm(range(args.iterations - 1),
                                        desc=f"{ciphersuite} using {os.path.basename(pem_cert_file)} "
                                             f"and {this_kxarg}",
                                        initial=1, total=args.iterations,
                                        leave=True):
                        s_client_completed_process = subprocess.run(s_client_command_split,
                                                                    stdin=subprocess.DEVNULL,
                                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                                                                    )
                        s_client_completed_process.check_returncode()
                        s_client_all_client_stdout.append(s_client_completed_process.stdout.decode())

                    s_server_popen.terminate()
                    # capture stderr output from server
                    server_stderr = s_server_popen.stderr.read().decode()
                    signclocks_raw = signtime_matcher.findall(server_stderr)
                    signclocks = [int(e[0]) for e in signclocks_raw]

                    if not clocks_per_second:
                        # We only need to capture this once
                        clocks_per_second = int(signclocks_raw[0][1])

                    kxclocks_raw = kxtime_matcher.findall(server_stderr)
                    kxclocks = [int(e[0]) for e in kxclocks_raw]
                    kx_messages = list({e[2] for e in kxclocks_raw})

                    # Get the bandwidth data from the client
                    bandwidth_raw = bandwidth_match.findall("\n".join(s_client_all_client_stdout))
                    # client_bytes_read_list_raw, client_bytes_sent_list_raw = [e[0], e[1] for e in bandwidth_raw]
                    client_bytes_read_list = list(map(lambda x: int(x[0]), bandwidth_raw))
                    client_bytes_sent_list = list(map(lambda x: int(x[1]), bandwidth_raw))

                    if not len(bandwidth_raw) == len(signclocks) == len(kxclocks):
                        raise Exception(f"Got different amounts of output for each metric"
                                        f"bandwidth_raw:{len(bandwidth_raw)} "
                                        f"signclocks:{len(signclocks)} "
                                        f"kxclocks:{len(kxclocks)}")

                    this_config_result_dict = {
                        **this_config_result_dict,
                        'success': True,
                        'message': "",
                        "signature_clocks": signclocks,
                        "signature_clocks_average": statistics.mean(signclocks),
                        "signature_clocks_stddev": statistics.stdev(signclocks),
                        "signature_seconds_average": statistics.mean(signclocks) / clocks_per_second,
                        "signature_seconds_stddev": statistics.stdev(signclocks) / clocks_per_second,
                        "key_exchange_clocks": kxclocks,
                        "key_exchange_clocks_average": statistics.mean(kxclocks),
                        "key_exchange_clocks_stddev": statistics.stdev(kxclocks),
                        "key_exchange_seconds_average": statistics.mean(kxclocks) / clocks_per_second,
                        "key_exchange_seconds_stddev": statistics.stdev(kxclocks) / clocks_per_second,
                        "key_exchange_message_set": kx_messages,
                        "client_bytes_read": client_bytes_read_list,
                        "client_bytes_read_average": statistics.mean(client_bytes_read_list),
                        "client_bytes_read_stddev": statistics.stdev(client_bytes_read_list),
                        "client_bytes_sent": client_bytes_sent_list,
                        "client_bytes_sent_average": statistics.mean(client_bytes_sent_list),
                        "client_bytes_sent_stddev": statistics.stdev(client_bytes_sent_list)
                    }

                except Exception as e:
                    tqdm.tqdm.write(
                        f"While handling {ciphersuite} with {pem_cert_file} encountered "
                        f"unexpected exception {traceback.format_exc()}"
                    )
                    this_config_result_dict = {
                        **this_config_result_dict,
                        'success': False,
                        'message': f"Unexpected exception: '{traceback.format_exc()}'\n"
                                   f"client_stdout:{str_if_not_invalid(s_client_completed_process.stdout.decode())}\n"
                                   f"client_stderr:{str_if_not_invalid(s_client_completed_process.stderr.decode())}\n"
                                   f"server_stdout:{server_stdout}\n"
                                   f"server_stderr:{server_stderr}"
                    }
                    continue
                finally:
                    results_dict[ciphersuite]['benchmark'][os.path.basename(pem_cert_file)][
                        simplify_kxarg(this_kxarg)] = this_config_result_dict

                    if not s_server_popen:
                        print("s_server_popen doesn't exist, ran command {}".format(s_server_command))
                    else:
                        s_server_popen.kill()

            with open("checkpoint.json.gz", "wb") as f:
                f.write(json.dumps(results_dict).encode())

output_dict = {
    'benchmark_results': results_dict,
    'clocks_per_second': clocks_per_second
}

with open("results.json", "w") as f:
    json.dump(output_dict, f)

# done
