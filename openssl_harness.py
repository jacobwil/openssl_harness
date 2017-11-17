#!/usr/bin/env python3

import argparse
import glob
import os
import pprint
import re
import shlex
import shutil
import statistics
import subprocess
import tqdm
from collections import defaultdict

signtime_matcher = re.compile(r"SIGNTIME: (?P<clockcount>\d+) clocks \((?P<clocks_per_second>\d+) clocks per second\)")
kxtime_matcher = re.compile(r"KXTIME: (?P<clockcount>\d+) clocks \((?P<clocks_per_second>\d+) clocks per second\)."
                            r"*MSG: (?P<additional_msg>[^\n]+)?")
# KXTIME: 86 clocks (1000000 clocks per second). MSG: kEECDH ECDH key exchange 80

ciphersuite_matcher = re.compile(r"Cipher\s*:\s*(?P<ciphersuite>[A-Z0-9-]+)")
protocol_matcher = re.compile(r"Protocol\s*:\s*(?P<protocol>(TLS|SSL)v\S+)")

clocks_per_second = None


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

    ciphersuite_list_from_openssl = subprocess_run_get_stdout("{} ciphers".format(args.openssl_binary)).split(":")

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

    print("Examining these ciphersuites: ")
    print("\t{}".format(" ".join(ciphersuite_list[:5])), end="")
    if len(ciphersuite_list) > 5:
        print(" and {} more . . . ".format(len(ciphersuite_list) - 5))
    else:
        print(" ")

    # Get the list of stacked PEMs
    if args.certificates_directory.endswith(".pem"):
        pem_cert_list = [args.certificates_directory]
    else:
        pem_cert_list = list(glob.glob(os.path.join(args.certificates_directory, "*.pem")))
    print("Using these pem files: \n\t{}".format("\n\t".join(pem_cert_list)))

    # Get the list of dhparams
    if args.certificates_directory.endswith(".pem"):
        dhparam_list = [args.certificates_directory]
    else:
        dhparam_list = list(glob.glob(os.path.join(args.certificates_directory, "*.pem")))
    print("Using these pem files: \n\t{}".format("\n\t".join(pem_cert_list)))

    # OK, let's start evaluating these ciphersuites
    # TODO: Future feature (maybe): For each certificate figure out what type of public key and how large it is
    # that way we can cleanly note it in the JSON

    # Format of this dictionary: results_dict['CIPHERSUITE']['CERTIFICATE_FILE']['DH_PARAM_FILE'] ->
    #       {'success': boolean, 'timing': ………
    #                                                          {'all_runs' : [(SIGTIME

    # defaultdict of defaultdict of dict.
    results_dict = defaultdict(lambda: defaultdict(dict))

    for ciphersuite in tqdm.tqdm(ciphersuite_list, unit="ciphersuites"):
        for pem_cert_file in tqdm.tqdm(pem_cert_list, unit="certificate files"):
            if ciphersuite.startswith("ECDH-") or ciphersuite.startswith("ECDHE-"):
                # If the dh paramaters aren't going to be used then skip it
                this_dhparam_list = [dhparam_list[0]]
            else:
                this_dhparam_list = dhparam_list

            for dh_param_file in tqdm.tqdm(this_dhparam_list, desc=f"with ciphersuite {ciphersuite}", unit="dhparam files"):
                # This level of loop is obviously going to generate a lot of nonsense when the ciphersuite is an ECDH
                # ciphersuite. We'll be smarter later. For now let's just ignore it.
                try:
                    # Start the TLS server
                    s_server_command = f"{args.openssl_binary} s_server -key {pem_cert_file} " \
                                       f"-cert {pem_cert_file} -accept {s_server_port} " \
                                       f"-dhparam {dh_param_file} -WWW"
                    s_server_popen = subprocess.Popen(shlex.split(s_server_command),
                                                      stdout=subprocess.PIPE,
                                                      stderr=subprocess.PIPE)

                    s_client_command = f"{openssl_binary} s_client -connect localhost:{s_server_port} " \
                                       f"-CAfile {pem_cert_file} -cipher {ciphersuite}"

                    s_client_command_split = shlex.split(s_client_command)

                    # Trial run to make sure that this certificate/ciphersuite combo works
                    s_client_completed_process = subprocess.run(s_client_command_split,
                                                                stdin=subprocess.DEVNULL,
                                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE
                                                                )

                    # Make sure we got a success return code
                    if 0 != s_client_completed_process.returncode:
                        results_dict[ciphersuite][os.path.basename(pem_cert_file)] = {
                            'success': False,
                            'message': f"Got non-0 return code: {s_client_completed_process.returncode}\n"
                                       f"stdout:{s_client_completed_process.stdout.decode()}\n"
                                       f"stderr:{s_client_completed_process.stderr.decode()}"
                        }
                        continue

                    # Make sure the ciphersuite is what we expected
                    actual_ciphersuite = ciphersuite_matcher.findall(s_client_completed_process.stdout.decode())[0]
                    if ciphersuite != actual_ciphersuite:
                        results_dict[ciphersuite][os.path.basename(pem_cert_file)] = {
                            'success': False,
                            'message': f"Got unexpected ciphersuite: {actual_ciphersuite}\n"
                                       f"stdout:{s_client_completed_process.stdout.decode()}\n"
                                       f"stderr:{s_client_completed_process.stderr.decode()}"
                        }
                        continue

                    # The successful run above will be the first iteration
                    for __ in tqdm.tqdm(range(args.iterations - 1),
                                        desc=f"{ciphersuite} using {os.path.basename(pem_cert_file)} "
                                             f"and {os.path.basename(dh_param_file)}",
                                        initial=1, total=args.iterations,
                                        leave=True):
                        s_client_completed_process = subprocess.run(s_client_command_split,
                                                                    stdin=subprocess.DEVNULL,
                                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                                                                    )
                        s_client_completed_process.check_returncode()

                    s_server_popen.terminate()
                    # capture stderr output
                    server_stderr = s_server_popen.stderr.read().decode()
                    signtimes_raw = signtime_matcher.findall(server_stderr)
                    signtimes = [int(e[0]) for e in signtimes_raw]

                    if not clocks_per_second:
                        # We only need to capture this once
                        clocks_per_second = signtimes_raw[0][1]

                    kxtimes_raw = kxtime_matcher.findall(server_stderr)
                    kxtimes = [int(e[0]) for e in kxtimes_raw]
                    kx_messages = list({e[2] for e in kxtimes_raw})

                    results_dict[ciphersuite][os.path.basename(pem_cert_file)] = {
                        'success': True,
                        'message': "",
                        "signature_clocks": signtimes,
                        "signature_clocks_average": statistics.mean(signtimes),
                        "signature_clocks_stddev": statistics.stdev(signtimes),
                        "key_exchange_clocks": kxtimes,
                        "key_exchange_clocks_average": statistics.mean(kxtimes),
                        "key_exchange_clocks_stddev": statistics.stdev(kxtimes),
                        "key_exchange_message_set": kx_messages
                    }

                except Exception as e:
                    tqdm.tqdm.write(
                        f"While handling {ciphersuite} with {pem_cert_file} encountered unexpected exception ")
                    results_dict[ciphersuite][os.path.basename(pem_cert_file)] = {
                        'success': False,
                        'message': f"Unexpected exception: {e}\n"
                                   f"stdout:{s_client_completed_process.stdout.decode()}\n"
                                   f"stderr:{s_client_completed_process.stderr.decode()}"
                    }
                    continue
                finally:
                    s_server_popen.kill()

print("done")

results_dict['clocks_per_second'] = clocks_per_second

with open("results.json", "w") as f:
    import json

    json.dump(results_dict, f)
# done
