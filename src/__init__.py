import os
import sys
import time
from datetime import timedelta
import argparse
from src import hashing as h
from src import password_audit as pa


def main():
    start = time.time()

    parser = argparse.ArgumentParser()
    parser.add_argument('-hibp', '--hibp-path', help='The HIBP .txt file of NTLM hashes',
                        dest='hibp', required=True)
    parser.add_argument('-a', '--a', help='.txt file containing additional passwords to check for', dest='a')
    parser.add_argument('-ad', '--ad-hashes', help='The NTLM hashes from of AD users', dest='ad_hashes',
                        required=True)
    parser.add_argument('-d','--find-duplicates', action='store_true', dest='d',
                        help='Output a list of duplicate password users')
    parser.add_argument('-m','--memory', action='store_true', dest='m',
                        help='Load HIBP hash list into memory (over 24GB RAM required)')
    parser.add_argument('-o','--out-path', dest='output',
                        help='Set output path. Uses working dir if not set')

    args = parser.parse_args()
    hibp_file = args.hibp
    additional_password_file = args.a
    ad_hash_file = args.ad_hashes
    duplicates = args.d
    memory = args.m
    out_path = args.output

    additional_count = 0

    print("""
                __    _ __   ____
               / /   (_) /  / __ \_      ______  __  __
              / /   / / /  / /_/ / | /| / / __ \/ / / /
             / /___/ / /  / ____/| |/ |/ / / / / /_/ /
            /_____/_/_/  /_/     |__/|__/_/ /_/\__, /
                                              /____/
    """)

    print('Loading AD user hashes...')
    ad_users = pa.import_ad_hashes(ad_hash_file)
    ad_lines = len(ad_users)

    if out_path:
        if not os.path.exists(out_path):
            out_path = os.getcwd()
            print('Not a valid output path, defaulting to current dir: {}'.format(out_path))
    else:
        out_path = os.getcwd()

    if memory:
        try:
            print('Loading HIBP hash dictionary into memory...')
            f = open(hibp_file)
            content = f.read()
            hibp_lines = content.count('\n')

            print('Comparing {} Active Directory users against {} known compromised passwords...'.format(ad_lines,
                                                                                                           hibp_lines))
            pa.multi_pro_search(ad_users, content, '{}/HIBP_matches.txt'.format(out_path))
            hibp_count = len(open('{}/HIBP_matches.txt'.format(out_path)).readlines())
            print('HIBP matches output to: {}/HIBP_matches.txt\n'
                  '-----'.format(out_path))
        except FileNotFoundError as not_found:
            print('No such file or directory: {}'.format(not_found.filename))
            sys.exit()
        except OSError:
            print('Not enough memory available\n'
                  'Rerun the application without the -m flag')
            sys.exit()
    else:
        try:
            print('Loading HIBP hash dictionary...')
            content = pa.import_hibp_hashes(hibp_file)
            hibp_lines = content.count(' ')

            print('Comparing {} Active Directory users against {} known compromised passwords...'.format(ad_lines,
                                                                                                           hibp_lines))
            pa.multi_pro_search(ad_users, content, '{}/HIBP_matches.txt'.format(out_path))
            hibp_count = len(open('{}/HIBP_matches.txt'.format(out_path)).readlines())
            print('HIBP matches output to: {}/HIBP_matches.txt\n'
                  '-----'.format(out_path))
        except FileNotFoundError as not_found:
            print('No such file or directory: {}'.format(not_found.filename))
            sys.exit()

    if additional_password_file:
        try:
            print('Loading additional hashes dictionary...')

            additional_content = h.get_hashes(additional_password_file)
            additional_lines = additional_content.count(' ')

            print('Comparing {} Active Directory users against {} additional password hashes...'.format(ad_lines,
                                                                                                          additional_lines))
            pa.multi_pro_search(ad_users, additional_content, '{}/additional_matches.txt'.format(out_path))
            additional_count = len(open('{}/additional_matches.txt'.format(out_path)).readlines())
            print('Additional matches output to: {}/additional_matches.txt\n'
                  '-----'.format(out_path))
        except FileNotFoundError as not_found:
            print('No such file or directory: {}'.format(not_found.filename))
            sys.exit()

    if duplicates:
        try:
            print('Finding users with duplicate passwords...')
            pa.find_duplicates(ad_users, '{}/duplicate_passwords.txt'.format(out_path))
            print('Duplicate password matches output to: {}/duplicate_passwords.txt\n'
                  '-----'.format(out_path))
        except FileNotFoundError as not_found:
            print('No such file or directory: {}'.format(not_found.filename))
            sys.exit()

    time_taken = time.time() - start

    total_comp_count = additional_count + hibp_count

    print('Audit completed \n'
          'Total compromised passwords: {}\n'
          'Passwords matching HIBP: {}\n'
          'Passwords matching additional dictionary: {}\n'
          'Time taken: {}\n'
          '-----'.format(total_comp_count, hibp_count, additional_count, str(timedelta(seconds=time_taken))))


if __name__ == '__main__':
    main()
