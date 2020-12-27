import os
import sys
import time
import builtins
import argparse
from datetime import timedelta

from lil_pwny import hashing
from lil_pwny import password_audit
from lil_pwny import logger

OUTPUT_LOGGER = ''


def main():
    global OUTPUT_LOGGER
    custom_count = 0
    duplicate_count = 0

    try:
        start = time.time()

        parser = argparse.ArgumentParser()
        parser.add_argument('-hibp', '--hibp-path', help='The HIBP .txt file of NTLM hashes',
                            dest='hibp', required=True)
        parser.add_argument('-c', '--custom', help='.txt file containing additional custom passwords to check for',
                            dest='custom')
        parser.add_argument('-ad', '--ad-hashes', help='The NTLM hashes from of AD users', dest='ad_hashes',
                            required=True)
        parser.add_argument('-d', '--duplicates', action='store_true', dest='d',
                            help='Output a list of duplicate password users')
        parser.add_argument('--output', choices=['file', 'stdout'], dest='logging_type',
                            help='Where to send results')
        parser.add_argument('-o', '--obfuscate', action='store_true', dest='obfuscate',
                            help='Obfuscate hashes from discovered matches by hashing with a random salt')

        args = parser.parse_args()
        hibp_file = args.hibp
        custom_passwords = args.custom
        ad_hash_file = args.ad_hashes
        duplicates = args.d
        logging_type = args.logging_type
        obfuscate = args.obfuscate

        if logging_type:
            if logging_type == 'file':
                OUTPUT_LOGGER = logger.FileLogger(log_path=os.getcwd())
            elif logging_type == 'stdout':
                OUTPUT_LOGGER = logger.StdoutLogger()
        else:
            OUTPUT_LOGGER = logger.StdoutLogger()

        if isinstance(OUTPUT_LOGGER, logger.StdoutLogger):
            print = OUTPUT_LOGGER.log_info
        else:
            print = builtins.print

        print('*** Lil Pwny started execution ***')
        print('Loading AD user hashes...')
        ad_users = password_audit.import_hashes(ad_hash_file)
        ad_lines = len(ad_users)

        print('Loading HIBP hash dictionary...')

        hibp_hashes = password_audit.import_hashes(hibp_file)
        hibp_lines = len(hibp_hashes)

        print('Comparing {} AD users against {} known compromised passwords...'.format(ad_lines, hibp_lines))
        hibp_results = password_audit.multi_pro_search(OUTPUT_LOGGER, ad_users, hibp_hashes)
        hibp_count = len(hibp_results)
        for hibp_match in hibp_results:
            if obfuscate:
                hibp_match['hash'] = hashing.obfuscate(hibp_match.get('hash'))
                hibp_match['obfuscated'] = 'True'
            else:
                hibp_match['obfuscated'] = 'False'
            OUTPUT_LOGGER.log_notification(hibp_match, 'hibp')

        if custom_passwords:
            try:
                print('Loading additional custom hashes dictionary...')

                custom_content = hashing.get_hashes(custom_passwords)

                print('Comparing {} Active Directory users against {} custom password hashes...'
                      .format(ad_lines, len(custom_content)))
                custom_matches = password_audit.multi_pro_search(OUTPUT_LOGGER, ad_users, custom_content)
                custom_count = len(custom_matches)
                for custom_match in custom_matches:
                    if obfuscate:
                        custom_match['hash'] = hashing.obfuscate(custom_match.get('hash'))
                        custom_match['obfuscated'] = 'True'
                    else:
                        custom_match['obfuscated'] = 'False'
                    OUTPUT_LOGGER.log_notification(custom_match, 'custom')
            except FileNotFoundError as not_found:
                print('No such file or directory: {}'.format(not_found.filename))
                sys.exit()

        if duplicates:
            try:
                print('Finding users with duplicate passwords...')
                duplicate_results = password_audit.find_duplicates(ad_users)
                duplicate_count = len(duplicate_results)
                for duplicate_match in duplicate_results:
                    if obfuscate:
                        duplicate_match['hash'] = hashing.obfuscate(duplicate_match.get('hash'))
                        duplicate_match['obfuscated'] = 'True'
                    else:
                        duplicate_match['obfuscated'] = 'False'
                    OUTPUT_LOGGER.log_notification(duplicate_match, 'duplicate')
            except FileNotFoundError as not_found:
                print('No such file or directory: {}'.format(not_found.filename))
                sys.exit()

        time_taken = time.time() - start

        total_comp_count = custom_count + hibp_count

        print('Audit completed')
        print('Total compromised passwords: {}'.format(total_comp_count))
        print('Passwords matching HIBP: {}'.format(hibp_count))
        print('Passwords matching custom password dictionary: {}'.format(custom_count))
        print('Passwords duplicated (being used by multiple user accounts): {}'.format(duplicate_count))
        print('Time taken: {}'.format(str(timedelta(seconds=time_taken))))

    except Exception as e:
        if isinstance(OUTPUT_LOGGER, logger.StdoutLogger):
            OUTPUT_LOGGER.log_critical(e)
        else:
            print = builtins.print
            print(e)


if __name__ == '__main__':
    main()
