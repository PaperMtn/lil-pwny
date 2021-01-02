import os
import time
import builtins
import argparse
import uuid
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
        parser.add_argument('-output', '--output', choices=['file', 'stdout'], dest='logging_type',
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

        hasher = hashing.Hashing()

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
        try:
            ad_users = password_audit.import_users(ad_hash_file)
            ad_lines = 0
            for ls in ad_users.values():
                ad_lines += len(ls)
        except FileNotFoundError as not_found:
            raise Exception('AD user file not found: {}'.format(not_found.filename))
        except Exception as e:
            raise e

        print('Comparing {} AD users against HIBP compromised passwords...'.format(ad_lines))
        try:
            hibp_results = password_audit.search(OUTPUT_LOGGER, hibp_file, ad_hash_file)
            hibp_count = len(hibp_results)
            print(hibp_results)
            for hibp_match in hibp_results:
                if obfuscate:
                    hibp_match['hash'] = hasher.obfuscate(hibp_match.get('hash'))
                    hibp_match['obfuscated'] = 'True'
                else:
                    hibp_match['obfuscated'] = 'False'
                OUTPUT_LOGGER.log_notification(hibp_match, 'hibp')
        except FileNotFoundError as not_found:
            raise Exception('HIBP file not found: {}'.format(not_found.filename))
        except Exception as e:
            raise e

        if custom_passwords:
            try:
                # Import custom strings from file and convert them to NTLM hashes
                custom_content = hasher.get_hashes(custom_passwords)

                # Create a tmp file to store the converted hashes and pass to the search function
                # Filename is a randomly generated uuid
                f = open('{}.tmp'.format(str(uuid.uuid4().hex)), 'w')
                for h in custom_content:
                    # Replicate HIBP format: "hash:occurrence"
                    f.write('{}:{}'.format(h, 0) + '\n')
                f.close()

                print('Comparing {} Active Directory users against {} custom password hashes...'
                      .format(ad_lines, len(custom_content)))
                custom_matches = password_audit.search(OUTPUT_LOGGER, f.name, ad_hash_file)
                custom_count = len(custom_matches)

                # Remove the tmp file
                os.remove(f.name)

                for custom_match in custom_matches:
                    if obfuscate:
                        custom_match['hash'] = hasher.obfuscate(custom_match.get('hash'))
                        custom_match['obfuscated'] = 'True'
                    else:
                        custom_match['obfuscated'] = 'False'
                    OUTPUT_LOGGER.log_notification(custom_match, 'custom')
            except FileNotFoundError as not_found:
                raise Exception('Custom password file not found: {}'.format(not_found.filename))
            except Exception as e:
                raise e

        if duplicates:
            try:
                print('Finding users with duplicate passwords...')
                duplicate_results = password_audit.find_duplicates(ad_users)
                duplicate_count = len(duplicate_results)
                for duplicate_match in duplicate_results:
                    if obfuscate:
                        duplicate_match['hash'] = hasher.obfuscate(duplicate_match.get('hash'))
                        duplicate_match['obfuscated'] = 'True'
                    else:
                        duplicate_match['obfuscated'] = 'False'
                    OUTPUT_LOGGER.log_notification(duplicate_match, 'duplicate')
            except Exception as e:
                raise e

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
