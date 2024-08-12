import argparse
import os
import sys
import tempfile
import time
import traceback
import warnings
from datetime import timedelta
from importlib import metadata

from lil_pwny import password_audit, hashing
from lil_pwny.loggers import JSONLogger, StdoutLogger
from lil_pwny.exceptions import FileReadError
from lil_pwny.custom_list_enhancer import CustomListEnhancer

output_logger = JSONLogger


def init_logger(logging_type: str, debug: bool) -> JSONLogger or StdoutLogger:
    """ Create a logger object. Defaults to stdout if no option is given

    Args:
        logging_type: Type of logging to use
        debug: Whether to use debug level logging or not
    Returns:
        JSONLogger or StdoutLogger
    """

    if not logging_type or logging_type == 'stdout':
        return StdoutLogger(debug=debug)
    return JSONLogger(debug=debug)


def get_readable_file_size(file_path: str) -> str:
    """ Get the size of a file in a human readable format

    Args:
        file_path: Path to the file to get the size of
    Returns:
        Human readable file size in bytes, KB, MB or GB
    """

    file_size_bytes = os.path.getsize(file_path)

    if file_size_bytes < 1024:  # Less than 1 KB
        return f"{file_size_bytes} bytes"
    elif file_size_bytes < 1024 ** 2:  # Less than 1 MB
        file_size_kb = file_size_bytes / 1024
        return f"{file_size_kb:.2f} KB"
    elif file_size_bytes < 1024 ** 3:  # Less than 1 GB
        file_size_mb = file_size_bytes / (1024 ** 2)
        return f"{file_size_mb:.2f} MB"
    else:  # 1 GB or more
        file_size_gb = file_size_bytes / (1024 ** 3)
        return f"{file_size_gb:.2f} GB"


def main():
    try:
        start = time.time()
        project_metadata = metadata.metadata('lil-pwny')

        parser = argparse.ArgumentParser(description='Fast offline auditing of Active Directory passwords using Python')
        parser.add_argument(
            '-hibp', '--hibp',
            help='The .txt file containing HIBP NTLM hashes',
            dest='hibp',
            required=True)
        parser.add_argument(
            '-v', '--version',
            action='version',
            version=f'lil-pwny {project_metadata.get("version")}')
        parser.add_argument(
            '-c', '--custom',
            help='.txt file containing additional custom passwords to check for',
            dest='custom')
        parser.add_argument(
            '-custom-enhance', '--custom-enhance',
            help='generate an enhanced custom password list based on the provided custom password list. Must be used'
                 ' with -c/--custom flag. The enhanced list will stored in memory and not written to disk.'
                 ' Provide the minimum length of the passwords you want. Default is 8',
            dest='custom_enhance')
        parser.add_argument(
            '-ad', '--ad-hashes',
            help='The .txt file containing NTLM hashes from AD users',
            dest='ad_hashes',
            required=True)
        parser.add_argument(
            '-d', '--duplicates',
            action='store_true',
            dest='d',
            help='Output a list of duplicate password users')
        parser.add_argument(
            '-output', '--output',
            choices=['file', 'stdout', 'json'],
            dest='logging_type',
            default='stdout',
            help='Where to send results')
        parser.add_argument(
            '-o', '--obfuscate',
            action='store_true',
            dest='obfuscate',
            default=False,
            help='Obfuscate hashes from discovered matches by hashing with a random salt')
        parser.add_argument(
            '--debug',
            dest='debug',
            action='store_true',
            help='Turn on debug level logging')

        args = parser.parse_args()
        hibp_file = args.hibp
        custom_passwords = args.custom
        ad_hash_file = args.ad_hashes
        duplicates = args.d
        logging_type = args.logging_type
        obfuscate = args.obfuscate
        debug = args.debug
        custom_enhance = args.custom_enhance

        hasher = hashing.Hashing()

        if logging_type == 'file':
            logging_type = 'stdout'
            logger = init_logger(logging_type, debug)
            logger.log('WARNING', 'File output is no longer supported.'
                                  ' Select JSON output and redirect this to file. Defaulting to stdout')
        else:
            logger = init_logger(logging_type, debug)

        logger.log('SUCCESS', 'Lil Pwny started execution')
        logger.log('INFO', f'Version: {project_metadata.get("version")}')
        logger.log('INFO', f'Created by: {project_metadata.get("author")}')
        logger.log('INFO', 'Loading AD user hashes...')

        # Load AD user hashes
        try:
            ad_users = password_audit.import_users(ad_hash_file)
            ad_lines = sum(len(ls) for ls in ad_users.values())
        except FileNotFoundError as e:
            logger.log('CRITICAL', f'AD user file not found: {e.filename}')
            sys.exit(1)
        except Exception as e:
            logger.log('CRITICAL', f'Error loading AD user hashes: {str(e)}')
            sys.exit(1)

        # Check HIBP file size
        try:
            logger.log('SUCCESS', f'Size of HIBP file provided {get_readable_file_size(hibp_file)}')
        except FileNotFoundError as e:
            logger.log('CRITICAL', f'HIBP file not found: {e.filename}')
            sys.exit(1)

        # Compare AD users against HIBP hashes
        logger.log('SUCCESS', f'Comparing {ad_lines} AD users against HIBP compromised passwords...')
        try:
            hibp_results = password_audit.search(
                log_handler=logger,
                hibp_hashes_filepath=hibp_file,
                ad_user_hashes=ad_users,
                finding_type='hibp',
                obfuscated=obfuscate)
            hibp_count = len(hibp_results)
            if logging_type != 'stdout':
                for hibp_match in hibp_results:
                    logger.log('NOTIFY', hibp_match, notify_type='hibp')
        except FileNotFoundError as e:
            logger.log('CRITICAL', f'HIBP file not found: {e.filename}')
            sys.exit(1)
        except Exception as e:
            logger.log('CRITICAL', f'Error during HIBP search: {str(e)}')
            sys.exit(1)

        # Handle custom passwords if provided
        custom_count = 0
        if custom_passwords:
            try:
                logger.log('INFO', 'Loading custom password list...')
                with open(custom_passwords, 'r') as f:
                    custom_passwords = [line.strip() for line in f]
                    logger.log('SUCCESS', f'Loaded {len(custom_passwords)} custom passwords')

                if custom_enhance:
                    logger.log('INFO', 'Enhancing custom password list by adding variations...')
                    custom_client = CustomListEnhancer(min_password_length=int(custom_enhance))
                    custom_passwords = custom_client.enhance_list(custom_passwords)
                    logger.log('SUCCESS', f'Enhanced custom password list to {len(custom_passwords)} '
                                          f'plaintext passwords')

                logger.log('INFO', 'Converting custom passwords to NTLM hashes...')
                custom_password_hashes = hasher.get_hashes(custom_passwords)
                logger.log('SUCCESS', f'Generated {len(custom_password_hashes)} custom password hashes')

                with tempfile.NamedTemporaryFile('w', delete=False) as temp_file:
                    for h in custom_password_hashes:
                        temp_file.write(f'{h}\n')
                    temp_file_path = temp_file.name

                logger.log('INFO', f'Comparing {ad_lines} Active Directory'
                                   f' users against {len(custom_password_hashes)} custom password hashes...')
                custom_matches = password_audit.search(
                    log_handler=logger,
                    hibp_hashes_filepath=temp_file_path,
                    ad_user_hashes=ad_users,
                    finding_type='custom',
                    obfuscated=obfuscate)
                custom_count = len(custom_matches)
                if logging_type != 'stdout':
                    for result in custom_matches:
                        logger.log('NOTIFY', result, notify_type='custom')
            except FileNotFoundError as e:
                logger.log('CRITICAL', f'Custom password file not found: {e.filename}')
                sys.exit(1)
            except Exception as e:
                logger.log('CRITICAL', f'Error during custom password search: {str(e)}')
                sys.exit(1)
            finally:
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)

        # Handle duplicates if requested
        duplicate_count = 0
        if duplicates:
            try:
                logger.log('INFO', 'Finding users with duplicate passwords...')
                duplicate_results = password_audit.find_duplicates(ad_users, obfuscate)
                duplicate_count = len(duplicate_results)
                for duplicate_match in duplicate_results:
                    logger.log('NOTIFY', duplicate_match, notify_type='duplicate')
            except Exception as e:
                logger.log('CRITICAL', f'Error finding duplicates: {str(e)}')
                sys.exit(1)

        time_taken = time.time() - start
        total_comp_count = custom_count + hibp_count

        logger.log('SUCCESS', 'Audit completed')
        logger.log('SUCCESS', f'Total compromised passwords: {total_comp_count}')
        logger.log('SUCCESS', f'Passwords matching HIBP: {hibp_count}')
        logger.log('SUCCESS', f'Passwords matching custom password dictionary: {custom_count}')
        logger.log('SUCCESS', f'Passwords duplicated (being used by multiple user accounts): {duplicate_count}')
        logger.log('SUCCESS', f'Time taken: {str(timedelta(seconds=time_taken))}')

    except Exception as e:
        logger.log('CRITICAL', str(e))
        logger.log('DEBUG', traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
