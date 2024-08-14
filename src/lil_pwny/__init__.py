import argparse
import os
import sys
import tempfile
import time
import traceback
from datetime import timedelta
from importlib import metadata
from typing import List, Dict

from lil_pwny import password_audit, hashing
from lil_pwny.variant_generators.custom_variant_generator import CustomVariantGenerator
from lil_pwny.variant_generators.username_variant_generator import UsernameVariantGenerator
from lil_pwny.exceptions import FileReadError
from lil_pwny.loggers import JSONLogger, StdoutLogger

output_logger = JSONLogger


def init_logger(logging_type: str, verbose: bool) -> JSONLogger or StdoutLogger:
    """ Create a logger object. Defaults to stdout if no option is given

    Args:
        logging_type: Type of logging to use
        verbose: Whether to use verbose logging or not
    Returns:
        JSONLogger or StdoutLogger
    """

    if not logging_type or logging_type == 'stdout':
        return StdoutLogger(debug=verbose)
    return JSONLogger(debug=verbose)


def get_readable_file_size(file_path: str) -> str:
    """ Get the size of a file in a human readable format

    Args:
        file_path: Path to the file to get the size of
    Returns:
        Human readable file size in bytes, KB, MB or GB
    """

    file_size_bytes = os.path.getsize(file_path)
    for unit in ['bytes', 'KB', 'MB', 'GB']:
        if file_size_bytes < 1024:
            return f'{file_size_bytes:.2f} {unit}'
        file_size_bytes /= 1024


def write_hash_temp_file(hash_list: List[str]) -> str:
    """ Writes a list of hashes to a temporary file and returns the file path.

        Args:
            hash_list: A list of hash strings to be written to the temporary file.
        Returns:
            str: The file path of the temporary file containing the hashes.
    """

    with tempfile.NamedTemporaryFile('w', delete=False) as temp_file:
        temp_file.write('\n'.join(hash_list))
    return temp_file.name


def find_matches(log_handler: JSONLogger or StdoutLogger,
                 filepath: str,
                 ad_user_hashes: Dict[str, List[str]],
                 finding_type: str,
                 obfuscated: bool,
                 logging_type: str) -> int:
    """ Searches for matches between Active Directory user hashes and a provided hash file, logs the results,
        and returns the number of matches found.

        Args:
            log_handler: The logger instance used to log messages.
            filepath: The path to the file containing the hash data to compare against.
            ad_user_hashes: A dictionary of NTLM hashes from Active Directory users.
            finding_type: The type of match being searched for (e.g., 'hibp', 'custom', 'username').
            obfuscated: Whether to obfuscate the matches found by hashing with a random salt.
            logging_type: The type of logging output to use ('stdout', 'json', etc.).
        Returns:
            The number of matches found.
    """

    matches = password_audit.search(
        log_handler=log_handler,
        hibp_hashes_filepath=filepath,
        ad_user_hashes=ad_user_hashes,
        finding_type=finding_type,
        obfuscated=obfuscated)
    number_of_matches = len(matches)
    if logging_type != 'stdout':
        for match in matches:
            log_handler.log('NOTIFY', match, notify_type=finding_type)

    return number_of_matches


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
            '--verbose',
            dest='verbose',
            action='store_true',
            help='Turn on verbose logging')

        args = parser.parse_args()
        hibp_file = args.hibp
        custom_passwords = args.custom
        ad_hash_file = args.ad_hashes
        duplicates = args.d
        logging_type = args.logging_type
        obfuscate = args.obfuscate
        verbose = args.verbose
        custom_enhance = args.custom_enhance

        hasher = hashing.Hashing()

        if logging_type == 'file':
            logging_type = 'stdout'
            logger = init_logger(logging_type, verbose)
            logger.log('WARNING', 'File output is no longer supported.'
                                  ' Select JSON output and redirect this to file. Defaulting to stdout')
        else:
            logger = init_logger(logging_type, verbose)

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

        # Check username variations
        logger.log('SUCCESS', f'Finding users using passwords that are a variation of their username...')
        username_variants = UsernameVariantGenerator().generate_variations(ad_users)
        logger.log('DEBUG', f'{len(username_variants)} username variants generated ')
        username_hashes = hasher.get_hashes(username_variants)
        logger.log('DEBUG', f'Converting username variants to NTLM hashes ')
        username_temp_filepath = write_hash_temp_file(username_hashes)

        username_count = find_matches(
            log_handler=logger,
            filepath=username_temp_filepath,
            ad_user_hashes=ad_users,
            finding_type='username',
            obfuscated=obfuscate,
            logging_type=logging_type)

        # Check HIBP file size
        try:
            logger.log('SUCCESS', f'Size of HIBP file provided {get_readable_file_size(hibp_file)}')
        except FileNotFoundError as e:
            logger.log('CRITICAL', f'HIBP file not found: {e.filename}')
            sys.exit(1)

        # Compare AD users against HIBP hashes
        logger.log('SUCCESS', f'Comparing {ad_lines} AD users against HIBP compromised passwords...')
        try:
            hibp_count = find_matches(
                log_handler=logger,
                filepath=hibp_file,
                ad_user_hashes=ad_users,
                finding_type='hibp',
                obfuscated=obfuscate,
                logging_type=logging_type)
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
                    custom_passwords = [line.strip() for line in f if line.strip()]
                    logger.log('SUCCESS', f'Loaded {len(custom_passwords)} custom passwords')

                if custom_enhance:
                    custom_count = 0
                    variants_count = 0
                    logger.log('INFO', 'Enhancing custom password list by adding variations...')
                    custom_client = CustomVariantGenerator(min_password_length=int(custom_enhance))
                    for custom_pwd in custom_passwords:
                        logger.log('DEBUG', f'Generating variants for `{custom_pwd}`...')
                        temp_custom_passwords = custom_client.enhance_password(custom_pwd)

                        logger.log('DEBUG', 'Converting custom passwords to NTLM hashes...')
                        custom_password_hashes = hasher.get_hashes(temp_custom_passwords)
                        variants_count += len(custom_password_hashes)
                        logger.log('SUCCESS', f'Generated {len(custom_password_hashes)} variants for `{custom_pwd}`')

                        custom_temp_file_path = write_hash_temp_file(custom_password_hashes)
                        logger.log('DEBUG', f'Custom hashes written to temp file {custom_temp_file_path}')
                        logger.log('INFO', f'Comparing {ad_lines} Active Directory'
                                           f' users against {len(custom_password_hashes)} custom password hashes...')

                        custom_count += find_matches(
                            log_handler=logger,
                            filepath=custom_temp_file_path,
                            ad_user_hashes=ad_users,
                            finding_type='custom',
                            obfuscated=obfuscate,
                            logging_type=logging_type)
                        os.remove(custom_temp_file_path)
                        logger.log('DEBUG', f'Temp file {custom_temp_file_path} deleted')
                else:
                    logger.log('DEBUG', 'Converting custom passwords to NTLM hashes...')
                    custom_password_hashes = hasher.get_hashes(custom_passwords)
                    custom_temp_file_path = write_hash_temp_file(custom_password_hashes)
                    logger.log('DEBUG', f'Custom hashes written to temp file {custom_temp_file_path}')

                    logger.log('INFO', f'Comparing {ad_lines} Active Directory'
                                       f' users against {len(custom_password_hashes)} custom password hashes...')
                    custom_count += find_matches(
                        log_handler=logger,
                        filepath=custom_temp_file_path,
                        ad_user_hashes=ad_users,
                        finding_type='custom',
                        obfuscated=obfuscate,
                        logging_type=logging_type)
                    os.remove(custom_temp_file_path)
                    logger.log('DEBUG', f'Temp file {custom_temp_file_path} deleted')
            except FileNotFoundError as e:
                logger.log('CRITICAL', f'Custom password file not found: {e.filename}')
                sys.exit(1)
            except Exception as e:
                logger.log('CRITICAL', f'Error during custom password search: {str(e)}')
                sys.exit(1)

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
        logger.log('SUCCESS', f'Passwords matching a variation of the username: {username_count}')
        logger.log('SUCCESS', f'Passwords matching HIBP: {hibp_count}')
        logger.log('SUCCESS', f'Passwords matching custom password dictionary: {custom_count}')
        if custom_enhance:
            logger.log('SUCCESS', f'Variant passwords generated from {len(custom_passwords)} custom passwords:'
                                  f' {variants_count}')
        logger.log('SUCCESS', f'Passwords duplicated (being used by multiple user accounts): {duplicate_count}')
        logger.log('SUCCESS', f'Time taken: {str(timedelta(seconds=time_taken))}')

    except Exception as e:
        logger.log('CRITICAL', str(e))
        logger.log('DEBUG', traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
