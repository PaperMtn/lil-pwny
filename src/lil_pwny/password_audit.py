import gc
import os
import multiprocessing as mp
from typing import List, Dict, TextIO
from pathlib import Path

from charset_normalizer import from_bytes

from lil_pwny.hashing import Hashing
from lil_pwny.loggers import JSONLogger, StdoutLogger
from lil_pwny.exceptions import MalformedHIBPError


def _sanitize_filepath(filepath: str) -> str:
    """ Check if the file path is valid

    Args:
        filepath: Input file path
    Returns:
        Resolved path as a string
    """

    path = Path(filepath).resolve()
    if not path.is_file():
        raise ValueError(f'Invalid file path: {filepath}')
    return str(path)


def import_users(filepath: str) -> Dict[str, List[str]]:
    """ Import Active Directory users from text file into a dict

    Args:
        filepath: Path for the AD user file
    Returns:
        Dict with the key as the NTLM hash, value is a list containing users matching that hash
    """

    users = {}
    filepath = _sanitize_filepath(filepath)

    with open(filepath, 'rb') as infile:
        raw_data = infile.read()
        encoding = from_bytes(raw_data).best().encoding

    with open(filepath, encoding=encoding) as infile:
        for u in _nonblank_lines(infile):
            username, pwd_hash = u.strip().split(':')[0].upper(), u.strip().split(':')[1].upper()
            if not username.endswith('$'):
                users.setdefault(pwd_hash, []).append(username)

    return users


def find_duplicates(ad_hash_dict: Dict, obfuscated: bool) -> List[dict]:
    """Returns users using the same hash in the input file. Outputs
    a file grouping all users of a hash being used more than once

    Args:
        ad_hash_dict: imported AD users as a dict
        obfuscated: flag to determine whether the hash should
    Returns:
        List of dicts containing results for users using the same password
    """

    results_list = []
    hash_client = Hashing()
    for u in ad_hash_dict:
        if u and len(ad_hash_dict.get(u)) > 1:
            duplicate_users = ad_hash_dict.get(u)
            if obfuscated:
                u = hash_client.obfuscate(u)
            output = {
                'hash': u,
                'users': duplicate_users,
                'obfuscated': obfuscated
            }
            results_list.append(output)

    return results_list


def search(log_handler: JSONLogger or StdoutLogger,
           hibp_hashes_filepath: str,
           ad_user_hashes: Dict[str, List[str]],
           finding_type: str,
           obfuscated: bool) -> List[dict]:
    """ Search for AD users in the HIBP file

    Args:
        log_handler: logger instance for outputting
        hibp_hashes_filepath: path to the HIBP file
        ad_user_hashes: imported AD user NTLM hashes. Output from import_users
        finding_type: type of finding
        obfuscated: flag to determine whether the hash should be obfuscated
    Returns:
        List of users matching the given password dictionary file (HIBP or custom)
    """

    result = mp.Manager().list()
    hash_client = Hashing()

    if isinstance(log_handler, StdoutLogger):
        worker_args = [
            ad_user_hashes,
            result,
            finding_type,
            log_handler,
            obfuscated,
            hash_client
        ]
    else:
        worker_args = [
            ad_user_hashes,
            result,
            finding_type,
            None,
            obfuscated,
            hash_client
        ]

    _multi_pro_search(
        log_handler=log_handler,
        hibp_filepath=hibp_hashes_filepath,
        block_size=100,
        cores=mp.cpu_count(),
        worker_function=_worker,
        worker_function_args=worker_args)

    return result._getvalue()


def _nonblank_lines(f: TextIO) -> str:
    """Generator to filter out blank lines from the input list

    Args:
        f: input file
    Returns:
        Yields line if it isn't blank
    """

    for line in f:
        if line.rstrip():
            yield line


def _divide_blocks(filepath: str,
                   size: int = 1024 * 1024 * 1000,
                   skip_lines: int = -1) -> List[tuple]:
    """ Divide the large text file into equal sized blocks, aligned to the start of a line

    Args:
        filepath: Path for the hash file (HIBP or custom)
        size: size of 1 block in MB
        skip_lines: number of top lines to skip while processing
    Returns:
        List containing the start points for the input file after dividing into blocks
    """

    blocks = []
    filepath = _sanitize_filepath(filepath)

    file_end = os.path.getsize(filepath)
    with open(filepath, 'rb') as f:
        if skip_lines > 0:
            for i in range(skip_lines):
                f.readline()

        block_end = f.tell()
        count = 0
        while True:
            block_start = block_end
            f.seek(f.tell() + size, os.SEEK_SET)
            f.readline()
            block_end = f.tell()
            blocks.append((block_start, block_end - block_start, filepath))
            count += 1

            if block_end > file_end:
                break

    return blocks


def _parallel_process_block(block_data: str) -> List[dict]:
    """ Carry out worker function on each line in a block

    Args:
        block_data: information on the block to process, start - end etc.
    Returns:
        List containing results of the worker on the block
    """

    block_start, block_size, filepath, function, encoding = block_data[:5]
    func_args = block_data[5:]
    block_results = []

    # Open the file again with the detected encoding and process the block
    with open(filepath, 'rb') as f:
        f.seek(block_start)
        cont = f.read(block_size).decode(encoding=encoding)
        lines = cont.splitlines()

        for i, line in enumerate(lines):
            output = function(line, *func_args)
            if output is not None:
                block_results.append(output)

    return block_results


def _multi_pro_search(log_handler: JSONLogger or StdoutLogger,
                      hibp_filepath: str,
                      block_size: int,
                      cores: int,
                      worker_function: callable,
                      worker_function_args: List,
                      skip_lines: int = 0) -> List[dict]:
    """Breaks the [HIBP|custom passwords] file into blocks and uses multiprocessing to iterate through them and return
     any matches against AD users.

    Args:
        log_handler: logger instance for outputting
        block_size: size of 1 block in MB
        cores: number of processes
        skip_lines: number of top lines to skip while processing
        worker_function: worker function that will carry out processing
        worker_function_args: arguments for the worker function
    Returns:
        List of users matching the given password dictionary file (HIBP or custom)
    """

    hibp_filepath = _sanitize_filepath(hibp_filepath)

    # Detect the file encoding
    with open(hibp_filepath, 'rb') as f:
        raw_data = f.read(10000)  # Read the first 10KB for encoding detection
        encoding = from_bytes(raw_data).best().encoding

    jobs = _divide_blocks(hibp_filepath, 1024 * 1024 * block_size, skip_lines)
    jobs = [list(j) + [worker_function, encoding] + worker_function_args for j in jobs]

    log_handler.log('INFO', f'Split into {len(jobs)} parallel jobs ')
    log_handler.log('INFO', f'{cores} cores being utilised')

    pool = mp.Pool(cores - 1, maxtasksperchild=1000)

    outputs = []
    for block_number in range(0, len(jobs), cores - 1):
        block_results = pool.map(_parallel_process_block, jobs[block_number: block_number + cores - 1])

        for i, sub_list in enumerate(block_results):
            for x in sub_list:
                outputs.append(x)
        del block_results
        gc.collect()

    pool.close()
    pool.terminate()


def _worker(line: str,
            user_list: Dict,
            result: List[dict],
            notify_type: str,
            logger: StdoutLogger or JSONLogger = None,
            obfuscated: bool = False,
            hash_client: Hashing = None) -> List[dict]:
    """ Worker function that carries out the processing on a line from the HIBP/custom passwords file. Checks to see
    whether the hash on that line is in the imported AD users. If a match, a dict containing match data is appended
    to the list shared between processes via multiprocessing

    Args:
        line: line from a block of the hash file
        user_list: dict containing imported AD user hashes
        result: multiprocessing list shared between all processes to collect results
        logger: logger instance for outputting
        notify_type: type of finding
        obfuscated: flag to determine whether the hash should be obfuscated
    Returns:
        List containing dict data of the matching user
    """

    try:
        ntlm_hash, count = line.rstrip().split(':')[0].upper(), line.rstrip().split(':')[1].strip().upper()
    except Exception as e:
        if logger:
            logger.log('ERROR', f'Failed to parse line: {line}. Error: {str(e)}')
        raise MalformedHIBPError(line)

    if user_list.get(ntlm_hash):
        return_hash = ntlm_hash
        if obfuscated:
            return_hash = hash_client.obfuscate(ntlm_hash)
        for u in user_list.get(ntlm_hash):
            finding = {
                'username': u,
                'hash': return_hash,
                'matches_in_hibp': count,
                'obfuscated': obfuscated
            }
            if isinstance(logger, StdoutLogger):
                logger.log('NOTIFY', finding, notify_type=notify_type)
            result.append(finding)

    return result
