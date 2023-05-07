import gc
import os
import multiprocessing as mp

from lil_pwny import logger


def import_users(filepath):
    """Import Active Directory users from text file into a dict

    Parameters:
        filepath: Path for the AD user file
    Returns:
        Dict with the key as the NTLM hash, value is a list containing users matching that hash
    """

    users = {}
    with open(filepath) as infile:
        for u in _nonblank_lines(infile):
            username, hash = u.strip().split(':')[0].upper(), u.strip().split(':')[1].upper()
            if not username.endswith('$'):
                users.setdefault(hash, []).append(username)

    return users


def find_duplicates(ad_hash_dict):
    """Returns users using the same hash in the input file. Outputs
    a file grouping all users of a hash being used more than once

    Parameters:
        ad_hash_dict: imported AD users as a dict
    Returns:
        List of dicts containing results for users using the same password
    """

    outlist = [{'hash': u, 'users': ad_hash_dict.get(u)} for u in ad_hash_dict if u and len(ad_hash_dict.get(u)) > 1]

    return outlist


def search(log_handler, hibp_path, ad_user_path):
    users = import_users(ad_user_path)
    result = mp.Manager().list()

    _multi_pro_search(log_handler, hibp_path, 100, mp.cpu_count(), _worker, [users, result])

    return result._getvalue()


def _nonblank_lines(f):
    """Generator to filter out blank lines from the input list

    Parameters:
        f: input file
    Returns:
        Yields line if it isn't blank
    """

    for line in f:
        if line.rstrip():
            yield line


def _divide_blocks(filepath, size=1024 * 1024 * 1000, skip_lines=-1):
    """Divide the large text file into equal sized blocks, aligned to the start of a line

    Parameters:
        filepath: Path for the hash file (HIBP or custom)
        size: size of 1 block in MB
        skip_lines: number of top lines to skip while processing
    Returns:
        List containing the start points for the input file after dividing into blocks
    """

    blocks = []
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


def _parallel_process_block(block_data):
    """Carry out worker function on each line in a block

    Parameters:
        block_data: information on the block to process, start - end etc.
    Returns:
        List containing results of the worker on the block
    """

    block_start, block_size, filepath, function = block_data[:4]
    func_args = block_data[4:]
    block_results = []
    with open(filepath, 'rb') as f:
        f.seek(block_start)
        cont = f.read(block_size).decode(encoding='utf-8')
        lines = cont.splitlines()

        for i, line in enumerate(lines):
            output = function(line, *func_args)
            if output is not None:
                block_results.append(output)

    return block_results


def _multi_pro_search(log_handler, filepath, block_size, cores, worker_function, worker_function_args, skip_lines=0, outfile=None):
    """Breaks the [HIBP|custom passwords] file into blocks and uses multiprocessing to iterate through them and return
     any matches against AD users.

    Parameters:
        log_handler: logger instance for outputting
        input_file_path: path to input file
        block_size: size of 1 block in MB
        cores: number of processes
        skip_lines: number of top lines to skip while processing
        worker_function: worker function that will carry out processing
        worker_function_args: arguments for the worker function
        outfile: output file (optional)
    Returns:
        List of users matching the given password dictionary file (HIBP or custom)
    """

    jobs = _divide_blocks(filepath, 1024 * 1024 * block_size, skip_lines)
    jobs = [list(j) + [worker_function] + worker_function_args for j in jobs]

    if isinstance(log_handler, logger.StdoutLogger):
        log_handler.log_info('Split into {} parallel jobs '.format(len(jobs)))
        log_handler.log_info('{} cores being utilised'.format(cores))
    else:
        print('Split into {} parallel jobs '.format(len(jobs)))
        print('{} cores being utilised'.format(cores))

    pool = mp.Pool(cores - 1, maxtasksperchild=1000)

    outputs = []
    for block_number in range(0, len(jobs), cores - 1):
        block_results = pool.map(_parallel_process_block, jobs[block_number: block_number + cores - 1])

        for i, subl in enumerate(block_results):
            for x in subl:
                if outfile is not None:
                    print(x, file=outfile)
                else:
                    outputs.append(x)
        del block_results
        gc.collect()

    pool.close()
    pool.terminate()

    return outputs


def _worker(line, userlist, result):
    """Worker function that carries out the processing on a line from the HIBP/custom passwords file. Checks to see
    whether the hash on that line is in the imported AD users. If a match, a dict containing match data is appended
    to the list shared between processes via multiprocessing

    Parameters:
        line: line from a block of the hash file
        userlist: dict containing imported AD user hashes
        result: multiprocessing list shared between all processes to collect results
    Returns:
        List containing dict data of the matching user
    """

    ntlm_hash, count = line.rstrip().split(':')[0].upper(), line.rstrip().split(':')[1].strip().upper()
    if userlist.get(ntlm_hash):
        for u in userlist.get(ntlm_hash):
            result.append({
                'username': u,
                'hash': ntlm_hash,
                'matches_in_hibp': count
            })

    return result
