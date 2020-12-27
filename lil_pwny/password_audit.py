import multiprocessing as mp
import itertools

from lil_pwny import logger


def import_hashes(hash_path):
    """Read contents of the AD input file and return them line
    by line in a dict"""

    output_dict = {}
    with open(hash_path) as infile:
        for line in nonblank_lines(infile):
            line.rstrip()
            temp = line.split(':')
            output_dict[temp[0].upper()] = temp[1].strip().upper()
    return output_dict


def find_duplicates(ad_hash_dict):
    """Returns users using the same hash in the input file. Outputs
    a file grouping all users of a hash being used more than once"""

    flipped = {}
    outlist = []

    for key, value in ad_hash_dict.items():
        if value not in flipped:
            flipped[value] = [key]
        else:
            flipped[value].append(key)

    for key, value in flipped.items():
        if len(list(value)) > 1:
            user_list = []
            for v in value:
                user_list.append({
                    'username': v,
                })
            output = {
                'hash': str(key),
                'users': user_list
            }
            outlist.append(output)

    return outlist


def worker(ad_users, hibp, result):
    """Worker for multiproccessing, compares one list against another
    and adds matches to a list"""

    for k, v in ad_users.items():
        if hibp.get(v):
            result.append({
                'username': k,
                'hash': v,
                'matches_in_hibp': hibp.get(v)
            })

    return result


def nonblank_lines(f):
    """Filter out blank lines from the input file"""

    for l in f:
        line = l.rstrip()
        if line:
            yield line


def multi_pro_search(log_handler, userlist, hash_dictionary):
    """Uses multiprocessing to split the userlist into (number of cores -1) amount
    of dictionaries of equal size, and search these against the HIBP list.
    Joins these together and outputs a list of matching users"""

    result = mp.Manager().list()

    chunks = mp.cpu_count() - 1

    if isinstance(log_handler, logger.StdoutLogger):
        log_handler.log_info('{} cores being utilised'.format(chunks))
    else:
        print('{} cores being utilised'.format(chunks))

    # Make sure each chunk is equal, remainder is added to last chunk
    chunk_size = round(len(userlist) / chunks)
    items = iter(userlist.items())

    # Creates a list of equal sized dictionaries
    list_of_chunks = [dict(itertools.islice(items, chunk_size)) for _ in range(chunks - 1)]
    list_of_chunks.append(dict(items))

    processes = []

    for dic in list_of_chunks:
        p = mp.Process(target=worker, args=(dic, hash_dictionary, result))
        processes.append(p)
        p.start()

    for process in processes:
        process.join()

    return result._getvalue()
