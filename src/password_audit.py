import multiprocessing as mp
import itertools


def import_ad_hashes(ad_hash_path):
    """Read contents of the AD input file and return them line
    by line in a list"""

    users = {}
    with open(ad_hash_path) as u_infile:
        for line in nonblank_lines(u_infile):
            line.strip()
            temp = line.split(':')
            uname = temp[0].upper()
            phash = temp[1].strip().upper()
            users[uname] = phash
    return users


def import_hibp_hashes(hibp_hash_path):
    """Read contents of the HIBP input file and return them line
    by line in a list"""

    hibp = []
    with open(hibp_hash_path) as h_infile:
        for line in nonblank_lines(h_infile):
            temp = line.split(':')
            hibp.append(temp[0])

    output = " ".join(hibp)

    return output


def find_duplicates(ad_hash_dict, output_file_path):
    """Returns users using the same hash in the input file. Outputs
    a file grouping all users of a hash being used more than once"""

    flipped = {}

    for key, value in ad_hash_dict.items():
        if value not in flipped:
            flipped[value] = [key]
        else:
            flipped[value].append(key)

    with open(output_file_path, 'w+') as f:
        for key, value in flipped.items():
            if len(list(value)) > 1:
                temp = '{} : {}'.format(str(key), str(value))
                f.write(temp + '\n')


def worker(ad_users, hibp, result):
    """Worker for multiproccessing, compares one list against another
    and adds matches to a list"""

    for k, v in ad_users.items():
        if v in hibp:
            result.append(k + ':' + v)

    return result


def nonblank_lines(f):
    """Filter out blank lines from the input file"""

    for l in f:
        line = l.rstrip()
        if line:
            yield line


def multi_pro_search(userlist, hash_dictionary, out_path):
    """Uses multiprocessing to split the userlist into (number of cores -1) amount
    of dictionaries of equal size, and search these against the HIBP list.
    Joins these together and outputs a list of matching users"""

    result = mp.Manager().list()

    chunks = mp.cpu_count() - 1
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

    write_output(out_path, result)

    return result


def write_output(out_path, out_list):
    """Writes the inputted list to a .txt file in the given path"""

    with open(out_path, 'w+') as f:
        for item in out_list:
            username = item.split(':', 1)[0]
            f.write(username + '\n')