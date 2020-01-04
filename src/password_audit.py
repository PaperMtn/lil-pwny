import multiprocessing as mp
import itertools
import time
from datetime import datetime, timedelta
import argparse


# import src.hash_generator


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
            hibp.append(line.strip())

    return hibp


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
                temp = '{0} : {1}'.format(str(key), str(value))
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
    print('{0} cores being utilised'.format(chunks))

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


def main():
    # start timer
    start = time.time()

    parser = argparse.ArgumentParser()
    parser.add_argument('-hibp', '--hibp', help='The HIBP .txt file of NTLM hashes', dest='hibp', required=True)
    parser.add_argument('-a', '--a', help='.txt file containing additional passwords to check for', dest='a')
    parser.add_argument('-ad-hashes', '-ad', '--ad', help='The NTLM hashes from of AD users', dest='ad_hashes',
                        required=True)
    parser.add_argument('-duplicates', '-d', '--d', action='store_true',
                        help='Output a list of duplicate password users')
    parser.add_argument('-memory', '-m', '--m', action='store_true', dest='m',
                        help='Load HIBP hash list into memory (over 20GB RAM required)')

    args = parser.parse_args()
    hibp_file = args.hibp
    additional_password_file = args.a
    ad_hash_file = args.ad_hashes
    duplicates = args.d
    memory = args.m

    additional_count = 0
    dup_count = 0

    print("""
    +-+-+-+-+-+-+ +-+-+-+-+
    |L|i|t|t|l|e| |P|w|n|y|
    +-+-+-+-+-+-+ +-+-+-+-+
    """)

    if memory:
        print('Loading HIBP hash dictionary into memory...')
        # Read the HIBP list into memory for faster searching
        f = open(hibp_file)
        content = f.read()
        hibp_lines = content.count('\n')
    else:
        print('Loading HIBP hash dictionary...')
        content = import_hibp_hashes(hibp_file)
        hibp_lines = len(content)

    print('Loading AD user hashes...')
    ad_users = import_ad_hashes(ad_hash_file)
    ad_lines = len(ad_users)

    if additional_password_file:
        print('Loading additional hashes dictionary...')

        # Read the hash list into memory for faster searching
        f_additional = open(additional_password_file)
        additional_content = f_additional.read()
        additional_lines = additional_content.count('\n')

        print('Comparing {0} AD users against {1} additional password hashes...'.format(ad_lines, additional_lines))
        multi_pro_search(ad_users, additional_content, './additional_matches.txt')
        additional_count = len(open('./additional_matches.txt').readlines())

    print('Comparing {0} AD users against {1} known compromised passwords...'.format(ad_lines, hibp_lines))
    multi_pro_search(ad_users, content, './HIBP_matches.txt')
    hibp_count = len(open('./HIBP_matches.txt').readlines())

    if duplicates:
        print('Finding users with duplicate passwords...')
        find_duplicates(ad_users, './duplicate_passwords.txt')

        # dup_count = len(dup_bq_list)

    # Time taken for the audit to run
    end = time.time()
    time_taken = end - start

    total_comp_count = additional_count + hibp_count + dup_count

    print('Audit completed \n'
          'Total compromised passwords: {}\n'
          'Passwords matching HIBP: {}\n'
          'Passwords matching additional dictionary: {}\n'
          'Time taken: {}'.format(total_comp_count, hibp_count, additional_count, str(timedelta(seconds=time_taken))))


if __name__ == '__main__':
    main()
