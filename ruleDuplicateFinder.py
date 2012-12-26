# ruleDuplicateFinder.py was created by Glenn P. Edwards Jr.
#	 	http://hiddenillusion.blogspot.com
# 				@hiddenillusion
# Version 0.0.1
# Date: 12-26-2012

import re
import os
import argparse
import collections

def main():
    parser = argparse.ArgumentParser(description='Looks at all of the rule names within the files provided and reports on doublicate rule names.')
    parser.add_argument('Path', help='Path to directory containing the YARA signature files.')
    args = vars(parser.parse_args())

    fnames = []
    rnames = []
    todos = {}
    d = collections.defaultdict(list)
    for root, dirs, files in os.walk(args['Path']):
        for name in files: 
            f = os.path.join(root, name)
            if f.endswith('yar') or f.endswith('yara'):
                fnames.append(f)
                with open(f, 'r') as reading:	
                    for l in reading:
                        if re.match('^rule .*',l):
                            """
                            Many rules are written with a further classification after their name; however,
                            YARA disregards that so we need to get rid of it as well
                            i.e. - rule My_rule : malware
                            """
                            new_l= l.split(':')[0]
                            clean = new_l.strip()
                            rnames.append(clean)
                            if todos.has_key(clean):
                                d[clean].append(todos[clean])
                                d[clean].append(f)
                            else:
                                todos.update({clean:f})
    fcount = collections.Counter(fnames)
    rcount = collections.Counter(rnames)
    dupcount = collections.Counter(d)
    print "[+] Total rule files found:",len(fcount)
    print "[+] Total rules found.....:",len(rcount)
    print "[+] Looking for duplicates"
    if len(d) < 0:
        print "[-] No dups found"
    else:
        print "[!] Dups found............:",len(dupcount)
        for rule,fname in d.iteritems():
            print "\t[!] ",rule
            for i in fname: 
                print "\t\t[-] ",i

if __name__ == "__main__":
        main()
