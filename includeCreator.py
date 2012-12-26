# includeCreator.py was created by Glenn P. Edwards Jr.
#	 	http://hiddenillusion.blogspot.com
# 				@hiddenillusion
# Version 0.0.1
# Date: 12-04-2012

import os
import argparse

def main():
    parser = argparse.ArgumentParser(description='Creates an "include.yara" file which contains various other YARA signature files.')
    parser.add_argument('-F', '--full', help='Include the full path to the other YARA signature files.', action='store_true')	
    parser.add_argument('-o', '--out', help='Path to save the newly created "include.yara" file.', required=True)	
    parser.add_argument('Path', help='Path to directory containing the YARA signature files.')
    args = vars(parser.parse_args())

    combined = 'include.yara'
    dir = args['Path']
    out_dir = args['out']	
    new_file = os.path.join(os.path.abspath(out_dir), combined)	

    print "[+] Creating: %s" % new_file
    with open(new_file, 'w') as outty:	
        c = 0
        for f in os.listdir(dir): # keeping it one level for right now
            if f.endswith('yar') or f.endswith('yara') and f != os.path.basename(new_file):
                print "[%s] Adding: %s" % (c,f)
                if args['full']:
                    f = os.path.abspath(f)			
                outty.write('include "%s"\n' % f)
                c += 1
    #print "[+] (%s) files added..." % len(os.listdir(dir))	
    
if __name__ == "__main__":
        main()
