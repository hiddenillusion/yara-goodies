# includeCreator.py was created by Glenn P. Edwards Jr.
#   https://hiddenillusion.github.io
#        @hiddenillusion
# Version 0.0.2
# Date: 2012-12-04

import os
import sys

def RecursePath(path):
  if not os.path.exists(path):
    path = path.rstrip('"')
    if not os.path.exists(path):
      return

  if os.path.exists(path):
    if os.path.isdir(path):
      for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
          fname = os.path.join(root, name)
          if os.path.isfile(fname):
            yield fname
          else:
            pass

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Creates an "include.yara" file which contains various other YARA signature files.')
    parser.add_argument('-f', '--full', help='Include the full path to the YARA signatue file(s).', action='store_true')
    parser.add_argument('-d', '--dir', help='Include the dirname in the path to the YARA signature file(s)', action='store_true')
    parser.add_argument('-o', '--out', help='Path to save the newly created "include.yara" file.', required=True)
    parser.add_argument('Path', help='Path to the directory containing the YARA signature files.')
    args = vars(parser.parse_args())

    combined = 'include.yara'
    use_full_path = args['full']
    use_dirname = args['dir']

    if use_full_path and use_dirname:
        print("[!] Can only use --full or --dir")
        sys.exit(1)

    new_file = os.path.join(os.path.abspath(args['out']), combined)

    print("[+] Creating: {0}".format(new_file))
    with open(new_file, 'a') as outty:
        cnt = 0
        for filepath in RecursePath(args['Path']):
            #if f.endswith('yar') or f.endswith('yara') and f != os.path.basename(new_file):
            if use_full_path:
                fname = os.path.abspath(filepath)
            elif use_dirname:
                fname = os.path.join(os.path.dirname(filepath), os.path.basename(filepath))
            else:
                fname = os.path.basename(filepath)

            outty.write('include "{0}"\n'.format(fname))
            cnt += 1
    print("[-] ({0}) files added...".format(cnt))
