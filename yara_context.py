import os
import sys
import yara
import argparse

# based on script from @jprosco
'''
def create_rules(dbfile):
    """
    Creates a yara rules file from a regex database
    """
    dbrules = dbfile.readlines()

    yara_rule = 'rule m_webshells : webshell\n{\n\tstrings:\n'

    for i, line in enumerate(dbrules):
        # dbfile does not escape forward slashes but yara regex must be surrounded by forward slashes
        line = line.replace('/', '\/').rstrip()
        line = line.replace('\\\\/', '\/')
        yara_rule = ''.join((yara_rule, '\t\t$s{0} = /{1}/ nocase\n'.format(str(i), line)))

    yara_rule = ''.join((yara_rule, '\n\tcondition:\n\t\tany of them\n}\n'))

    return yara_rule
'''

def doWork(rules, filepath, output):
    row = {}
    row['File'] = ''
    row['Rule'] = ''
    row['Match'] = ''
    row['Offset'] = ''
    row['Context'] = ''
    MatchNumber = 0
    compiled_rules = yara.compile(rules)

    print "[+] Scanning..: {0}".format(filepath)
    print "[-] File size : {0} (bytes)".format(os.path.getsize(filepath))
    with open(output, 'a') as outty:    
        try:
            #matches = compiled_rules.match(filepath)
            try:
                matches = compiled_rules.match(filepath, fast=True, timeout=60) #timeout is in seconds
                if len(matches) > 0:
                    row['File'] = filepath
                    for rule in matches:
                        rule_text = '\tRULE:\t\t{0}'.format(rule)  
                        print rule_text
                        row['Rule'] = rule
                        # Helps to associates matches in rule on a file since there can be many and 
                        # they are getting put onto separate lines
                        MatchNumber += 1

                        for s in rule.strings:
                            match_text = '\t\tMATCH:\t\t{0}'.format(s[2].lstrip())
                            print match_text
                            row['Match'] = s[2].lstrip()

                            offset_text = '\t\tOFFSET:\t\t{0}'.format(s[0])
                            print offset_text
                            row['Offset'] = str(s[0])

                            with open(filepath, 'r') as matchfile:
                                exact_offset = s[0]
                                # print before match at offset to try and get more context                        
                                #larger_context = s[0] - 100
                                matchfile.seek(exact_offset)
                                context = matchfile.readline().strip()
                                context_text = '\t\tCONTEXT:\t{0}\n'.format(context)
                                print context_text                             
                                row['Context'] = context

                            result = (row['File'] +'\t'+ str(row['Rule']) +'\t'+ str(MatchNumber) +'\t'+ row['Match'] +'\t'+ row['Offset'] +'\t'+ row['Context'] + '\n')
                            outty.write(result)               
            except yara.TimeoutError:
                print "[!] ERROR (timeout): {0}".format(filepath)
                error_text = "ERROR (timeout) {0}\n".format(filepath)
                outty.write(error_text)
                pass
        # exception is thrown by yara on an attempt to read a 0-byte file
        except yara.Error as err:
            print "[!] ERROR:",err
            error_text = "ERROR: {0}".format(filepath)
            outty.write(error_text)
            pass

def main():
    parser = argparse.ArgumentParser()    
    parser.add_argument("-i", "--input", required=True, help="Input file or directory of files to recursively search")
    parser.add_argument("-o", "--output", required=True, help="Output file to save results to")
    parser.add_argument("-r", "--rules", required=True, help="YARA rules file")
    #parser.add_argument("-t", "--terms", required=False, help="File containing terms to create yara rules out of")    

    args = parser.parse_args()

    inny = args.input
    if not os.path.exists(inny):
        print "[!] Input file does not exist"
        sys.exit()
    rules = args.rules
    output = args.output    
    #if args.terms:
    #    terms = args.terms
    #    create_rules(args.db)

    with open(output, 'a') as outty:
        headers = 'File' +'\t'+ 'Rule' +'\t' + 'MatchNumber' +'\t'+ 'Match' +'\t'+ 'Offset' +'\t'+ 'Context' +'\n'
        outty.write(headers)    

    print "[+] YARA Rules: {0}".format(rules)
    if os.path.isdir(inny):
        for root, dirs, files in os.walk(inny):
            for filename in files:
                filepath = os.path.join(root, filename)
                doWork(rules, filepath, output)           
    else:
        doWork(rules, inny, output)                         


if __name__ == '__main__':
    main()
