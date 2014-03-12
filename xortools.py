#!/usr/bin/python
"""
The original file sources from : http://code.google.com/p/malwarecookbook/source/browse/trunk/12/1/xortools.py

Any modifications, as outlined in comments, were created by:
    Glenn P. Edwards Jr.
http://hiddenillusion.blogspot.com
        @hiddenillusion
Version 0.1
Date: 03-08-2014
"""
import re
import sys
import struct

def single_byte_xor(buf, key):
    out = ''
    for i in buf:
        out += chr(ord(i) ^ key)
    return out

def single_byte_brute_xor(buf, plntxt, start=None, end=None):
    for key in range (0,255):
        out = ''
        for i in buf:
            out += chr(ord(i) ^ key)
        for p in plntxt:
            if out[start:end].find(p) != -1:
                return (p, key, out)
    return (None,None,None)

def get_xor_permutations(buf):
    out = []
    for key in range(1,255):
        out.append(two_byte_xor(buf, key))
    return out

""" This is a modified function to generate multibyte XOR keys in order """
def get_xor_permutations_multi(buf):
    out = {}
    # can skip 0x1 - 0xf if you only want to only focus on two characters (16, 255)
    for k1 in range (1,255):
        for k2 in range (1,255):
            key = (hex(k1)+hex(k2)).replace("0x","")
            out[key] = xor_multi(buf, k1, k2)
    return out

""" Same as above function, just calling a different XOR function at the end so wanted to separate it """
def get_xor_permutations_xrat(buf):
    out = {}
    # can skip 0x1 - 0xf if you only want to only focus on two characters (16, 255)
    for k1 in range (16,255):
        for k2 in range (16,255):
            key = (hex(k1)+hex(k2)).replace("0x","")
            out[key] = xor_xrat(buf, k1, k2)
    return out
            
""" Function for XOR'ing with multibyte XOR key """
def xor_multi(buf, k1, k2):
    blen = len(buf)
    out = ''
    for i in range(0,len(buf)/2):
        c = struct.unpack(">H", buf[(i*2):(i*2)+2])[0]
        newbie = ''
        key = (hex(k1) + hex(k2).replace("0x",""))
        try:
            newbie = c ^ int(key, 16)
            out += hex(newbie).replace("0x","")
        except ValueError:
            print "[!] VE:",key
            pass
        i += 1
    return out

"""
- This one skips 3 bytes in rule matching
- XtremeRAT skips U+000D & U+000A & because of null bytes, essentially becomes 1 byte XOR as first 2 bytes of key XOR & 2nd always gets unicode space so
  XOR with first key on even characters and skip odd characters and replace with 2 byte wild cards in YARA rule (or with those 2 bytes...better for YARA).

Note: depending on where the string to match is within the file, could have to be reversed.
"""
def xor_xrat(buf, k1, k2):
    key1 = hex(k1).replace("0x","")
    key2 = hex(k2).replace("0x","")
    key = (hex(k1) + hex(k2).replace("0x",""))
    out = ''

    for i in range(0,len(buf)):
        c = buf[i:i+1]
        newbie = ''
        try:
            # reverse this if needed (you can usually tell by 
			# commonly repeated character is hex view of XOR'ed file)
            newbie = ord(c) ^ k1
            hx = hex(newbie).replace("0x","")
            '''
            YARA throws errors on nibbles so currently 'blindly' 
			add wildcards so you can add a skip if len != 2 bytes 
            '''
            if len(hx) != 2:
                hx = "?" + hx
            out += ' {0} {1}'.format(hx, key2)
        except ValueError:
            print "[!] VE:",key
            pass
    return out

def two_byte_xor(buf, key):
    out = ''
    for i in range(0,len(buf)/2):
        c = struct.unpack(">H", buf[(i*2):(i*2)+2])[0]
        c ^= key
        out += struct.pack(">H", c)
    return out

def four_byte_xor(buf, key):
    out = ''
    for i in range(0,len(buf)/4):
        c = struct.unpack("=I", buf[(i*4):(i*4)+4])[0]
        c ^= key
        out += struct.pack("=I", c)
    return out

def rolling_xor(buf, key):
    out = ''
    k = 0
    for i in buf:
        if k == len(key):
            k = 0
        out += chr(ord(i) ^ ord(key[k]))
        k += 1
    return out

def yaratize(rule, vals):
    n = 0
    strs = []
    for val in vals:
        s = '    $%d = { ' % n
        for c in val:
            s += "%2.2x " % ord(c)
        s += '}'
        strs.append(s)
        n += 1
    return """
rule %s
{
   strings:
%s

   condition:
   	any of them
}""" % (rule,'\n'.join(strs))

""" This is a modified version to include the XOR key in the rule's string """
def yaratize_multi(ofile, rule, vals):
    print "[+] Total rules:",len(vals)-1 #blank header
    # Because we don't want to crash YARA by creating one large rule file (Error 25, Overflow), 
    # splitting them into separate rules/files helps. 
    r_cnt = 0

    for k, r in sorted(vals.items()):
        with open(ofile, 'a') as rules:
            r_name = "rule %s_%d" % (rule, r_cnt)
            rules.write('\n' + r_name)
            rules.write(" {")
            rules.write(" strings:")
            pairs = [r[i:i+2] for i in range(0, len(r), 2)]
            s = " $xor_%s = {" % k
            for pair in pairs:
                if len(pair) != 2:
                    pair = pair + "?"
                s += " %2.2s " % pair
            s += "}"
            rules.write(s)
            rules.write(" condition:")
            rules.write(" any of them")
            rules.write("}")
            r_cnt += 1
    print "[+] Rules saved as:",ofile

""" Same as above except doesn't add wildcard if hex string is 1 char. & doesn't do spacing as it's already done"""
def yaratize_xrat(ofile, rule, vals):
    print "[+] Total rules:",len(vals)-1 #blank header
    # Because we don't want to crash YARA by creating one large rule file (Error 25, Overflow), 
    # splitting them into separate rules/files helps. 
    r_cnt = 0

    for k, r in sorted(vals.items()):
        with open(ofile, 'a') as rules:
            r_name = "rule %s_%d" % (rule, r_cnt)
            rules.write('\n' + r_name)
            rules.write(" {")
            rules.write(" strings:")
            pairs = [r[i:i+2] for i in range(0, len(r), 2)]
            s = " $xor_%s = {" % k
            for pair in pairs:
                s += " %2.2s " % pair
            s += "}"
            rules.write(s)
            rules.write(" condition:")
            rules.write(" any of them")
            rules.write("}")
            r_cnt += 1
    print "[+] Rules saved as:",ofile
