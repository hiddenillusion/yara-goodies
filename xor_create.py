"""
An example of how to import from xortools and auto-create
YARA rules based on a string of your choice
"""
from xortools import get_xor_permutations_xrat as get_perms_xrat
from xortools import yaratize_xrat as yara_xrat

string = 'Microsoft'
rname  = 'two_byte_xor_XtremeRAT_keylog_' + string
fname  = rname + '.yara'
yara_xrat(fname, rname, get_perms_xrat(string))

