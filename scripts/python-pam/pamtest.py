#!/usr/bin/env python

import sys
import PAM

def pam_conv(auth, query_list, userData):

	resp = []

        bad_pass = "ubuntu\x00rocks"

	for i in range(len(query_list)):
		query, type = query_list[i]
		if type == PAM.PAM_PROMPT_ECHO_ON:
			resp.append((bad_pass, 0))
		elif type == PAM.PAM_PROMPT_ECHO_OFF:
			resp.append((bad_pass, 0))
		elif type == PAM.PAM_PROMPT_ERROR_MSG or type == PAM.PAM_PROMPT_TEXT_INFO:
			print query
			resp.append(('', 0))
		else:
			return None

	return resp

service = 'passwd'

if len(sys.argv) == 2:
	user = sys.argv[1]
else:
	user = None

auth = PAM.pam()
auth.start(service)
if user != None:
	auth.set_item(PAM.PAM_USER, user)
auth.set_item(PAM.PAM_CONV, pam_conv)
try:
	auth.authenticate()
	auth.acct_mgmt()
except PAM.error, resp:
	print 'Go away! (%s)' % resp
except:
	print 'Internal error'
else:
	print 'Good to go!'
