#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import os
import sys
import os.path
import re
import hashlib
from pprint import pprint
from subprocess import Popen, PIPE

reload(sys)  
sys.setdefaultencoding('utf-8')

###############################
### check format
###############################
re_uuid = re.compile('^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')

cpfq_version = 1
possible_categories = ["admin", "web", "pwn", "crypto", "forensic", "misc", "ppc", "recon", "reverse", "stego"]

def detectEncoding(path):
	p = Popen(['file', '-i', path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	output, err = p.communicate(b"input data that is passed to subprocess' stdin")
	pattern = re.compile('.*charset=(.*).*')
	m = pattern.match(output)
	if m:
		return m.group(1)
	return 'unknown'

def parseAuthor(path):
	author = ''
	with open(path) as f:
		content = ''.join(f.readlines())
		content = content.replace('\r', '')
		content = content.replace('\n', '')
		content = content.replace('\t', '')
		pattern = re.compile('.*"nick"[ ]*\:[ ]*"([A-Z-a-z@!._]*)".*')
		m = pattern.match(content)
		if m:
			author = m.group(1)
		contacts = []
		pattern = re.compile('.*"contacts"[ ]*\:[ ]*\[[ ]*"([A-Z-a-z@/!._]*)"[ ]*,[ ]*"([A-Z-a-z@/!._]*)".*')
		m = pattern.match(content)
		if m:
			contacts.append(m.group(1));
			contacts.append(m.group(2));

	return author + '(' + ', '.join(contacts) + ')'

def check_category_(data, path):
	print(" * Checking category...")
	category = 'unknown'
	if 'category' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "category"');
		return -10;
	else:
		category = data['category']

	if category not in possible_categories:
		print("[ERROR] " + path + '/main.json: Field "category" has wrong value');
		return -11;
	print(" * -> OK")
	return 0;

def check_value_(data, path):
	print(" * Checking value...")
	value = 0
	if 'value' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "value"');
		return -13;
	else:
		value = data['value']
		if value == 0 or value < 0:
			print("[ERROR]" + path + '/main.json: Quest has value equal 0 or less')
			return -14;
	print(" * -> OK")
	return 0

def check_cpfq_(data, path):
	print(" * Checking cpfq version...")
	if 'cpfq' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "cpfq"');
		return -15;
	else:
		cpfq = data['cpfq']
		if cpfq != cpfq_version:
			print("[ERROR] " + path + '/main.json: cpfq not equal ' + cpfq_version)
			return -16;
	print(" * -> OK")
	return 0
	
def check_uuid_(data, path):
	print(" * Checking uuid ...")
	if 'uuid' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "uuid"');
		return -17;
	else:
		uuid = data['uuid']
		if not re_uuid.match(uuid):
			print("[ERROR] " + path + '/main.json: uuid has invalid format, expected: ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
			return -18;
	print(" * -> OK")
	return 0

def check_authors_(data, path):
	print(" * Checking authors...")
	authors = []
	if 'authors' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "authors"')
		return -19;
	else:
		if not isinstance(data['authors'], list):
			print("[ERROR] " + path + '/main.json: Field "authors" must be list')
			return -20;
		else:
			authors_ = data['authors']
			
			for author in authors_:
				name = ""
				team = ""
				contacts = []
				if "name" not in author:
					print("[ERROR] " + path + '/main.json: Missing subfield author "name"')
					return -21;
				else:
					name = author["name"]
					if name == "":
						print("[ERROR] " + path + '/main.json: Subfield author "name" is empty')
						return -22;
						
				if "team" not in author:
					print("[ERROR]" + path + '/main.json: Missing subfield author "team"')
					return -23;
				else:
					team = author["team"]
					if team == "":
						print("[ERROR] " + path + '/main.json: Subfield author "team" is empty')
						return -23;
				if "contacts" not in author:
					print("[ERROR] " + path + '/main.json: Missing subfield author "contacts"')
					return -24;
				else:
					if not isinstance(author['contacts'], list):
						print("[ERROR] " + path + '/main.json: Subfield author "contacts" must be list')
						return -25;
					else:
						for c in author['contacts']:
							if c == "":
								print("[ERROR] " + path + '/main.json: Empty field in author "contacts"')
								return -26;
							else:
								contacts.append(c);
				contacts = ', '.join(contacts)
				if contacts == "":
					print("[ERROR] " + path + '/main.json: Missing data in subfield authors "contacts"')
					return -27;
	print(" * -> OK")
	return 0

def check_name_(data, path):
	print(" * Checking name ...")
	if 'name' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "uuid"');
		return -28;
	else:
		name = data['name']
		if name == "":
			print("[ERROR] " + path + '/main.json: Field "name" is empty')
			return -29;
		
		dirname = path.split("/")[-1];
		if name != dirname:
			print("[ERROR] " + path + '/main.json: Field "name" has wrong value must like dirname "' + dirname + '" be "' + folder + '"')
			return -30;
			
	print(" * -> OK")
	return 0

def check_description_(data, path):
	print(" * Checking description ...")
	description = {"RU" : "", "EN": ""}
	if 'description' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "name"')
		return -31;
	else:
		description = data['description']
		if 'RU' not in description:
			print("[ERROR] " + path + '/main.json: Missing subfield description "RU"')
			return -32;
		else:
			if description["RU"] == "":
				print("[ERROR] " + path + '/main.json: Empty field in description "RU"')
				return -33;
			
		if 'EN' not in description:
			print("[ERROR] " + path + '/main.json: Missing subfield description "EN"')
			return -34;
		else:
			if description["EN"] == "":
				print("[ERROR] " + path + '/main.json: Empty field in description "EN"')
				return -35;
	print(" * -> OK")
	return 0

def check_hints_(data, path):
	print(" * Checking hints ...")
	hints = []
	if 'hints' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "hints"')
		return -36;
	else:
		if not isinstance(data['hints'], list):
			print("[ERROR] " + path + '/main.json: Field "hints" must be list')
			return -37;
		else:
			hints = data['hints']
			for hint in hints:
				if 'RU' not in hint:
					print("[ERROR] " + path + '/main.json: Missing subfield hint "RU"')
					return -38;
				else:
					if hint["RU"] == "":
						print("[ERROR] " + path + '/main.json: Empty field in hint "RU"')
						return -39;
					
				if 'EN' not in hint:
					print("[ERROR] " + path + '/main.json: Missing subfield hint "EN"')
					return -40;
				else:
					if hint["EN"] == "":
						print("[ERROR] " + path + '/main.json: Empty field in hint "EN"')
						return -41;
	print(" * -> OK")
	return 0;

def check_flag_type_(data, path):
	print(" * Checking flag_type ...")
	if 'flag_type' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "flag_type"');
		return -42;
	else:
		flag_type = data['flag_type']
		if flag_type != "static":
			print("[ERROR] " + path + '/main.json: Field "flag_type" must be static')
			return -43;
			
	print(" * -> OK")
	return 0
	
def check_flag_format_(data, path):
	print(" * Checking flag_format ...")
	if 'flag_format' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "flag_format"');
		return -44;
	else:
		try:
			flag_format = data['flag_format']
			flag_format = re.compile(flag_format)
		except Exception as e:
			print("[ERROR] " + path + '/main.json: Incorrect regular expression in flag_format')
			return -45;
	print(" * -> OK")
	return 0

def check_flag_key_(data, path):
	print(" * Checking flag key ...")
	flag_key = ''
	if 'flag_key' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "flag_key"')
		return -46;
	else:
		flag_key = data['flag_key']
		flag_format = re.compile(data['flag_format'])
			
		pattern = re.compile('FHQ\(.*\)')
		pattern2 = re.compile('FHQ\{.*\}')
		m = flag_format.match(flag_key)
		if flag_key == "":
			print("[ERROR] " + path + '/main.json: Field "flag_key" is empty')
			return -47;
		elif not m:
			print("[ERROR] " + path + '/main.json: Wrong value of field "flag_key" must be format "' + data['flag_format'] + '"')
			return -48;
		flag_file_txt = path + '/private/static/flag.txt';
		text_file = open(flag_file_txt, "r")
		flag_file_txt_content = text_file.read()
		flag_file_txt_content = flag_file_txt_content.strip()
		if flag_file_txt_content != flag_key:
			print("[ERROR] " + path + '/main.json: Wrong value of field "flag_key" not equal with ' + flag_file_txt)
			return -70;
		text_file.close()
			
	print(" * -> OK")
	return 0

def check_files_(data, path):
	print(" * Checking files ...")
	if 'files' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "files"')
		return -49;
	else:
		if not isinstance(data['files'], list):
			print("[ERROR] " + path + '/main.json: Field "files" must be list')
			return -50;
		else:
			files = data['files']
			for f in files:
				if 'name' not in f:
					print("[ERROR] " + path + '/main.json: Missing subfield file "name"')
					return -51;
				else:
					if f["name"] == "":
						print("[ERROR] " + path + '/main.json: Empty field in file "name"')
						return -52;
				
				if 'location' not in f:
					print("[ERROR] " + path + '/main.json: Missing subfield file "location"')
					return -53;
				else:
					fn = f["location"]
					if fn == "":
						print("[ERROR] " + path + '/main.json: Empty field in file "location"')
						return -54;

					f_path = path + '/public/' + fn;
					if not os.path.isfile(f_path):
						print("[ERROR] " + path + '/main.json: Not found file by path: ' + f_path)
						return -55;
					f_md5 = hashlib.md5(open(path + '/public/' + fn, 'rb').read()).hexdigest()

					if 'md5' not in f:
						print("[ERROR] " + path + '/main.json: Missing subfield file "md5"')
						return -56;
					else:
						if f['md5'] != f_md5:
							print("[ERROR] " + path + '/main.json: "md5" incorrect for ' + f_path + ', expected: ' + f_md5)
							return -57;
	print(" * -> OK")
	return 0;

def check_links_(data, path):
	print(" * Checking links ...")
	if 'links' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "links"')
		return -58;
	else:
		if not isinstance(data['links'], list):
			print("[ERROR] " + path + '/main.json: Field "links" must be list')
			return -59;
		else:
			links = data['links']
			for li in links:
				if 'storage' not in li:
					print("[ERROR] " + path + '/main.json: Missing subfield file "storage"')
					return -60;
				else:
					if li["storage"] == "":
						print("[ERROR] " + path + '/main.json: Empty field in file "storage"')
						return -61;
				
				if 'url' not in li:
					print("[ERROR] " + path + '/main.json: Missing subfield file "url"')
					return -62;
				else:
					if li["url"] == "":
						print("[ERROR] " + path + '/main.json: Empty field in file "url"')
						return -63;
	print(" * -> OK")
	return 0;

def check_game_name_(data, folder):
	print(" * Checking game name ...")
	if 'game_name' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "game_name"')
		return -64;
	else:
		game = data['game_name']
		if game == "":
			print("[ERROR] " + path + '/main.json: Game Name could not be empty')
			return -65;
	print(" * -> OK")
	return 0;

def check_game_uuid_(data, path):
	print(" * Checking game uuid ...")
	if 'game_uuid' not in data:
		print("[ERROR] " + path + '/main.json: Missing field "game_uuid"');
		return -66;
	else:
		game_uuid = data['game_uuid']
		if not re_uuid.match(game_uuid):
			print("[ERROR] " + path + '/main.json: game_uuid has invalid format, expected: ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
			return -67;
	print(" * -> OK")
	return 0

def check_(path):
	print("Start checking... ")
	print("Path: '" + path + "'")
	if not os.path.isdir(path):
		print("[ERROR] Not found path ")
		return -3
		
	# check SOLVE.md
	if not os.path.isfile(path + '/SOLVE.md'):
		print("[ERROR] Not found file: " + path + '/SOLVE.md');
		return -5
		
	# check private
	if not os.path.isdir(path + '/private'):
		print("[ERROR] Not found folder: " + path + '/private');
		return -7
		
	if not os.path.isdir(path + '/private/static'):
		print("[ERROR] Not found folder: " + path + '/private/static');
		return -68
		
	if not os.path.isfile(path + '/private/static/flag.txt'):
		print("[ERROR] Not found file: " + path + '/private/static/flag.txt');
		return -69
	
	# check main.json
	if not os.path.isfile(path + '/main.json'):
		print("[ERROR] Not found file: " + path + '/main.json');
		return -4

	try:
		with open(path + '/main.json') as main_json:
			print("Read main.json")
			data = json.load(main_json)

			r = check_cpfq_(data, path);
			if r != 0: return r;
			
			r = check_uuid_(data, path);
			if r != 0: return r;
			
			r = check_name_(data, path)
			if r != 0: return r;
			
			r = check_category_(data, path);
			if r != 0: return r;

			r = check_description_(data, path)
			if r != 0: return r;

			r = check_hints_(data, path)
			if r != 0: return r;

			r = check_value_(data, path)
			if r != 0: return r;
			
			r = check_flag_type_(data, path)
			if r != 0: return r;
			
			r = check_flag_format_(data, path)
			if r != 0: return r;

			r = check_flag_key_(data, path)
			if r != 0: return r;
			
			r = check_files_(data, path)
			if r != 0: return r;
			
			r = check_links_(data, path)
			if r != 0: return r;

			r = check_authors_(data, path)
			if r != 0: return r;
			
			r = check_game_name_(data, path)
			if r != 0: return r;
			
			r = check_game_uuid_(data, path)
			if r != 0: return r;

	except Exception as e:
		status = ''
		encoding = detectEncoding(path + '/main.json');
		print(encoding);
		if encoding != 'utf-8':
			status = encoding
			print('[ERROR] Wrong encoding in "' + path + '", expected "utf-8", got "' + encoding + '"')
			return -9;
		print('[ERROR] checker not checked')
		print e.message, e.args
		return -12;
	
	print(path + " - everything is ok")
	return 0

###############################
### update_readme
###############################

def update_readme_(path):
	print("Start updating readme " + path)
	r = check_(path)
	if r != 0:
		print("[ERROR] wrong format of quest")
		exit(r);
	
	with open(path + '/main.json') as main_json:
		print("Read main.json")
		data = json.load(main_json)
		readme = open(path + '/README.md', 'w')
		readme.write("# " + data["name"] + " (Game: "+ data["game_name"] + ")\n\n")
		readme.write("## Category \n\n")
		readme.write("\t" + data["category"] + " (+" + str(data["value"]) + ")\n\n")
		readme.write("## Description \n\n")
		readme.write("RU:\n\n\t" + data["description"]["RU"] + "\n\n")
		readme.write("EN:\n\n\t" + data["description"]["EN"] + "\n\n")

		readme.write("## Files \n\n")
		for f in data["files"]:
			readme.write(" * File " + f["location"] + " (md5: " + f["md5"] + ")\n")
		readme.write("\n")
		
		readme.write("## Links \n\n")
		for li in data["links"]:
			readme.write(" * Link " + li["storage"] + ": [" + li["url"] + "](" + li["url"] + ")  \n")
		readme.write("\n")
		
		readme.write("## Authors \n\n")
		for au in data["authors"]:
			readme.write(" * Author \"[" + au["team"] + "] " + au["name"] + "\" (" + ', '.join(au["contacts"]) + ")\n")
		readme.write("\n")

		i = 0;		
		readme.write("## Hints \n\n")
		for h in data["hints"]:
			i = i + 1
			readme.write("### Hint " + str(i) + " \n\n")
			readme.write(" * RU: " + h["RU"] + "\n")
			readme.write(" * EN: " + h["EN"] + "\n")
			readme.write("\n")

		readme.write("## Flag \n\n")
		readme.write(" * Flag type: " + data["flag_type"] + "\n")
		readme.write(" * Flag format: `" + data["flag_format"] + "`\n")
		readme.write("\n\n")
		readme.write(" " + data["flag_key"] + "\n\n")
		
		readme.write("#### Generated \n\n")
		readme.write("Generated by cpfq-v1 (https://github.com/freehackquest/cross-platform-format-quest-v1)\n\n")



###############################
### create 
###############################

def create_(path):
	print("Start create folder " + path)


###############################
### run
###############################

if len(sys.argv) != 3:
	print("\nUsage: " + sys.argv[0] + " [check|update_readme|create] <path-to-folder>")
	exit(-1)



command = sys.argv[1]


if command != 'check' and command != 'update_readme' and command != 'create':
	print("\nUsage: " + sys.argv[0] + " [check|update_readme|create] <path-to-folder>")
	exit(-2)

path = sys.argv[2]


if command == 'check':
	check_(path)
elif command == 'update_readme':
	check_(path)
	update_readme_(path)
elif command == 'create':	
	create_(path)
