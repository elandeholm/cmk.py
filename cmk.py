#! /usr/bin/env python

import re
import sys
import os
import subprocess
import shlex

SH="/bin/sh"
ENV="/usr/bin/env"
DOTCMK=".cmk"
CMKSH=".cmksh"
CMKSH_WRAP="./.cmksh-wrap"

def defaults(config):
	# sane defaults
	config["CC"] = "gcc"
	config["LD"] = "gcc"
	config["RM"] = "rm"
	config["DEFINES"] = [ ]
	config["CC-FLAGS"] = [ "Wall", "std=c99" ]
	config["CC-DFLAGS"] = [ "g", "DDEBUG" ]
	config["CC-OFLAGS"] = [ "O2", "native" ]
	config["LD-FLAGS"] = [ ]
	config["RM-FLAGS"] = "f"
	config["LD-LIBS"] = [ ]

def execute(cmd, env=False, inp=None):
	fail = None
	stdoutdata = ""
	stderrdata = ""
	try:
		if env:
			p = subprocess.Popen(
				cmd, shell=False, stdin=subprocess.PIPE,
				stdout=subprocess.PIPE, stderr=subprocess.PIPE
			)
		else:
			p = subprocess.Popen(
				cmd, shell=False, stdin=subprocess.PIPE,
				stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}
			)		
		if inp:
			stdoutdata, stderrdata = p.communicate(inp)
		else:
			stdoutdata, stderrdata = p.communicate()
	except Exception, fail:
		pass
	
	if fail or p.returncode != 0:
		print("command failed: {:s}".format(cmd))
		if fail:
			print("exception: {:s}".format(fail))
		elif p.returncode != 0:
			print("return code: {:d}".format(p.returncode))

		if stderrdata != "":
			print("contents of stderr:")
			for line in stderrdata.split("\n"):
				if len(line) > 0:
					print("  {:s}".format(line))
		return None
		
	return stdoutdata

def add_configurable(makefile, config, variable):
	try:
		values = value = config[variable]
		if list(value) == value:
			values = " ".join(value)
		if variable.endswith("FLAGS"):
			try:
				flags = []
				for flag in value:
					if flag[0] != "-" and flag[0] != "$":
						flags.append("-{}".format(flag))
				value = " ".join(flags)
			except:
				pass
		elif variable.endswith("LIBS"):
			try:
				flags = []
				for flag in value:
					if flag[0] != "-":
						flags.append("-l{}".format(flag))
				value = " ".join(flags)
			except:
				pass		
		else:
			value = values
	except:
		value = ""
	makefile.append("{}={{}}".format(variable).format(value))

def add_configurables(makefile, config, variables):
	for variable in variables:
		add_configurable(makefile, config, variable)

def prepend_flag(config, flag, first):
	try:
		value = config[flag]
		if list(value) == value:
			config[flag] = [ first ]
			config[flag].extend(value)
		else:
			config[flag] = [ first, value ]
	except KeyError:
		config[flag] = [ first ]	

def add_preamble(makefile, config):
	if "PREAMBLE" in config:
		makefile.append(config["PREAMBLE"])
	add_configurables(makefile, config, [ "CC", "RM" ])
	DEFINES=[]
	try:
		for define in config["DEFINES"]:
			key, value = define, ""
			try:
				equals = define.index("=")
				key, value = define[:equals], define[equals+1:]
			except:
				pass				
			if len(value):			
				DEFINES.append("-D{}={}".format(key, value))
			else:
				DEFINES.append("-D{}".format(key))
	except:
		DEFINES = [ config["DEFINES"] ]
		pass
#	DEFINES.sort()


	config["CC-DEFINES"] = " ".join(DEFINES)

	prepend_flag(config, "CC-FLAGS", "$(CC-DEFINES)")
	prepend_flag(config, "CC-DFLAGS", "$(CC-FLAGS)")
	prepend_flag(config, "CC-OFLAGS", "$(CC-FLAGS)")

	add_configurables(makefile, config, [
		"CC-DEFINES", "CC-FLAGS", "CC-DFLAGS", "CC-OFLAGS", "LD-FLAGS", "RM-FLAGS", "LD-LIBS"
	])

def add_objs(makefile, objs):
	files = []
	for obj in objs:
		files.append("{}.o".format(obj))
	makefile.append("\nOBJS={}".format(" ".join(files)))

def add_exes(makefile, objs):
	makefile.append("EXES={}\n".format(" ".join(objs)))		

def get_config_if_set(config, variable):
	if variable in config:
		return "$({})".format(variable)
	else:
		return ""

def add_obj(makefile, config, name, dependencies):
	cc_flags=get_config_if_set(config, "CC-FLAGS")
	hdeps = " ".join([ "{}.h".format(d) for d in dependencies])
	makefile.append(
		"{}.o: {}.c {}\n\t$(CC) {} -o {}.o -c {}.c".format(
			name, name, hdeps, cc_flags, name, name
		)
	)

def add_exe(makefile, config, name, dependencies):
	ld_flags=get_config_if_set(config, "LD-FLAGS")
	odeps = " ".join([ "{}.o".format(d) for d in dependencies])
	makefile.append(
		"{}: {}.o {}\n\t$(CC) {} -o {} {} $(LD-LIBS)".format(
			name, name, odeps, ld_flags, name, odeps
		)
	)

def add_all(makefile):
	makefile.append("all:\t$(EXES)\n\t")

def add_clean(makefile):
	makefile.append("clean:\n\t$(RM) $(RM-FLAGS) $(OBJS) $(EXES)\n\t")

def scanner(cfile):
	deps = set()
	main = False
	ipat = re.compile('#[ ]*include[ ]+"([^"]*)"')
	mpat = re.compile('int[ ]+main[ ]*\(')
	for line in cfile:
		matches = ipat.findall(line)
		if matches:
			file_name = matches[0]
			name, ext = os.path.splitext(matches[0])
			deps.add(name)
		if mpat.match(line):
			main = True
	return main, deps

def dotcmk(file_name, lines=[]):
	config = {}
	if file_name:
		try:
			with open(file_name, "rb") as config_file:
				lines = config_file.readlines().split("\n")
		except IOError:
			pass
	more = False
	lines.append("\n") # guard against line continuation on the last line
	for line in lines:
		if len(line) and line[-1] == "\\":
			more =  True
			prev = line[:-1]
			continue
		elif more:
			line = "\n".join(prev, line)
		try:
			equals = line.index("=")
			name = line[:equals]
			if name == "DEFINES":
				value = shlex.split(line[equals+1:], False)
			else:
				value = line[equals+1:]
			config[name] = value
		except:
			if line and not line.isspace():
				print("mea culpa; I don't understand the configure argument: {}".format(line))
				raise
	return config

def configure():
	config = {}
	defaults(config)
	#override configurables defined in .cmk or .cmksh
	global SH, DOTCMK, CMKSH, CMKSH_WRAP
	dotconfig = dotcmk(DOTCMK)
	if dotconfig:
		config.update(dotconfig)
	try:
		output = None
		with open(CMKSH_WRAP, "wb") as wrap_file, open(CMKSH, "rb") as cmksh_file:
			wrap_file.writelines([ " ".join(["#!", SH, "-a"]), "\n" ])
			wrap_file.writelines(cmksh_file.readlines())
			wrap_file.writelines([ENV, "\n"])
			os.chmod(CMKSH_WRAP, 0755)
	except IOError:
		pass
	else:
		output = execute(CMKSH_WRAP)
	finally:
		os.remove(CMKSH_WRAP)
		if output:
			config.update(dotcmk(None, output.split("\n")))
	return config
	
# nonrecursive dependency inference like a baws!

def exe_dependencies(name, dependencies):
	deps = set((name,))
	unresolved = [ name ]
	try:
		unresolved.extend(dependencies[name])
		print("unresolved is {}".format(unresolved))
	except:
		raise
	while len(unresolved):
		print("** unresolved is {}".format(unresolved))
		unresolved_new = set()
		for name2 in unresolved:
			if name2 in deps: # I've already done you!
				print("already dun {}".format(name2))
			else:
				deps.add(name2)
			try:
				deps_new = [ d for d in dependencies[name2] if not d in deps ]
				for new in deps_new:
					unresolved_new.add(new)
				print("name is {}, deps_new is {}".format(name2, deps_new))
			except KeyError:
				print("KeyError on {}".format(name2))
		print("** unresolved is {}, unresolved_new is {}".format(unresolved, unresolved_new))
		unresolved = unresolved_new
		
	print("returning {}".format(deps))
	return sorted(deps)

if __name__ == "__main__":
	objs = set()
	exes = set()
	dependencies = {}
	makefile = []
	config = configure()	

	do_make = False
	make_args = []
	cmk_args = []
	cmk_arg = True
	for arg in sys.argv[1:]:
		if cmk_arg and arg == "make":
			cmk_arg = False
			do_make = True
		elif cmk_arg:
			cmk_args.append(arg)
		else:
			make_args.append(arg)
	config.update(dotcmk(None, cmk_args))

	for file_name in os.listdir("."):
		name, ext = os.path.splitext(file_name)
		if ext.lower() == ".c":
			with open(file_name, "rb") as cfile:
				main, deps = scanner(cfile)
				dependencies[name] = sorted(deps)
				print("added dependency[{}]: {}".format(name, dependencies[name]))
				objs.add(name)
				print("added obj: {}".format(name))
				if main:
					exes.add(name)
				print("added exe: {}".format(name))

	objs_ordered = sorted(objs)
	exes_ordered = sorted(exes)
	add_preamble(makefile, config)
	add_objs(makefile, objs_ordered)
	add_exes(makefile, exes_ordered)
	for name in sorted(objs):
		add_obj(makefile, config, name, dependencies[name])	
	for name in exes_ordered:
		add_exe(makefile, config, name, exe_dependencies(name, dependencies))
	add_all(makefile)
	add_clean(makefile)	

	makefile_text = "\n".join(makefile)
	
	if do_make:
		make_cmd = [ "make", "-f", "-" ]
		make_cmd.extend(make_args)
		print(execute(make_cmd, env=True, inp=makefile_text))
	else:
		print(makefile_text)

