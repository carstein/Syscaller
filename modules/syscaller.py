# Author: carstein <michal.melewski@gmail.com>
# Annotate function with prototype

import os
import sys
import json
from binaryninja import *

supported_platforms = {
    'linux-x86': 'syscalls_32.json',
    'linux-x86_64': 'syscalls_64.json'
}

# Simple database loader - assume all is in one file for now
def load_database(data_db):
  current_file_path = os.path.dirname(os.path.abspath(__file__))
  data_db_path = os.path.join(current_file_path, '..', 'data', data_db)
  fh = open(data_db_path, 'r')
  return json.load(fh)

# Function to be executed when we invoke plugin
def run_plugin(bv, function):
  # logic of platform selection
  if bv.platform.name not in supported_platforms:
    log_error('[x] Right now this plugin supports only the following platforms: ' + str(supported_platforms.keys()))
    return -1

  db = load_database(supported_platforms[bv.platform.name])
  registers = bv.platform.system_call_convention.int_arg_regs

  for block in function.low_level_il:
    for instruction in block:
      if instruction.operation == LowLevelILOperation.LLIL_SYSCALL:
        possible_value = instruction.get_reg_value(registers[0])
        if(hasattr(possible_value, 'value')):
          syscall = db[str(possible_value.value)] # Get corresponding syscall
        else:
          syscall = {'name': 'Unknown Syscall', 'args': []}
        args = []
        # construct arguments
        for i, arg in enumerate(syscall['args']):
          possible_arg_value = instruction.get_reg_value(registers[i+1])
          if(hasattr(possible_arg_value, 'value')):
            arg_value = possible_arg_value.value
          else:
            s = '{}: {}'.format(arg['name'], 'Unknown')
            args.append(s)
            continue

          if arg['type'] == 'value':
            value = arg_value
          if arg['type'] == 'pointer':
            value = '*{}'.format(hex(arg_value))
          if arg['type'] == 'string':
            s = bv.read(arg_value, bv.find_next_data(arg_value, "\x00") - arg_value)
            if s:
              value = '<{}>'.format(repr(s))
            else:
              value = '[{}]'.format(hex(arg_value))

          s = '{}: {}'.format(arg['name'], value)
          args.append(s)

        comment = '{syscall_name}({arguments})'.format(syscall_name=syscall['name'], arguments = ", ".join(args))
        function.set_comment(instruction.address, comment)
        args = []
