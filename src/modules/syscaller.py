# Author: carstein <michal.melewski@gmail.com>
# Annotate function with prototype

import os
import sys
import json
from binaryninja import *

syscalls_32_db = 'syscalls_32.json'

# Simple database loader - assume all is in one file for now
def load_database(data_path):
  fh = open(sys.path[0]+'/syscaller/data/' + data_path, 'r')
  return json.load(fh)

# Function to be executed when we invoke plugin
def run_plugin(bv, function):
  # logic of platform selection
  if bv.platform.name != 'linux-x86':
    log_error('[x] Right now this pluggin support only linux-x86 platform')
    return -1

  db = load_database(syscalls_32_db)
  registers = bv.platform.system_call_convention.int_arg_regs

  for block in function.low_level_il:
    for instruction in block:
      if instruction.operation == LowLevelILOperation.LLIL_SYSCALL:
        syscall = db[str(function.get_reg_value_at_low_level_il_instruction(
                          instruction.instr_index, registers[0]).value)] # Get corresponding syscall

        args = []
        # construct arguments
        for i, arg in enumerate(syscall['args']):
          arg_value = function.get_reg_value_at_low_level_il_instruction(instruction.instr_index, registers[i+1]).value

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
