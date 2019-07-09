# Author: carstein <michal.melewski@gmail.com>
# Syscaller - decoreate syscall with arguments

import os
import sys
import json

import binaryninja as bn

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
    bn.log_error('[x] Right now this plugin supports only the following platforms: ' + str(supported_platforms.keys()))
    return -1

  db = load_database(supported_platforms[bv.platform.name])

  task = SyscallerTask(bv, function, db)
  task.start()


class SyscallerTask(bn.BackgroundTaskThread):
  def __init__(self, bv, function, db):
    super(SyscallerTask, self).__init__('Decorating function ...')
    self.bv = bv
    self.function = function
    self.db = db
    self.registers = bv.platform.system_call_convention.int_arg_regs
 
  def run(self):
    for block in self.function.low_level_il:
      for instruction in block:
        if instruction.operation == bn.LowLevelILOperation.LLIL_SYSCALL:
          possible_value = instruction.get_reg_value(self.registers[0])

          if(hasattr(possible_value, 'value')):
            syscall = self.db[str(possible_value.value)] # Get corresponding syscall
          else:
            syscall = {'name': 'Unknown Syscall', 'args': []}
          
          args = []
          # construct arguments
          for i, arg in enumerate(syscall['args']):
            possible_arg_value = instruction.get_reg_value(self.registers[i+1])

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
              s = self.bv.read(arg_value, self.bv.find_next_data(arg_value, "\x00") - arg_value)
              if s:
                value = '<{}>'.format(repr(s))
              else:
                value = '[{}]'.format(hex(arg_value))

            s = '{}: {}'.format(arg['name'], value)
            args.append(s)

          comment = '{syscall_name}({arguments})'.format(syscall_name=syscall['name'], arguments = ", ".join(args))
          self.function.set_comment(instruction.address, comment)
          args = []
