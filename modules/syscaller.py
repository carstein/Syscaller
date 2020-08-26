# Author: carstein <michal.melewski@gmail.com>
# Syscaller - decorate syscall with arguments

import os
import sys
import json

import binaryninja as bn

supported_platforms = {
    'linux-x86': 'syscalls_32.json',
    'linux-x86_64': 'syscalls_64.json',
    'linux-aarch64': 'syscalls_aarch64.json',
    'linux-armv7': 'syscalls_arm.json',
    'linux-thumb2': 'syscalls_arm.json',
    'linux-armv7eb': 'syscalls_arm.json',
    'linux-thumb2eb': 'syscalls_arm.json',
    'linux-mipsel': 'syscalls_mips32.json',
    'linux-mips': 'syscalls_mips32.json',
    'linux-ppc32': 'syscalls_ppc32.json',
    'linux-ppc32_le': 'syscalls_ppc32.json',
    'linux-ppc64': 'syscalls_ppc64.json',
    'linux-ppc64_le': 'syscalls_ppc64.json',
}

# Simple database loader - assume all is in one file for now
def load_database(data_db):
  current_file_path = os.path.dirname(os.path.abspath(__file__))
  data_db_path = os.path.join(current_file_path, '..', 'data', data_db)
  fh = open(data_db_path, 'r')
  return json.load(fh)

def check_arch(platform_name):
  if platform_name not in supported_platforms:
    bn.log_error('[x] Right now this plugin supports only the following platforms: ' + str(supported_platforms.keys()))
    return False
  
  return True

def run_plugin_current(bv, function):
  if check_arch(bv.platform.name):
    db = load_database(supported_platforms[bv.platform.name])

    task = SyscallerTask(bv, [function], db)
    task.start()

def run_plugin_all(bv):
  if check_arch(bv.platform.name):
    db = load_database(supported_platforms[bv.platform.name])

    task = SyscallerTask(bv, bv.functions, db)
    task.start()


class SyscallerTask(bn.BackgroundTaskThread):
  def __init__(self, bv, functions, db):
    super(SyscallerTask, self).__init__('Decorating function ...')
    self.bv = bv
    self.functions = functions
    self.db = db
    self.registers = bv.platform.system_call_convention.int_arg_regs
 
  def run(self):
    for function in self.functions:
      for block in function.low_level_il:
        for instruction in block:
          if instruction.operation == bn.LowLevelILOperation.LLIL_SYSCALL:
            possible_value = instruction.get_reg_value(self.registers[0])

            if(possible_value.is_constant):
              syscall = self.db[str(possible_value.value)] # Get corresponding syscall
            else:
              syscall = {'name': 'Unknown Syscall', 'args': []}
            bn.log_info("[*] Found syscall {} in function {} at 0x{:x}".format(syscall['name'],
                                                                           function.name, 
                                                                           instruction.address))
            
            args = []
            # construct arguments
            for i, arg in enumerate(syscall['args']):
              possible_arg_value = instruction.get_reg_value(self.registers[i+1])

              if(possible_arg_value.is_constant):
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
            function.set_comment(instruction.address, comment)
            args = []
