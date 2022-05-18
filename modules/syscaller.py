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
        bn.log_error(
            '[x] Right now this plugin supports only the following platforms: '
            + str(supported_platforms.keys()))
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


    def annotate_llil(self, function, block, instruction):
        comment = self.format_comment(function, instruction, self.registers)
        function.set_comment(instruction.address, comment)

    def is_constant_regval(self, what: bn.variable.RegisterValue):
        return what.type in (bn.RegisterValueType.ConstantValue, bn.RegisterValueType.ConstantPointerValue)

    def format_comment(self, function, instruction, registers):

        possible_value = instruction.get_reg_value(
            registers[0])

        if self.is_constant_regval(possible_value):
            syscall = self.db[str(
                possible_value.value
            )]  # Get corresponding syscall
        else:
            syscall = {'name': 'Unknown Syscall', 'args': []}

        bn.log_info(
            "[*] Found syscall {} in function {} at 0x{:x}".
            format(syscall['name'], function.name,
                   instruction.address))

        args = []
        # construct arguments
        for i, arg in enumerate(syscall['args']):
            possible_arg_value = instruction.get_reg_value(
                registers[i + 1])

            if self.is_constant_regval(possible_value):
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
                s = self.bv.read(
                    arg_value,
                    self.bv.find_next_data(arg_value, "\x00") -
                    arg_value)
                if s:
                    value = '<{}>'.format(repr(s))
                else:
                    value = '[{}]'.format(hex(arg_value))

            s = '{}: {}'.format(arg['name'], value)
            args.append(s)


        # finally set comment
        comment = '{syscall_name}({arguments})'.format(
            syscall_name=syscall['name'],
            arguments=", ".join(args))

        return comment

    def annotate_syscall(self, function, block, instruction, target):
        args = []
        # registers = self.bv.platform.calling_conventions[0].int_arg_regs
        registers = target.calling_convention.int_arg_regs
        if not registers:
            bn.log_warning("Non-register based calling conventions are not yet implemented")
            return

        comment = self.format_comment(function, instruction, registers)
        function.set_comment(instruction.address, comment)


    def run(self):
        for function in self.functions:
            for block in function.low_level_il:
                for instruction in block:
                    if instruction.operation == bn.LowLevelILOperation.LLIL_SYSCALL:
                        self.annotate_llil(function, block, instruction)
                    elif instruction.operation == bn.LowLevelILOperation.LLIL_CALL:
                        dest = instruction.dest
                        if not isinstance(dest, bn.lowlevelil.LowLevelILConstPtr):
                            continue
                        target = self.bv.get_function_at(dest)
                        if target and target.name == "syscall":
                            self.annotate_syscall(function, block, instruction, target)
