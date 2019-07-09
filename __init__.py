#!/usr/bin/env python
# author: carstein <michal.melewski@gmail.com>
# Annotate syscalls with arguments

from binaryninja import PluginCommand

from .modules import syscaller

# register plugin
PluginCommand.register_for_function(
  "Syscaller/Decorate syscalls in function",
  "Annotate syscalls with arguments",
  syscaller.run_plugin)
