#!/usr/bin/env python
# author: carstein <michal.melewski@gmail.com>
# Annotate syscalls with prototype

import os
import json
from binaryninja import PluginCommand

from modules import syscaller

# register plugin
PluginCommand.register_for_function(
  "[sysc] Decorate syscalls",
  "Annotate syscalls with arguments",
  syscaller.run_plugin)
