#!/bin/bash

SRC="src/*"
DST="$HOME/.binaryninja/plugins/syscaller"

if [ "$(uname)" == 'Linux' ]; then
  mkdir -p $DST
  cp -r $SRC $DST
else
  echo "Platform not supported"
fi
