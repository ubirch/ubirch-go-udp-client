#! /usr/bin/env bash
SCRIPTPATH="$( cd "$(dirname "$0")" || exit ; pwd -P )"
if [ ! -f $SCRIPTPATH/ubirch-go-client ]; then
  echo "Missing 'ubirch-go-client' program file"
  exit 1
fi
if [ ! -f $SCRIPTPATH/config.json ]; then
  echo "Missing 'config.json' configurations file"
  exit 1
fi

while (true); do
  $SCRIPTPATH/ubirch-go-client
  echo "Press Ctrl-C to stop!"
  sleep 5
done
