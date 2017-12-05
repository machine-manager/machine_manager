#!/bin/sh

# Check for terminal support
if [ "$OS" != "Windows_NT" ]; then
	if test -t 1 -a -t 2; then
		export MACHINE_MANAGER_ANSI_ENABLED=1
	fi
fi

MM="$(dirname -- "$(realpath -- "$0")")/machine_manager"
if [ "$1" = "ls" ]; then
	exec "$MM" "$@" | less -SR
else
	exec "$MM" "$@"
fi
