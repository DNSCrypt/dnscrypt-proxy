#!/usr/bin/env bash

# Expand the arguments into an array of strings. This is requires because the GitHub action
# provides all arguments concatenated as a single string.
ARGS=("$@")

/bin/gosec ${ARGS[*]}
