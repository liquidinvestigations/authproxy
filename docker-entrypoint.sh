#!/bin/bash -ex

echo "Running in $PWD"

# chown -R $UID:$GID $DATA_DIR
chown -R 666:666 /app

# su liquid --command "./dockercmd"
# sudo -Eu $USER_NAME "$@

exec gosu liquid "$@"
