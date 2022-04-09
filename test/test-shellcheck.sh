#! /bin/bash

#
# Run shellcheck ( https://github.com/koalaman/shellcheck ) on the shellscripts
#
# Fail if shellchekc detects errors
#
SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")

export RESULT=0
export SHELLCHECK_OPTS="-e SC2181 -e SC1090"

# $1: shell script to check
run_shellcheck () {
    shellcheck -s bash -S error "$1"
    if [[ $? != "0" ]]; then
        RESULT=1
    fi

}

for file in "$SCRIPTDIRPATH"/../{bin,test}/*.sh
do
    echo "linting \"$file\""
    run_shellcheck "$file"
done

if [[ "$RESULT" == "0" ]]; then
    echo "shellcheck options: \"$SHELLCHECK_OPTS\""
    echo "shellcheck did not find errors"
fi
exit "$RESULT"
