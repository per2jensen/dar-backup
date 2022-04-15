#! /bin/bash

#
#  Run all "test-*" scripts
#
RUNNER_LOG=/tmp/dar-backup-runner.log
exec 1> >(tee -a -- $RUNNER_LOG)
exec 2> >(tee -a -- $RUNNER_LOG >&2)
DATE=$(date -Iseconds)
echo "------------------------------------------------------------------"
echo "dar-backup test runner started: $DATE"
echo "------------------------------------------------------------------"

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")

set -o monitor

TESTRESULT=0
TESTNO=1
for file in "${SCRIPTDIRPATH}"/test-*.sh; do
    $("$file" > /dev/null 2>&1)
    if [[ $? == "0" ]]; then
        RESULT=ok
    else
        RESULT=error
        if [[ ! "$file" =~ test-fail.sh  ]]; then
            TESTRESULT=1
        fi
    fi
    printf "%-6s: test #: %-3s %-60s \n" "${RESULT}" "${TESTNO}" "${file}"
    TESTNO=$(( $TESTNO + 1 ))
done

if [[ $TESTRESULT == "0" ]]; then
    printf "SUCCESS - all testcases succeeded (test-fail.sh must fail) \n"
fi
exit "$TESTRESULT"

