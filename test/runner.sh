#! /bin/bash

#
#  Run all "test-*" scripts
#
RUNNER_LOG=/tmp/dar-backup-runner.log

TESTCASE_LOG=/tmp/dar-backup-test-cases.log
rm -f $TESTCASE_LOG

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
RESULT=""
for file in "${SCRIPTDIRPATH}"/test-*.sh; do
    TIME=$(date "-Iseconds")
    printf "%-20s: #: %-15s %-60s \n" "==>Testcase<==: ${TESTNO}" "${TIME}"  "${file}"  >> $TESTCASE_LOG
    $("$file" >> $TESTCASE_LOG  2>&1)
    if [[ $? == "0" ]]; then
        RESULT=ok
    else
        RESULT=error
        if [[ ! "$file" =~ test-fail.sh  ]]; then
            TESTRESULT=1
        fi
    fi
    printf "%-6s: #: %-3s %-60s \n" "${RESULT}" "${TESTNO}" "${file}"
    TESTNO=$(( TESTNO + 1 ))
    RESULT=""
done

if [[ $TESTRESULT == "0" ]]; then
    printf "SUCCESS - all testcases succeeded (test-fail.sh must fail) \n"
fi
exit "$TESTRESULT"

