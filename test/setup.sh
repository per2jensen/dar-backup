#! /bin/bash
# test setup for every test script
# this is sourced in the actual test scripts

DATE=$(date +"%Y-%m-%d")
TESTRESULT=0

TESTDIR=/tmp/dar-backup-test

failOnError () {
  if [[ $1 != "0"  ]]; then
      echo operation failed, exiting
      exit 1
  fi
}


# grep for expected string and print result
# $1: search string
# $2: logfile to search in
checkExpectLog () {
  grep -P "$1" "$2" > /dev/null
  if [[ $? == "0" ]]; then
    echo "ok \"$1\" found"
  else
    echo "ERROR: \"$1\" NOT found"
    TESTRESULT=1
  fi
}



# grep for string expected NOT to be found and print result
# $1: search string
# $2: logfile to search in
checkDontFindLog () {
  grep -P "$1" "$2" > /dev/null
  if [[ $? == "0" ]]; then
    echo "ERROR \"$1\" was found"
    TESTRESULT=1
  else
    echo "ok \"$1\" not found as expected"
  fi
}

# check given symbolic link path, verify it exists and is a link
# $1: link paht
checkExpectSymbolicLink () {
  if [[ -L "$1" ]]; then
    echo "ok Symbolic link: \"$1\" found"
  else
    echo "ERROR: symbolic link \"$1\" NOT found"
    TESTRESULT=1
  fi
}

echo "setup.sh:  TESTDIR:       $TESTDIR"
echo "setup.sh:  SCRIPTDIRPATH: $SCRIPTDIRPATH"

rm -fr "$TESTDIR"
mkdir -p "$TESTDIR/archives"

cp -R "$SCRIPTDIRPATH/dirs"         "$TESTDIR/"
cp -R "$SCRIPTDIRPATH/../bin"       "$TESTDIR/"
cp -R "$SCRIPTDIRPATH/../conf"      "$TESTDIR/"
# override some conf files with test versions
cp -R "$SCRIPTDIRPATH/conf"    "$TESTDIR/"


# test templates dir and copy it
cp -R "$SCRIPTDIRPATH/templates"                          "$TESTDIR/"
# non-test templates
cp "$SCRIPTDIRPATH/../templates/dar_par.dcf.template"     "$TESTDIR/templates/"
cp "$SCRIPTDIRPATH/../templates/darrc.template"           "$TESTDIR/templates/"


chmod +x "$TESTDIR/bin/install.sh"
"$TESTDIR/bin/install.sh"

source "$TESTDIR/conf/dar-backup.conf"
