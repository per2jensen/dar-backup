#! /bin/bash

# Generate par2 repair files of .dar files
#
#

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
SCRIPTNAME=$(basename "$0")

ARCHIVE_DIR=""
DAR_ARCHIVE=""


# Get the options
while [ -n "$1" ]; do
  case "$1" in
      --archive-dir)
          shift
          ARCHIVE_DIR="$1"
          ;;
      --archive|-a)
          shift
          DAR_ARCHIVE="$1"
          ;;
      --help|-h)
          echo "$SCRIPTNAME [--help|-h] [--archive|-a <archive name>] [--local-backup-dir] [--alternate-archive-dir <directory>]"
          echo "   --archive-dir <archive directory>"
          echo "   --archive <archive name>, the archive to work on ie: \"TEST_FULL_2022-12-28\""
          exit
          ;;
      *)
          echo option "\"$1\"" not recognized, exiting
          exit
          ;;
  esac
  shift
done

if [[ $ARCHIVE_DIR == ""  ]]; then
    echo "ERROR \"ARCHIVE_DIR\" not given, $SCRIPTNAME exiting"
    exit 1
fi
if [[ $DAR_ARCHIVE == ""  ]]; then
    echo "ERROR \"DAR_ARCHIVE\" not given, $SCRIPTNAME exiting"
    exit 1
fi
 

if [[ ! -d "$ARCHIVE_DIR"  ]]; then
    echo "ERROR alternate archive directory: \"$ARCHIVE_DIR\" not found, $SCRIPTNAME exiting"
    exit 1
fi

RESULT=0
while IFS= read -r -d "" file
do
    echo "Generate 5% repair data for: \"$file\""
    par2 c -r5 -n1 "$file"
    if [[ $? != "0" ]]; then
        RESULT=1
    fi
done <   <(find "$ARCHIVE_DIR" -type f -name "${DAR_ARCHIVE}.*.dar" -print0)


PAR2_FILES=$(find "$ARCHIVE_DIR" -type f -name "${DAR_ARCHIVE}.*.dar.par2" |wc -l)
if (( PAR2_FILES > 0 )); then
    if [[ $RESULT == "0" ]]; then
        echo "par2 successfully generated repair files"
        exit 0
    fi
fi

if [[ $RESULT != "0" ]]; then
    echo "par2 generation of repair files failed"
    exit 1
fi

if (( PAR2_FILES == 0 )); then
        echo "no par2 repair files was generated"
        exit 1
fi
