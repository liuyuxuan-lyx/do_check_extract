#!/bin/bash

DATE=$(date -Iseconds)
KLEE_OUTPUT_DIR="klee-output"
JOB_DIR=${KLEE_OUTPUT_DIR}"/klee-output-"${DATE}

if [ $# -gt 0 ]
then
    if [ $1 == '-c' -o $1 == '--clean' ]
    then
        rm -rf ${KLEE_OUTPUT_DIR}
    fi
else
    mkdir -p ${KLEE_OUTPUT_DIR}
    ../klee-workdir/klee/build/bin/klee --output-dir=${JOB_DIR} --write-kqueries ./build/target.bc
fi



