#!/bin/bash

usage="$(basename "$0") [-h] [-q queue name] [-w work dir] [-r remote destination] [-g Google project] [-z zone] [-p proxy path] [-c grid certificates] -- copy files to remote storage

where:
    -h  show this help text
    -q  PanDA queue name
    -w  work directory
    -r  remote destination (e.g. nfs-client:/mnt/dask)
    -g  Google project
    -z  zone
    -p  proxy path
    -c  grid certificates directory"

if [[ $1 == "" ]]; then
  echo $usage
  exit 1
fi

while getopts :h:q:w:r:g:z:p:c: flag
do
    case "${flag}" in
        h) echo $usage
          exit 0
          ;;
        q) queuename=${OPTARG};;
        w) workdir=${OPTARG};;
        r) destination=${OPTARG};;
        g) project=${OPTARG};;
        z) zone=${OPTARG};;
        p) proxy=${OPTARG};;
        c) certificates=${OPTARG};;
        :) printf "missing argument for -%s\n" "$OPTARG" >&2
          echo "$usage" >&2
          exit 1
          ;;
        \?) printf "illegal option: -%s\n" "$OPTARG" >&2
          echo "$usage" >&2
          exit 1
          ;;
    esac
done

queuedata="$workdir/queuedata.json"
queuedata_script="queuedata.sh"

# first download queuedata and store in file
if [ -f "$queuedata_script" ]; then
    ./queuedata.sh -q $queuename
else
    echo "$queuedata_script does not exist (copy it to this folder)"
    exit 1
fi

# download ddm endpoints
curl -sS "https://atlas-cric.cern.ch/cache/ddmendpoints.json" >ddmendpoints.json

# copy panda queue json
cp /cvmfs/atlas.cern.ch/repo/sw/local/etc/cric_pandaqueues.json .

files=($proxy $queuedata ddmendpoints.json cric_pandaqueues.json)

# was queuedata downloaded?
if [ -f "$queuedata" ]; then
    echo "$queuedata exists."
    for f in ${files[@]}; do
        echo "copying $f to $destination in project $project"
        gcloud compute scp --recurse $f $destination --project "$project" --zone "$zone"
    done
else
    echo "$queuedata does not exist."
    exit 1
fi

# copy grid certificates
if [ ${certificates+x} ]; then
    echo "$certificates will be transferred."
    files=(`ls $certificates`)
    for f in ${files[@]}; do
        echo "copying $f to nfs-client:$certificates in project $project"
        gcloud compute scp --recurse $certificates/$f nfs-client:$certificates --project "$project" --zone "$zone"
    done
fi

exit 0

