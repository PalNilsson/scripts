#!/bin/bash

usage="$(basename "$0") [-h] [-q queue name] -- download PanDA queuedata for the given queue

where:
    -h  show this help text
    -q  PanDA queue name"

if [[ $1 == "" ]]; then
  echo $usage
  exit 1
fi

while getopts :hq: flag
do
    case "${flag}" in
        h) echo $usage
          exit 0
          ;;
        q) queue=${OPTARG};;
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

if [[ $queue != "" ]]; then
  curl -sS "http://pandaserver.cern.ch:25085/cache/schedconfig/$queue.all.json" >$queue.json
fi
