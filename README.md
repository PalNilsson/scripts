# scripts
A collection of useful scripts for ATLAS/PanDA work.

<b>Archiving</b>:
The archiving tool can be used to make self-extractable binaries from the source files located in the src directory.

<b>Queuedata</b>:
This script will download the queuedata for a given PanDA queue from the PanDA server.

<b>Remote copy</b>:
This is intended to be used on a Harvester node for transferring the grid proxy and queuedata to a remote shared file system (using gcloud command).

<b>Split pilot log</b>:
A small utility for splitting a large intermingled PanDA Pilot log into one output file per pilot.
E.g. usable with huge batch logs from Perlmutter, where all pilots write to a single combined stdout/stderr log and each physical line is tagged at the beginning with the pilot number.

