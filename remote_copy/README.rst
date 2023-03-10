This script is intended to be used on a Harvester node for transferring the grid proxy and queuedata to thr remote shared file system.

To use the script, first copy remote_copy.sh (from this GitHub repository) and queuedata.sh (separate GitHub repository) into the same directory ("copy" in the example below).

# remote_copy.sh -q panda_queue -w /local_path/copy -r nfs-client:/mnt/dask -g google_project -z zone -p proxy_path
