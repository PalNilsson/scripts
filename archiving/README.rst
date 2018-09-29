The archiving tool can be used to make self-extractable binaries from the source files located
in the src directory.

Move any source file (e.g. runcontainer.py) into its own directory (e.g. runcontainer) in the src directory,
update the create_self_extractable_archive.sh script accordingly (set the name of the target - e.g. 'runcontainer'),
add a version file in the corresponding src directory (src/runcontainer/version containing e.g. 1.0.0), then run the
script.

Example directory structure before running script:

imacky:archiving Paul$ ls -lFR
total 16
-rw-r--r--  1 Paul  staff  964 29 Sep 13:00 README.rst
drwxr-xr-x  2 Paul  staff   68 29 Sep 12:58 build/
-rwxr-xr-x  1 Paul  staff  637 29 Sep 12:53 create_self_extractable_archive.sh*
drwxr-xr-x  2 Paul  staff   68 29 Sep 12:58 dist/
drwxr-xr-x  3 Paul  staff  102 29 Sep 12:57 src/
drwxr-xr-x  3 Paul  staff  102 29 Sep 12:43 template/

./build:

./dist:

./src:
total 0
drwxr-xr-x  4 Paul  staff  136 29 Sep 12:57 runcontainer/

./src/runcontainer:
total 32
-rwxr-xr-x  1 Paul  staff  9448 29 Sep 12:51 runcontainer.py*
-rw-r--r--  1 Paul  staff     5 29 Sep 12:54 version

./template:
total 8
-rw-r--r--  1 Paul  staff  205 29 Sep 12:43 zipheader


The archiving scripts are based on T. Maeno's PanDA wnscript tools (https://github.com/PanDAWMS/panda-wnscript).

