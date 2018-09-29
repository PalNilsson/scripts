The archiving tool can be used to make self-extractable binaries from the source files located
in the src directory.

Move any source file (e.g. runcontainer.py) into its own directory (e.g. runcontainer) in the src directory,
update the create_self_extractable_archive.sh script accordingly (set the name of the target - e.g. 'runcontainer'),
add a version file in the corresponding src directory (src/runcontainer/version containing e.g. 1.0.0), then run the
script.

Example directory structure before running script:

README.rst
build/
create_self_extractable_archive.sh*
dist/
src/
template/

./build:

./dist:

./src:

runcontainer/

./src/runcontainer:

runcontainer.py*

version

./template:

zipheader


The archiving scripts are based on T. Maeno's PanDA wnscript tools (https://github.com/PanDAWMS/panda-wnscript).

