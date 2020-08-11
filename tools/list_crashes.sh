# Count and list the different crashes, can be used to get a quick overview
# of the fuzzing results for a given project
grep -roh -E ".{0,1}RPCException\(\'[a-z0-9 ]+'," $1 | sort | uniq -c
