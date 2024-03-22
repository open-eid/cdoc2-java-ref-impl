# `CDOC2` container testing

### Setup before testing
* Install `bats` Bash Automated Testing System from github https://github.com/bats-core/
* Download bats helper libraries:
```bash
cd bats
source install_bats.sh
```
This command will install helper libraries into temporary folder `/target` and arrange check out 
into specified release tags. The folder won't be commited and can be deleted manually after testing 
and recreated again running the command ones more.


## Tests running

_Precondition_: bats helper libraries are installed.
Run tests: 
```bash
cd bats
source variables.sh
bats cdoc2_tests.bats
```

Result has to as follows:

```
 ✓ Starting...
 ✓ test1: ......
 ✓ test2: ......
 ...............
 ✓ All tests were executed.

3 tests, 0 failures
```

All test vectors within testing will be created in the same temporary folder `/target`. Test 
results will be deleted after each test case execution automatically.
