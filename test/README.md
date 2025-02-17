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

#### Expect

For interactive tests, 'expect' tool is used. For Debian based system it can be installed with:
```bash
sudo apt-get install expect
```
If expect is not installed, then tests that require it, will be skipped.

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


### Running capsule server scenario tests (experimental)

Create DB Docker image, follow https://github.com/open-eid/cdoc2-capsule-server/server-db/README.md

Login to docker (ghcr.io) - [Authenticating with personal access token](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic)

Run `run-capsule-server-bats-tests.sh`:
```bash
cd bats
./run-capsule-server-bats-tests.sh
```

### Running Smart-ID/Mobile-ID tests (experimental)

Smart-ID/Mobile-ID tests will use [SK demo environment for Smart-ID](https://github.com/SK-EID/smart-id-documentation/wiki/Smart-ID-demo) 
and [SK demo environment for Mobile-ID](https://github.com/SK-EID/MID/wiki/Environment-technical-parameters#demo-parameters) 

To use pre-built images, login to docker (ghcr.io) - [Authenticating with personal access token](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic)

Run `cdoc2_shares_server_tests.bats` tests with following command:
```bash
cd bats
bash run-shares-server-bats-tests.sh
```

Alternatively build Docker images locally if the last repo state is required:

* Check-out the repo [cdoc2-shares-server](https://github.com/open-eid/cdoc2-shares-server/)
* Follow build instructions in https://github.com/open-eid/cdoc2-shares-server/ 
* Build `cdoc2-shares-server` and `cdoc2-shares-server-liquibase` Docker images: 
  `build-images.sh` 
* Verify that values in `test/bats/config/shares-server/.env.local` are correct
* Run `source config/shares-server/export-env.sh config/shares-server/.env.local && cd bats;bash run-shares-server-bats-tests.sh`
