# Versioning guidelines for CDOC2 project

CDOC2 modules are split between two repositories (or more in future). As all modules are not in the
same repository, then version management becomes necessity.

To help with version management, this document describes some ways to manage module versions.

CDOC2 project tries to follow [semantic versioning](https://semver.org/)

## Development without release (inc_version.sh)

* Create feature branch <TASK_ID>_<short_description>
* Make changes

Before opening merge request, run `inc_versions.sh -d` (dry-run) and `inc_versions.sh`

This, will scan modules and increase module version only for changed modules that are not already on
"-SNAPSHOT" version. Changes are detected only for current branch and won't work for main branch.

* `git diff` to verify changes
* Commit, push
* Create MR

`inc_version.sh -d` will print out changed modules, but doesn't change any files.

The script is not perfect, for example if you only change README in a module, then module is still
considered changed although no code changes.

## Using latest version of modules (use_latest_snapshot.sh)

After creating new version Maven module or artifact, install it locally

`mvn install`
`mvn -f <module_name> install`

### Update cdoc2 dependencies for single module

* `mvn -f <module> versions:use-latest-versions -Dincludes=ee.cyber.cdoc2:* -DexcludeReactor=false -DallowSnapshots=true`

Example: `mvn -f get-server versions:use-latest-versions -Dincludes=ee.cyber.cdoc2:* -DexcludeReactor=false -DallowSnapshots=true`


### Update cdoc2 dependencies for all modules in repository

* Run `use_latest_snapshot.sh` to update all modules
* `git diff` to verify changes

## Releases (prepare_release.sh and make_release.sh)

General release procedure:

* Checkout clean branch (usually 'master')
* `prepare_release.sh` (changes versions to RELEASE versions and runs tests)
* Verify changes (`git diff`)
* Edit CHANGELOG.md
* `make_release.sh -d` (`git commit; git push` to RELEASE branch)

This will change -SNAPSHOT version to release version, update dependencies in all modules to latest
non-SNAPSHOT version. Build, test, create release branch, push changes, deploy maven artifacts.

Without parameters `prepare_release.sh` will use version (with -SNAPSHOT removed) from parent pom. 
To specify custom release version use `-v`, example `prepare_release.sh -v 1.2.3`. This will update
version in parent pom before changing other versions.

If everything went well, then
* release branch was created with name 'release_v<parent-pom.version>'
* original branch is checked out ('master' usually)
* Nothing is commited to main branch ('master')

To finish create squash merge from release branch to main branch
```bash
git merge --squash $RELEASE_BRANCH
git commit -m "Squashed commit from $RELEASE_BRANCH"
git push $GIT_REMOTE $GIT_BRANCH
```

or create GitHub PR (recommended) from release branch and merge from GitHub. 

Finish by [publishing](README.md#publishing) deliverables from a release tag.

### Release cdoc2-java-ref-impl and cdoc2-capsule-server

Since test code for cdoc2-capsule-server depends on cdoc2-java-ref-impl `cdoc2-lib` module and
transiently `cdoc2-client` module, then for bigger releases following procedure is recommended:

* Checkout both repositories
* Run `prepare_release.sh` in `cdoc2-java-ref-impl` and then in `cdoc2-capsule-server`. That installs
  `cdoc2-lib` into local maven repository and `cdoc2-capsule-server` will use it during testing
  ('mvn verify')
* Update CHANGELOGs in both repositories
* Run `make_release.sh` in `cdoc2-java-ref-impl` and then in `cdoc2-capsule-server`

### make_release.sh without deploy

`make_release.sh -d` will create release branch, but will not deploy Maven artifacts. 
