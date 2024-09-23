#!/bin/bash

#Update dependencies for latest -SNAPSHOT

mvn versions:use-latest-versions -Dincludes=ee.cyber.cdoc2:* -DexcludeReactor=false -DallowSnapshots=true
