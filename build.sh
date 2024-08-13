#!/bin/bash

FOLDER_OF_THIS_SCRIPT=$(cd $(dirname $0); pwd)

bazel build //:envoy -c fastbuild