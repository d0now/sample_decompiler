#!/bin/bash

set -ex

ROOT=$(realpath $(dirname $0))
KSC=$(realpath $ROOT/../kaitai-struct-compiler/bin/kaitai-struct-compiler)

$KSC -t python --outdir $ROOT/pysd resources/elf.ksy
