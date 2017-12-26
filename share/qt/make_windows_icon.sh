#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/hempcoin.ico

convert ../../src/qt/res/icons/hempcoin-16.png ../../src/qt/res/icons/hempcoin-32.png ../../src/qt/res/icons/hempcoin-48.png ${ICON_DST}
