#!/bin/sh

arm-linux-androideabi-gcc \
	-march=armv7-a \
	-shared \
	-fpic \
	-std=c11 \
	-Wall \
	-Wextra \
	*.c \
	-I . \
	-o libandroid-shmem.so \
	-Wl,--version-script=exports.txt

