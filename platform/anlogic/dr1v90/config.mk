#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Anlogic Corporation or its affiliates.
#
#

AL_BOARD ?= board_def
AL_OLD_BOARD := $(shell [ -e $(platform_src_dir)/board ]&&$(READLINK) $(platform_src_dir)/board)
ifneq ("boards/$(AL_BOARD)","$(AL_OLD_BOARD)")
AL_BOARD_DIR := $(shell rm -f $(platform_src_dir)/board;ln -s boards/$(AL_BOARD) $(platform_src_dir)/board;touch $(platform_src_dir)/board/*)
endif

# Compiler flags
platform-genflags-y = -I$(platform_src_dir)/board
platform-cppflags-y =
platform-cflags-y =
platform-asflags-y =
platform-ldflags-y =

# Command for platform specific "make run"
platform-runcmd =

# Blobs to build
FW_TEXT_START ?= 0x00000000
FW_DYNAMIC=y
FW_JUMP=y
# This needs to be 2MB aligned for 64-bit system
FW_JUMP_ADDR=$(shell printf "0x%X" $$(($(FW_TEXT_START) + 0x200000)))
# FW_JUMP_FDT_ADDR=$(shell printf "0x%X" $$(($(FW_TEXT_START) + 0x8000000)))
FW_PAYLOAD=y
# This needs to be 2MB aligned for 64-bit system
FW_PAYLOAD_OFFSET=0x200000
# FW_PAYLOAD_FDT_ADDR=$(FW_JUMP_FDT_ADDR)

