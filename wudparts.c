/*
 * Copyright (C) 2016 FIX94
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

bool parts_open = false;
FILE *parts[12] = { NULL };
uint64_t part_offset_start[12];
uint64_t part_offset_end[12];
uint64_t part_offset_current[12];
uint64_t current_offset = 0;

bool wudparts_open(const char *path)
{
	uint64_t offset = 0;
	int i;
	bool fail = false;
	for(i = 0; i < 12; i++)
	{
		char file[1024];
		sprintf(file, "%s/game_part%i.wud", path, i+1);
		parts[i] = fopen(file,"rb");
		if(parts[i] == NULL)
		{
			printf("Failed to open game_part%i.wud!\n", i+1);
			fail = true;
			break;
		}
		part_offset_current[i] = 0;
		part_offset_start[i] = offset;
		fseek(parts[i],0,SEEK_END);
		size_t fsize = ftell(parts[i]);
		fseek(parts[i],0,SEEK_SET);
		if((i == 11 && fsize != 0x53A00000) || (i != 11 && fsize != 0x80000000))
		{
			printf("game_part%i.wud has a wrong filesize!\n", i+1);
			fail = true;
			break;
		}
		offset += fsize;
		part_offset_end[i] = offset;
	}
	if(!fail)
	{
		current_offset = 0;
		parts_open = true;
		return true;
	}
	//failed!
	for(i = 0; i < 12; i++)
	{
		if(parts[i] != NULL)
		{
			fclose(parts[i]);
			parts[i] = NULL;
		}
	}
	return false;
}

static size_t _wudparts_read_offset(uint8_t *buf, uint64_t offset, size_t len)
{
	size_t read = 0;
	int i;
	for(i = 0; i < 12; i++)
	{
		if(offset >= part_offset_start[i] && offset < part_offset_end[i])
		{
			uint64_t seekOffset = (offset - part_offset_start[i]);
			if(part_offset_current[i] != seekOffset)
			{
				printf("Seeking to 0x%" PRIx64 " in game_part%i.wud\n", seekOffset, i+1);
				fseeko64(parts[i], seekOffset, SEEK_SET);
				part_offset_current[i] = seekOffset;
			}
			size_t toread = (size_t)((offset + len) > part_offset_end[i]) ? (part_offset_end[i] - offset) : len;
			read += fread(buf, 1, toread, parts[i]);
			part_offset_current[i] += read;
			buf += toread;
			offset += toread;
			len -= toread;
			if(len == 0)
				break;
		}
	}
	return read;
}

size_t wudparts_read(void *buf, size_t len)
{
	if(buf == NULL || len == 0) return 0;
	size_t read = _wudparts_read_offset((uint8_t*)buf, current_offset, len);
	current_offset += read;
	return read;
}

void wudparts_seek(uint64_t offset)
{
	current_offset = offset;
}

uint64_t wudparts_tell()
{
	return current_offset;
}

void wudparts_close()
{
	if(parts_open == false)
		return;
	int i;
	for(i = 0; i < 12; i++)
	{
		if(parts[i] != NULL)
		{
			fclose(parts[i]);
			parts[i] = NULL;
		}
	}
	parts_open = false;
}
