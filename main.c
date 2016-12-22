/*
 * Copyright (C) 2016 FIX94
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <stdio.h>
#include <malloc.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include "rijndael.h"
#include "sha1.h"
#include "fst.h"
#include "tmd.h"
#include "structs.h"
#include "wudparts.h"

#define ALIGN_FORWARD(x,align) \
	((typeof(x))((((uint32_t)(x)) + (align) - 1) & (~(align-1))))

int main(int argc, char *argv[])
{
	puts("wud2app v1.1u1 by FIX94");
	char *ckeyChr = NULL, *gkeyChr = NULL, *gwudChr = NULL;
	bool use_wudparts = false;
	if(argc != 2 && argc != 4)
	{
		puts("--- Single WUD File Usage ---");
		puts("wud2app common.key game.key game.wud");
		puts("--- Wudump Folder Usage ---");
		puts("wud2app \"/full/path/to/folder\" ");
		return 0;
	}
	else if(argc == 2)
	{
		if(wudparts_open(argv[1]) == false)
			return -1;
		puts("Opened Wudump WUD Parts!");
		use_wudparts = true;
	}
	else
	{
		ckeyChr = argv[1];
		gkeyChr = argv[2];
		gwudChr = argv[3];
	}

	//get common key
	FILE *f = NULL;
	if(use_wudparts)
	{
		char tmpChr[1024];
		sprintf(tmpChr,"%s/common.key",argv[1]);
		f = fopen(tmpChr, "rb");
		if(!f)
		{
			puts("Failed to open common.key!");
			return -3;
		}
	}
	else
	{
		f = fopen(ckeyChr, "rb");
		if(!f)
		{
			printf("%s not found!\n", ckeyChr);
			return -1;
		}
	}
	fseek(f, 0, SEEK_END);
	size_t ckeysize = ftell(f);
	rewind(f);
	if(ckeysize != 16)
	{
		puts("Common key size wrong!");
		fclose(f);
		return -2;
	}
	uint8_t ckey[16];
	fread(ckey,1,16,f);
	fclose(f);

	//get disc key
	if(use_wudparts)
	{
		char tmpChr[1024];
		sprintf(tmpChr,"%s/game.key",argv[1]);
		f = fopen(tmpChr, "rb");
		if(!f)
		{
			puts("Failed to open game.key!");
			return -3;
		}
	}
	else
	{
		f = fopen(gkeyChr, "rb");
		if(!f)
		{
			printf("%s not found!\n", gkeyChr);
			return -3;
		}
	}
	fseek(f, 0, SEEK_END);
	size_t keysize = ftell(f);
	rewind(f);
	if(keysize != 16)
	{
		puts("Disc key size wrong!");
		fclose(f);
		return -4;
	}
	uint8_t gamekey[16];
	fread(gamekey,1,16,f);
	fclose(f);

	//open game wud
	if(!use_wudparts)
	{
		f = fopen(gwudChr, "rb");
		if(!f)
		{
			printf("%s not found!\n", gwudChr);
			return -5;
		}
	}
	//read wud name
	char outDir[11];
	outDir[10] = '\0';
	if(use_wudparts)
		wudparts_read(outDir, 10);
	else
		fread(outDir, 1, 10, f);

	puts("Reading Disc FST from WUD");
	//read out and decrypt partition table
	uint8_t *partTblEnc = malloc(0x8000);
	if(use_wudparts)
	{
		wudparts_seek(0x18000);
		wudparts_read(partTblEnc, 0x8000);
	}
	else
	{
		fseeko64(f, 0x18000, SEEK_SET);
		fread(partTblEnc, 1, 0x8000, f);
	}
	uint8_t iv[16];
	memset(iv,0,16);
	aes_set_key(gamekey);
	uint8_t *partTbl = malloc(0x8000);
	aes_decrypt(iv,partTblEnc,partTbl,0x8000);
	free(partTblEnc);

	uint32_t magic = __builtin_bswap32(*(uint32_t*)partTbl);
	if(magic != 0xCCA6E67B)
	{
		puts("Invalid FST!");
		goto extractEnd;
	}
	//make sure TOC is actually valid
	uint32_t expectedHash[5];
	expectedHash[0] = __builtin_bswap32(*(uint32_t*)(partTbl+8));
	expectedHash[1] = __builtin_bswap32(*(uint32_t*)(partTbl+12));
	expectedHash[2] = __builtin_bswap32(*(uint32_t*)(partTbl+16));
	expectedHash[3] = __builtin_bswap32(*(uint32_t*)(partTbl+20));
	expectedHash[4] = __builtin_bswap32(*(uint32_t*)(partTbl+24));

	SHA1Context ctx;
	SHA1Reset(&ctx);
	SHA1Input(&ctx,partTbl+0x800,0x7800);
	SHA1Result(&ctx);

	if(memcmp(ctx.Message_Digest, expectedHash, 0x14) != 0)
	{
		puts("Invalid TOC SHA1!");
		goto extractEnd;
	}

	int numPartitions = __builtin_bswap32(*(uint32_t*)(partTbl+0x1C));
	int siPart;
	toc_t *tbl = (toc_t*)(partTbl+0x800);
	void *tmdBuf = NULL;
	bool certFound = false, tikFound = false, tmdFound = false;
	uint8_t tikKey[16];

	puts("Searching for SI Partition");
	//start by getting cert, tik and tmd
	for(siPart = 0; siPart < numPartitions; siPart++)
	{
		if(strncasecmp(tbl[siPart].name,"SI",3) == 0)
			break;
	}
	if(strncasecmp(tbl[siPart].name,"SI",3) != 0)
	{
		puts("No SI Partition found!");
		goto extractEnd;
	}

	//create output folder
	mkdir(outDir);

	//dont care about first header but only about data
	uint64_t offset = ((uint64_t)__builtin_bswap32(tbl[siPart].offsetBE))*0x8000;
	offset += 0x8000;
	//read out FST
	puts("Reading SI FST from WUD");
	void *fstEnc = malloc(0x8000);
	if(use_wudparts)
	{
		wudparts_seek(offset);
		wudparts_read(fstEnc, 0x8000);
	}
	else
	{
		fseeko64(f, offset, SEEK_SET);
		fread(fstEnc, 1, 0x8000, f);
	}
	void *fstDec = malloc(0x8000);
	memset(iv, 0, 16);
	aes_set_key(gamekey);
	aes_decrypt(iv, fstEnc, fstDec, 0x8000);
	free(fstEnc);
	uint32_t EntryCount = (__builtin_bswap32(*(uint32_t*)(fstDec + 8)) << 5);
	uint32_t Entries = __builtin_bswap32(*(uint32_t*)(fstDec + 0x20 + EntryCount + 8));
	uint32_t NameOff = 0x20 + EntryCount + (Entries << 4);
	FEntry *fe = (FEntry*)(fstDec + 0x20 + EntryCount);

	//increase offset past fst for actual files
	offset += 0x8000;
	uint32_t entry;
	for(entry = 1; entry < Entries; ++entry)
	{
		if(certFound && tikFound && tmdFound)
			break;
		uint32_t cNameOffset = __builtin_bswap32(fe[entry].NameOffset) >> 8;
		const char *name = (const char*)(fstDec + NameOff + cNameOffset);
		if(strncasecmp(name, "title.", 6) != 0)
			continue;
		uint32_t CNTSize = __builtin_bswap32(fe[entry].FileLength);
		uint64_t CNTOff = ((uint64_t)__builtin_bswap32(fe[entry].FileOffset)) << 5;
		uint64_t CNT_IV = __builtin_bswap64(CNTOff >> 16);
		void *titleF = malloc(ALIGN_FORWARD(CNTSize,16));
		if(use_wudparts)
		{
			wudparts_seek(offset + CNTOff);
			wudparts_read(titleF, ALIGN_FORWARD(CNTSize,16));
		}
		else
		{
			fseeko64(f, offset + CNTOff, SEEK_SET);
			fread(titleF, 1, ALIGN_FORWARD(CNTSize,16), f);
		}
		uint8_t *titleDec = malloc(ALIGN_FORWARD(CNTSize,16));
		memset(iv,0,16);
		memcpy(iv + 8, &CNT_IV, 8);
		aes_set_key(gamekey);
		aes_decrypt(iv,titleF,titleDec,ALIGN_FORWARD(CNTSize,16));
		free(titleF);
		char outF[64];
		sprintf(outF,"%s/%s",outDir,name);
		//just write the first found cert, they're all the same anyways
		if(strncasecmp(name, "title.cert", 11) == 0 && !certFound)
		{
			puts("Writing title.cert");
			FILE *t = fopen(outF, "wb");
			fwrite(titleDec, 1, CNTSize, t);
			fclose(t);
			certFound = true;
		}
		else if(strncasecmp(name, "title.tik", 10) == 0 && !tikFound)
		{
			uint32_t tidHigh = __builtin_bswap32(*(uint32_t*)(titleDec+0x1DC));
			if(tidHigh == 0x00050000)
			{
				puts("Writing title.tik");
				FILE *t = fopen(outF, "wb");
				fwrite(titleDec, 1, CNTSize, t);
				fclose(t);
				tikFound = true;
				uint8_t *title_id = titleDec+0x1DC;
				int k;
				for(k = 0; k < 8; k++)
				{
					iv[k] = title_id[k];
					iv[k + 8] = 0x00;
				}
				uint8_t *tikKeyEnc = titleDec+0x1BF;
				aes_set_key(ckey);
				aes_decrypt(iv,tikKeyEnc,tikKey,16);
			}
		}
		else if(strncasecmp(name, "title.tmd", 10) == 0 && !tmdFound)
		{
			uint32_t tidHigh = __builtin_bswap32(*(uint32_t*)(titleDec+0x18C));
			if(tidHigh == 0x00050000)
			{
				puts("Writing title.tmd");
				FILE *t = fopen(outF, "wb");
				fwrite(titleDec, 1, CNTSize, t);
				fclose(t);
				tmdFound = true;
				tmdBuf = malloc(CNTSize);
				memcpy(tmdBuf, titleDec, CNTSize);
			}
		}
		free(titleDec);
	}
	free(fstDec);

	if(!tikFound || !tmdFound)
	{
		puts("tik or tmd not found!");
		goto extractEnd;
	}
	TitleMetaData *tmd = (TitleMetaData*)tmdBuf;
	char gmChar[19];
	uint64_t fullTid = __builtin_bswap64(tmd->TitleID);
	sprintf(gmChar,"GM%016" PRIx64, fullTid);
	printf("Searching for %s Partition\n", gmChar);
	uint32_t appBufLen = 64*1024*1024;
	void *appBuf = malloc(appBufLen);
	//write game .app data next
	int gmPart;
	for(gmPart = 0; gmPart < numPartitions; gmPart++)
	{
		if(strncasecmp(tbl[gmPart].name,gmChar,18) == 0)
			break;
	}
	if(strncasecmp(tbl[gmPart].name,gmChar,18) != 0)
	{
		puts("No GM Partition found!");
		goto extractEnd;
	}
	puts("Reading GM Header from WUD");
	offset = ((uint64_t)__builtin_bswap32(tbl[gmPart].offsetBE))*0x8000;
	uint8_t *fHdr = malloc(0x8000);
	if(use_wudparts)
	{
		wudparts_seek(offset);
		wudparts_read(fHdr, 0x8000);
	}
	else
	{
		fseeko64(f, offset, SEEK_SET);
		fread(fHdr, 1, 0x8000, f);
	}
	uint32_t fHdrCnt = __builtin_bswap32(*(uint32_t*)(fHdr+0x10));
	uint8_t *hashPos = fHdr + 0x40 + (fHdrCnt*4);

	//grab FST first
	puts("Reading GM FST from WUD");
	uint64_t fstSize = __builtin_bswap64(tmd->Contents[0].Size);
	fstEnc = malloc(ALIGN_FORWARD(fstSize,16));
	if(use_wudparts)
	{
		wudparts_seek(offset + 0x8000);
		wudparts_read(fstEnc, ALIGN_FORWARD(fstSize,16));
	}
	else
	{
		fseeko64(f, offset + 0x8000, SEEK_SET);
		fread(fstEnc, 1, ALIGN_FORWARD(fstSize,16), f);
	}
	//write FST to file
	uint32_t fstContentCid = __builtin_bswap32(tmd->Contents[0].ID);
	char outF[64];
	sprintf(outF,"%s/%08x.app",outDir,fstContentCid);
	printf("Writing %08x.app\n",fstContentCid);
	FILE *t = fopen(outF, "wb");
	fwrite(fstEnc, 1, ALIGN_FORWARD(fstSize,16), t);
	fclose(t);
	//decrypt FST to use now
	memset(iv, 0, 16);
	uint16_t content_index = tmd->Contents[0].Index;
	memcpy(iv, &content_index, 2);
	aes_set_key(tikKey);
	fstDec = malloc(ALIGN_FORWARD(fstSize,16));
	aes_decrypt(iv, fstEnc, fstDec, ALIGN_FORWARD(fstSize,16));
	free(fstEnc);
	app_tbl_t *appTbl = (app_tbl_t*)(fstDec+0x20);

	//write in files
	uint16_t titleCnt = __builtin_bswap16(tmd->ContentCount);
	uint16_t curCont;
	for(curCont = 1; curCont < titleCnt; curCont++)
	{
		uint64_t appOffset = ((uint64_t)__builtin_bswap32(appTbl[curCont].offsetBE))*0x8000;
		uint64_t totalAppOffset = offset + appOffset;
		if(use_wudparts)
			wudparts_seek(totalAppOffset);
		else
			fseeko64(f, totalAppOffset, SEEK_SET);
		uint64_t tSize = __builtin_bswap64(tmd->Contents[curCont].Size);
		uint32_t curContentCid = __builtin_bswap32(tmd->Contents[curCont].ID);
		char outF[64];
		sprintf(outF,"%s/%08x.app",outDir,curContentCid);
		printf("Writing %08x.app\n",curContentCid);
		FILE *t = fopen(outF, "wb");
		uint64_t total = tSize;
		while(total > 0)
		{
			uint32_t toWrite = ((total > (uint64_t)appBufLen) ? (appBufLen) : (uint32_t)(total));
			if(use_wudparts)
				wudparts_read(appBuf, toWrite);
			else
				fread(appBuf, 1, toWrite, f);
			fwrite(appBuf, 1, toWrite, t);
			total -= toWrite;
		}
		fclose(t);
		uint16_t type = __builtin_bswap16(tmd->Contents[curCont].Type);
		if(type & 2) //h3 hashes used
		{
			char outF[64];
			sprintf(outF,"%s/%08x.h3",outDir,curContentCid);
			printf("Writing %08x.h3\n",curContentCid);
			t = fopen(outF, "wb");
			uint32_t hashNum = (uint32_t)((tSize / 0x10000000ULL) + 1);
			fwrite(hashPos, 1, (0x14*hashNum), t);
			fclose(t);
			hashPos += (0x14*hashNum);
		}
	}
	free(fstDec);
	free(appBuf);
	free(tmdBuf);

	puts("Done!");
extractEnd:
	free(partTbl);
	if(use_wudparts)
		wudparts_close();
	else
		fclose(f);
	return 0;
}
