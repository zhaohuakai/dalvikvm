/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Access the contents of a Jar file.
 *
 * This isn't actually concerned with any of the Jar-like elements; it
 * just wants a zip archive with "classes.dex" inside.  In Android the
 * most common example is ".apk".
 */

#include "Dalvik.h"
#include "libdex/OptInvocation.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <fcntl.h>
#include <errno.h>

static const char* kDexInJarName = "classes.dex";

/*
 * Attempt to open a file whose name is similar to <fileName>,
 * but with the supplied suffix.  E.g.,
 * openAlternateSuffix("Home.apk", "dex", O_RDONLY) will attempt
 * to open "Home.dex".  If the open succeeds, a pointer to a
 * malloc()ed copy of the opened file name will be put in <*pCachedName>.
 *
 * <flags> is passed directly to open(). O_CREAT is not supported.
 */
static int openAlternateSuffix(const char *fileName, const char *suffix,
    int flags, char **pCachedName)
{
	printf("ZHK in JarFile.cpp:48\n");
    char *buf, *c;
    size_t fileNameLen = strlen(fileName);
    size_t suffixLen = strlen(suffix);
    size_t bufLen = fileNameLen + suffixLen + 1;
    int fd = -1;

    buf = (char*)malloc(bufLen);
    if (buf == NULL) {
        errno = ENOMEM;
		printf("ZHK in JarFile.cpp:58\n");
        return -1;
    }

    /* Copy the original filename into the buffer, find
     * the last dot, and copy the suffix to just after it.
     */
    memcpy(buf, fileName, fileNameLen + 1);
    c = strrchr(buf, '.');
    if (c == NULL) {
        errno = ENOENT;
		printf("ZHK in JarFile.cpp:69\n");
        goto bail;
    }
    memcpy(c + 1, suffix, suffixLen + 1);

    fd = open(buf, flags);
    if (fd >= 0) {
        *pCachedName = buf;
		printf("ZHK in JarFile.cpp:77 fd=%d\n", fd);
        return fd;
    }
	printf("ZHK in JarFile.cpp:80 Couldn't open %s: %s\n", buf, strerror(errno));
    ALOGV("Couldn't open %s: %s", buf, strerror(errno));
bail:
    free(buf);
    return -1;
}

/*
 * Checks the dependencies of the dex cache file corresponding
 * to the jar file at the absolute path "fileName".
 */
DexCacheStatus dvmDexCacheStatus(const char *fileName)
{
    ZipArchive archive;
    char* cachedName = NULL;
    int fd;
    DexCacheStatus result = DEX_CACHE_ERROR;
    ZipEntry entry;

    /* Always treat elements of the bootclasspath as up-to-date.
     * The fact that interpreted code is running at all means that this
     * should be true.
     */
    if (dvmClassPathContains(gDvm.bootClassPath, fileName)) {
        return DEX_CACHE_OK;
    }

    //TODO: match dvmJarFileOpen()'s logic.  Not super-important
    //      (the odex-first logic is only necessary for dexpreopt)
    //      but it would be nice to be consistent.

    /* Try to find the dex file inside of the archive.
     */
    if (dexZipOpenArchive(fileName, &archive) != 0) {
        return DEX_CACHE_BAD_ARCHIVE;
    }
    entry = dexZipFindEntry(&archive, kDexInJarName);
    if (entry != NULL) {
        bool newFile = false;

        /*
         * See if there's an up-to-date copy of the optimized dex
         * in the cache, but don't create one if there isn't.
         */
        ALOGV("dvmDexCacheStatus: Checking cache for %s", fileName);
        cachedName = dexOptGenerateCacheFileName(fileName, kDexInJarName);
        if (cachedName == NULL)
            return DEX_CACHE_BAD_ARCHIVE;

        fd = dvmOpenCachedDexFile(fileName, cachedName,
                dexGetZipEntryModTime(&archive, entry),
                dexGetZipEntryCrc32(&archive, entry),
                /*isBootstrap=*/false, &newFile, /*createIfMissing=*/false);
        ALOGV("dvmOpenCachedDexFile returned fd %d", fd);
        if (fd < 0) {
            result = DEX_CACHE_STALE;
            goto bail;
        }

        /* dvmOpenCachedDexFile locks the file as a side-effect.
         * Unlock and close it.
         */
        if (!dvmUnlockCachedDexFile(fd)) {
            /* uh oh -- this process needs to exit or we'll wedge the system */
            printf("ZHK in JarFile.cpp:144 Unable to unlock DEX file\n");
			ALOGE("Unable to unlock DEX file");
            goto bail;
        }

        /* When createIfMissing is false, dvmOpenCachedDexFile() only
         * returns a valid fd if the cache file is up-to-date.
         */
    } else {
        /*
         * There's no dex file in the jar file.  See if there's an
         * optimized dex file living alongside the jar.
         */
        fd = openAlternateSuffix(fileName, "odex", O_RDONLY, &cachedName);
        if (fd < 0) {
			printf("ZHK in JarFile:158 Zip is good, but no %s inside, and no .odex file in the same directory\n", kDexInJarName);
            ALOGI("Zip is good, but no %s inside, and no .odex "
                    "file in the same directory", kDexInJarName);
            result = DEX_CACHE_BAD_ARCHIVE;
            goto bail;
        }

        ALOGV("Using alternate file (odex) for %s ...\n", fileName);
        if (!dvmCheckOptHeaderAndDependencies(fd, false, 0, 0, true, true)) {
            ALOGE("%s odex has stale dependencies", fileName);
            ALOGE("odex source not available -- failing");
            result = DEX_CACHE_STALE_ODEX;
            goto bail;
        } else {
			ALOGV("%s odex has good dependencies", fileName);
        }
    }
    result = DEX_CACHE_OK;

bail:
	printf("ZHK in JarFile:182 \n");
    dexZipCloseArchive(&archive);
    free(cachedName);
    if (fd >= 0) {
        close(fd);
    }
    return result;
}

/*
 * Open a Jar file.  It's okay if it's just a Zip archive without all of
 * the Jar trimmings, but we do insist on finding "classes.dex" inside
 * or an appropriately-named ".odex" file alongside.
 *
 * If "isBootstrap" is not set, the optimizer/verifier regards this DEX as
 * being part of a different class loader.
 */
int dvmJarFileOpen(const char* fileName, const char* odexOutputName,
    JarFile** ppJarFile, bool isBootstrap)
{
    /*
     * TODO: This function has been duplicated and modified to become
     * dvmRawDexFileOpen() in RawDexFile.c. This should be refactored.
     */
	printf("\t\t\t\t\t\tin JarFile.cpp:195\n");
    ZipArchive archive;
    DvmDex* pDvmDex = NULL;
    char* cachedName = NULL;
    bool archiveOpen = false;
    bool locked = false;
    int fd = -1;
    int result = -1;

    /* Even if we're not going to look at the archive, we need to
     * open it so we can stuff it into ppJarFile.
     */
    if (dexZipOpenArchive(fileName, &archive) != 0){
		printf("in JarFile.cpp:208 open .jar false\n");
		goto bail;
	}
    archiveOpen = true;

    /* If we fork/exec into dexopt, don't let it inherit the archive's fd.
     */
    dvmSetCloseOnExec(dexZipGetArchiveFd(&archive));

    /* First, look for a ".odex" alongside the jar file.  It will
     * have the same name/path except for the extension.
     */
    fd = openAlternateSuffix(fileName, "odex", O_RDONLY, &cachedName);
    if (fd >= 0) {
		printf("ZHK in JarFile:233 Using alternate file (odex) for %s ...", fileName);
        ALOGV("Using alternate file (odex) for %s ...", fileName);
        // ZHKTODO
		if (false){//!dvmCheckOptHeaderAndDependencies(fd, false, 0, 0, true, true)) {
            printf("in JarFile.cpp:230 %s odex has stale dependencies\n", fileName);
			ALOGE("%s odex has stale dependencies", fileName);
            free(cachedName);
            cachedName = NULL;
            close(fd);
            fd = -1;
            goto tryArchive;
        } else {
			printf("%s odex has good dependencies\n", fileName);
            ALOGV("%s odex has good dependencies\n", fileName);
            //TODO: make sure that the .odex actually corresponds
            //      to the classes.dex inside the archive (if present).
            //      For typical use there will be no classes.dex.
        }
    } else {
        ZipEntry entry;

tryArchive:
		printf("in JarFile.cpp:247 tryArchive\n");
        /*
         * Pre-created .odex absent or stale.  Look inside the jar for a
         * "classes.dex".
         */
        entry = dexZipFindEntry(&archive, kDexInJarName);
		printf("in JarFile.cpp:253\n");
        if (entry != NULL) {
            bool newFile = false;

            /*
             * We've found the one we want.  See if there's an up-to-date copy
             * in the cache.
             *
             * On return, "fd" will be seeked just past the "opt" header.
             *
             * If a stale .odex file is present and classes.dex exists in
             * the archive, this will *not* return an fd pointing to the
             * .odex file; the fd will point into dalvik-cache like any
             * other jar.
             */
            if (odexOutputName == NULL) {
                cachedName = dexOptGenerateCacheFileName(fileName,
                                kDexInJarName);
                if (cachedName == NULL)
                    goto bail;
            } else {
                cachedName = strdup(odexOutputName);
            }
			printf("ZHK in JarFile:275 dvmJarFileOpen: Checking cache for %s (%s)\n",
				  fileName, cachedName);
            ALOGV("dvmJarFileOpen: Checking cache for %s (%s)",
                fileName, cachedName);
            fd = dvmOpenCachedDexFile(fileName, cachedName,
                    dexGetZipEntryModTime(&archive, entry),
                    dexGetZipEntryCrc32(&archive, entry),
                    isBootstrap, &newFile, /*createIfMissing=*/true);
			printf("ZHK in JarFile.cpp:284\n");
            if (fd < 0) {
				printf("ZHK in JarFile.cpp:290 Unable to open or create cache for %s (%s)\n",
					  fileName, cachedName);
                ALOGI("Unable to open or create cache for %s (%s)",
                    fileName, cachedName);
                goto bail;
            }
            locked = true;
			printf("ZHK in JarFile.cpp:292\n");
            /*
             * If fd points to a new file (because there was no cached version,
             * or the cached version was stale), generate the optimized DEX.
             * The file descriptor returned is still locked, and is positioned
             * just past the optimization header.
             */
            if (newFile) {
                u8 startWhen, extractWhen, endWhen;
                bool result;
                off_t dexOffset;

                dexOffset = lseek(fd, 0, SEEK_CUR);
                result = (dexOffset > 0);
				printf("ZHK in JarFile.cpp:306 result=%d\n", result);
                if (true) {
                    startWhen = dvmGetRelativeTimeUsec();
                    result = dexZipExtractEntryToFile(&archive, entry, fd) == 0;
                    extractWhen = dvmGetRelativeTimeUsec();
                }
				printf("ZHK in JarFile.cpp:315 \n");
                if (true) {
                    result = dvmOptimizeDexFile(fd, dexOffset,
                                dexGetZipEntryUncompLen(&archive, entry),
                                fileName,
                                dexGetZipEntryModTime(&archive, entry),
                                dexGetZipEntryCrc32(&archive, entry),
                                isBootstrap);
                }

                if (false) {
					printf("ZHK in JarFile:317 Unable to extract+optimize DEX from '%s'\n", fileName);
                    ALOGE("Unable to extract+optimize DEX from '%s'",
                        fileName);
                    goto bail;
                }
				printf("ZHK in JarFile.cpp:335 \n");
                endWhen = dvmGetRelativeTimeUsec();
				printf("ZHK in JarFile.cpp:337 DEX prep '%s': unzip in %dms, rewrite %dms\n",
					  fileName,
					  (int) (extractWhen - startWhen) / 1000,
					  (int) (endWhen - extractWhen) / 1000);
                ALOGD("DEX prep '%s': unzip in %dms, rewrite %dms",
                    fileName,
                    (int) (extractWhen - startWhen) / 1000,
                    (int) (endWhen - extractWhen) / 1000);
            }
        } else {
			printf("in JarFile.cpp:334 Zip is good, but no %s inside, and no valid .odex file in the same directory\n", kDexInJarName);
            ALOGI("Zip is good, but no %s inside, and no valid .odex "
                    "file in the same directory", kDexInJarName);
            goto bail;
        }
    }

    /*
     * Map the cached version.  This immediately rewinds the fd, so it
     * doesn't have to be seeked anywhere in particular.
     */
    if (dvmDexFileOpenFromFd(fd, &pDvmDex) != 0) {
		printf("ZHK inJarFile.cpp:350 Unable to map %s in %s\n", kDexInJarName, fileName);
        ALOGI("Unable to map %s in %s", kDexInJarName, fileName);
        goto bail;
    }

    if (locked) {
        /* unlock the fd */
        if (!dvmUnlockCachedDexFile(fd)) {
            /* uh oh -- this process needs to exit or we'll wedge the system */
            printf("in JarFile.cpp:359 Unable to unlock DEX file\n");
			ALOGE("Unable to unlock DEX file");
            goto bail;
        }
        locked = false;
    }
	printf("ZHK in JarFile.cpp:365 Successfully opened '%s' in '%s'\n", kDexInJarName, fileName);
    ALOGV("Successfully opened '%s' in '%s'", kDexInJarName, fileName);

    *ppJarFile = (JarFile*) calloc(1, sizeof(JarFile));
    (*ppJarFile)->archive = archive;
    (*ppJarFile)->cacheFileName = cachedName;
    (*ppJarFile)->pDvmDex = pDvmDex;
    cachedName = NULL;      // don't free it below
    result = 0;

bail:
	//printf("ZHK in Jarfile.cpp:376 bail\n");
    /* clean up, closing the open file */
    if (archiveOpen && result != 0)
        dexZipCloseArchive(&archive);
	//printf("ZHK in Jarfile.cpp:389 bail\n");
    free(cachedName);
	//printf("ZHK in Jarfile.cpp:391 bail\n");
    if (fd >= 0) {
        if (locked){
            // ZHKTODO
			//(void) dvmUnlockCachedDexFile(fd);
			printf("ZHK in Jarfile.cpp:393 bail\n");
		}
		printf("ZHK in Jarfile.cpp:395 bail\n");
        close(fd);
    }
	//printf("ZHK in Jarfile.cpp:395 bail\n");
    return result;
}

/*
 * Close a Jar file and free the struct.
 */
void dvmJarFileFree(JarFile* pJarFile)
{
    if (pJarFile == NULL)
        return;

    dvmDexFileFree(pJarFile->pDvmDex);
    dexZipCloseArchive(&pJarFile->archive);
    free(pJarFile->cacheFileName);
    free(pJarFile);
}
