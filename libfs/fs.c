#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define FS_SIGNATURE "ECS150FS"
#define FAT_EOC 0xFFFF

struct __attribute__((packed)) superblock {
	char signature[8];
	uint16_t total_blocks;
	uint16_t root_dir_idx;
	uint16_t data_start_idx;
	uint16_t data_blocks;
	uint8_t fat_blocks;
	uint8_t padding[4079];
};

struct __attribute__((packed)) root_dir_entry {
	char filename[FS_FILENAME_LEN];
	uint32_t size;
	uint16_t first_block;
	uint8_t padding[10];
};

static int mounted = 0;
static struct superblock sb;
static uint16_t *fat = NULL;
static struct root_dir_entry *root_dir = NULL;

int fs_mount(const char *diskname)
{
	if (mounted)
		return -1;

	if (block_disk_open(diskname) < 0)
		return -1;

	if (block_read(0, &sb) < 0) {
		block_disk_close();
		return -1;
	}

	if (memcmp(sb.signature, FS_SIGNATURE, 8) != 0) {
		block_disk_close();
		return -1;
	}

	int disk_blocks = block_disk_count();
	if (disk_blocks < 0 || disk_blocks != sb.total_blocks) {
		block_disk_close();
		return -1;
	}

	fat = malloc(sb.fat_blocks * BLOCK_SIZE);
	if (!fat) {
		block_disk_close();
		return -1;
	}

	for (int i = 0; i < sb.fat_blocks; i++) {
		if (block_read(i + 1, (char *)fat + (i * BLOCK_SIZE)) < 0) {
			free(fat);
			block_disk_close();
			return -1;
		}
	}

	root_dir = malloc(BLOCK_SIZE);
	if (!root_dir) {
		free(fat);
		block_disk_close();
		return -1;
	}

	if (block_read(sb.root_dir_idx, root_dir) < 0) {
		free(root_dir);
		free(fat);
		block_disk_close();
		return -1;
	}

	mounted = 1;
	return 0;
}

int fs_umount(void)
{
	if (!mounted)
		return -1;

	free(fat);
	free(root_dir);
	fat = NULL;
	root_dir = NULL;

	if (block_disk_close() < 0)
		return -1;

	mounted = 0;
	return 0;
}

int fs_info(void)
{
	if (!mounted)
		return -1;

	int free_blocks = 0;
	for (int i = 0; i < sb.data_blocks; i++) {
		if (fat[i] == 0)
			free_blocks++;
	}

	int file_count = 0;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] != '\0')
			file_count++;
	}

	printf("FS Info:\n");
	printf("total_blk_count=%d\n", sb.total_blocks);
	printf("fat_blk_count=%d\n", sb.fat_blocks);
	printf("rdir_blk=%d\n", sb.root_dir_idx);
	printf("data_blk=%d\n", sb.data_start_idx);
	printf("data_blk_count=%d\n", sb.data_blocks);
	printf("fat_free_ratio=%d/%d\n", free_blocks, sb.data_blocks);
	printf("rdir_free_ratio=%d/%d\n", FS_FILE_MAX_COUNT - file_count, FS_FILE_MAX_COUNT);

	return 0;
}


int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_ls(void)
{
	/* TODO: Phase 2 */
}

int fs_open(const char *filename)
{
	/* TODO: Phase 3 */
}

int fs_close(int fd)
{
	/* TODO: Phase 3 */
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}
