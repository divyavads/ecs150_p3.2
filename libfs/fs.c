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

#define FS_MAX_FD 32

struct file_descriptor {
	int in_use;
	char filename[FS_FILENAME_LEN];
	size_t offset;
};

static struct file_descriptor fd_table[FS_MAX_FD] = {0};

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
	if (!mounted || !filename)
		return -1;

	if (strlen(filename) == 0 || strlen(filename) > FS_FILENAME_LEN)
		return -1;

	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] != '\0' && 
			strcmp(root_dir[i].filename, filename) == 0) {
			return -1;
		}
	}

	int slot = -1;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] == '\0') {
			slot = i;
			break;
		}
	}

	if (slot == -1)
		return -1;
	memset(&root_dir[slot], 0, sizeof(struct root_dir_entry));
	strncpy(root_dir[slot].filename, filename, FS_FILENAME_LEN);
	root_dir[slot].size = 0;
	root_dir[slot].first_block = FAT_EOC;
	if (block_write(sb.root_dir_idx, root_dir) < 0)
		return -1;

	return 0;
}

int fs_delete(const char *filename)
{
	if (!mounted || !filename)
		return -1;
	int slot = -1;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] != '\0' && 
			strcmp(root_dir[i].filename, filename) == 0) {
			slot = i;
			break;
		}
	}

	if (slot == -1)
		return -1;
	uint16_t current_block = root_dir[slot].first_block;
	while (current_block != FAT_EOC) {
		uint16_t next_block = fat[current_block];
		fat[current_block] = 0;  // Mark as free
		current_block = next_block;
	}
	for (int i = 0; i < sb.fat_blocks; i++) {
		if (block_write(i + 1, (char *)fat + (i * BLOCK_SIZE)) < 0)
			return -1;
	}
	memset(&root_dir[slot], 0, sizeof(struct root_dir_entry));
	if (block_write(sb.root_dir_idx, root_dir) < 0)
		return -1;

	return 0;
}

int fs_ls(void)
{
	if (!mounted)
		return -1;

	printf("FS Ls:\n");
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] != '\0') {
			printf("file: %s, size: %d, data_blk: %d\n",
				   root_dir[i].filename,
				   root_dir[i].size,
				   root_dir[i].first_block);
		}
	}
	return 0;
}

int fs_open(const char *filename)
{
	if (!mounted || !filename)
		return -1;
	int slot = -1;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] != '\0' && 
			strcmp(root_dir[i].filename, filename) == 0) {
			slot = i;
			break;
		}
	}
	if (slot == -1)
		return -1;
	int fd = -1;
	for (int i = 0; i < FS_MAX_FD; i++) {
		if (!fd_table[i].in_use) {
			fd = i;
			break;
		}
	}
	if (fd == -1)
		return -1;

	fd_table[fd].in_use = 1;
	strncpy(fd_table[fd].filename, filename, FS_FILENAME_LEN);
	fd_table[fd].offset = 0;

	return fd;
}

int fs_close(int fd)
{
	if (!mounted || fd < 0 || fd >= FS_MAX_FD || !fd_table[fd].in_use)
		return -1;

	fd_table[fd].in_use = 0;
	return 0;
}

int fs_stat(int fd)
{
	if (!mounted || fd < 0 || fd >= FS_MAX_FD || !fd_table[fd].in_use)
		return -1;

	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] != '\0' && 
			strcmp(root_dir[i].filename, fd_table[fd].filename) == 0) {
			return root_dir[i].size;
		}
	}

	return -1;
}

int fs_lseek(int fd, size_t offset)
{
	if (!mounted || fd < 0 || fd >= FS_MAX_FD || !fd_table[fd].in_use)
		return -1;

	size_t file_size = 0;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] != '\0' && 
			strcmp(root_dir[i].filename, fd_table[fd].filename) == 0) {
			file_size = root_dir[i].size;
			break;
		}
	}

	if (file_size == 0)
		return -1;

	if (offset > file_size)
		return -1;

	fd_table[fd].offset = offset;
	return 0;
}

/* Helper function to get index of data block */
int get_data_block_index(uint16_t start_block, size_t offset){
	size_t skip = offset / BLOCK_SIZE;
	uint16_t curr = start_block;

	while(skip > 0 && curr != FAT_EOC){
		curr = fat[curr];
		skip--;
	}

	if(curr == FAT_EOC){
		return -1;
	}

	return curr;
}

/* Helper function to allocate new data block */
int allocate_new_block(uint16_t *last){
	for(int i = 0; i < sb.data_blocks; i++){
		if(fat[i] == 0){
			fat[i] = FAT_EOC;
			if(*last != FAT_EOC){
				fat[*last] = i;
			}
			*last = i;
			return i;
		}
	}

	return -1;
}
int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
	// /*Placeholder to remove warning*/
	// if(count == 0) return 0;
	// if(!buf) return -1;
	// return fd;

	if(!mounted || fd < 0 || fd >= FS_MAX_FD || !fd_table[fd].in_use || buf == NULL){
		return -1;
	}

	struct file_descriptor *file = &fd_table[fd];
	struct root_dir_entry *entry = NULL;
	for(int i = 0; i < FS_FILE_MAX_COUNT; i++){
		if(strncmp(root_dir[i].filename, file->filename, FS_FILENAME_LEN) == 0){
			entry = &root_dir[i];
			break;
		}
	}

	if(!entry){
		return -1;
	}

	size_t bytes_written = 0;
	const char *char_buf = (const char *)buf;
	char block_buf[BLOCK_SIZE];
	uint16_t last;
	
	if(entry->first_block == FAT_EOC){
		
		if(allocate_new_block(&last) == -1){
			return -1;
		}
		entry->first_block = last;
	}

	

	while(fat[last] != FAT_EOC){
		last = fat[last];
	}

	while(bytes_written < count){
		int block_index = get_data_block_index(entry->first_block, file->offset);

		if(block_index == -1){
			

			if(allocate_new_block(&last) == -1){
				break;
			}

			block_index = last;
			
		}

		block_read(sb.data_start_idx + block_index, block_buf);
		size_t block_offset = file->offset % BLOCK_SIZE;
		size_t to_write = BLOCK_SIZE - block_offset;


		if(to_write > count - bytes_written){
			to_write = count - bytes_written;
		}


		memcpy(block_buf + block_offset, char_buf + bytes_written, to_write);
		block_write(sb.data_start_idx + block_index, block_buf);

		file->offset += to_write;
		bytes_written += to_write;

	
	}

	if(file->offset > entry->size){
		entry->size = file->offset;
	}

	

	return bytes_written;


}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
	// 	/*Placeholder to remove warning*/
	// 	if(count == 0) return 0;
	// 	if(!buf) return -1;
	// 	return fd;

	if(!mounted || fd < 0 || fd >= FS_MAX_FD || !fd_table[fd].in_use || buf == NULL){
		return -1;
	}

	struct file_descriptor *file = &fd_table[fd];
	struct root_dir_entry *entry = NULL;

	for(int i = 0; i < FS_FILE_MAX_COUNT; i++){
		if(strncmp(root_dir[i].filename, file->filename, FS_FILENAME_LEN) == 0){
			entry = &root_dir[i];
			break;
		}
	}

	if(!entry){
		return -1;
	}

	if(file->offset >= entry->size){
		return 0;
	}

	if(file->offset + count > entry->size){
		count = entry->size - file->offset;
	}

	size_t bytes_read = 0;
	char *char_buf = (char *)buf;
	char block_buf[BLOCK_SIZE];


	while(bytes_read < count){
		int block_index = get_data_block_index(entry->first_block, file->offset);
		if(block_index == -1){
			break;
		}

		block_read(sb.data_start_idx + block_index, block_buf);
		size_t block_offset = file->offset % BLOCK_SIZE;
		size_t to_read = BLOCK_SIZE - block_offset;

		if(to_read > count - bytes_read){
			to_read = count - bytes_read;
		}

		memcpy(char_buf + bytes_read, block_buf + block_offset, to_read);

		file->offset += to_read;
		bytes_read += to_read;


	}


	return bytes_read;

}
