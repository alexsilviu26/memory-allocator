// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <errno.h>

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#include "../utils/block_meta.h"
#include "../utils/osmem.h"
#include "../utils/printf.h"

/* MMAP and SBRK defines*/
#define PROT_READ 0x1
#define PROT_WRITE 0x2

/* Sharing types*/
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MIN_BLOCK_SIZE 1
#define PAGE_SIZE (4 * 1024)
#define MMAP_THRESHOLD (128 * 1024)

/* Struct block_meta defines */
#define ALIGNMENT 8 // must be a power of 2
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

static struct block_meta *start;
static size_t treshold = MMAP_THRESHOLD;
static int status = STATUS_FREE;

void coalesce(struct block_meta **block)
{
    if ((*block)->next != NULL) {
        if ((*block)->next->status == STATUS_FREE) {
            size_t size = (*block)->next->size + sizeof(struct block_meta);
            (*block)->size += size;
            (*block)->next = (*block)->next->next;

            if ((*block)->next != NULL)
                (*block)->next->prev = (*block);
        }
    }
    if ((*block)->prev != NULL) {
        if ((*block)->prev->status == STATUS_FREE) {
            size_t size = (*block)->size + sizeof(struct block_meta);
            (*block)->prev->size += size;
            (*block)->prev->next = (*block)->next;

            if ((*block)->next != NULL)
                (*block)->next->prev = (*block)->prev;
        }
    }
}

void coalesce_all(void)
{
	struct block_meta *curr = start;

	for (curr = start; curr != NULL; curr = curr->next) {
		if (curr->status == STATUS_FREE)
			coalesce(&curr);
	}
}

void split_block(struct block_meta **block, size_t size)
{
	size_t size_mem_block = ALIGN(size) + sizeof(struct block_meta);

	if ((*block)->size >= size_mem_block + ALIGN(MIN_BLOCK_SIZE)) {
		struct block_meta *new_block = (struct block_meta *)((void *)(*block) + size_mem_block);
		size_t dimension = (*block)->size - size_mem_block;

		new_block->status = STATUS_FREE;
		new_block->size = dimension;
		new_block->next = (*block)->next;
		new_block->prev = (*block);
		(*block)->status = STATUS_ALLOC;
		(*block)->size = ALIGN(size);
		(*block)->next = new_block;
	}
	if ((*block)->size < size_mem_block + ALIGN(MIN_BLOCK_SIZE))
		(*block)->status = STATUS_ALLOC;
}

struct block_meta *find_fit(struct block_meta **last, size_t size)
{
	struct block_meta *curr = start;

	for (curr = start; curr != NULL; curr = curr->next) {
		if (curr->status == STATUS_FREE && curr->size >= size)
			break;
		*last = curr;
	}
	return curr;
}

void *heap_prealloc(size_t size)
{
	void *mem = sbrk(size);
	struct block_meta *aux = (struct block_meta *)mem;

	if (mem == (void *)-1) {
		DIE(mem == (void *)-1, "HEAP PREALLOCATION FAILED");
		return NULL;
	}
	start = aux;
	size_t dimension = size - sizeof(struct block_meta);

	start->size = dimension;
	start->status = STATUS_ALLOC;
	start->prev = NULL;
	start->next = NULL;

	void *payload = (void *)start + sizeof(struct block_meta);

	return payload;
}

void *extend_block(struct block_meta *block, size_t size)
{
	size_t dimension = ALIGN(size) - block->size;
	void *mem = sbrk(dimension);

	if (mem == (void *)-1) {
		DIE(mem == (void *)-1, "EXTEND BLOCK FAILED");
		return NULL;
	}

	block->status = STATUS_ALLOC;
	block->size = ALIGN(size);
	return mem;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (size == 0)
		return NULL;

	size_t size_block_meta = ALIGN(size);
	size_t size_mem_block = size_block_meta + sizeof(struct block_meta);

	if (treshold >= size_mem_block) {
		if (status == STATUS_FREE) {
			void *mem = heap_prealloc(MMAP_THRESHOLD);

			if (mem == NULL)
				return NULL;

			status = STATUS_ALLOC;

			return mem;
		}
		if (status == STATUS_ALLOC) {
			struct block_meta *last = start;
			struct block_meta *block = find_fit(&last, size_block_meta);

			if (block != NULL) {
				split_block(&block, size);

				void *payload = (void *)block + sizeof(struct block_meta);

				return payload;
			}
			if (block == NULL) {
				if (last->status == STATUS_FREE) {
					void *mem = extend_block(last, size);

					if (mem == NULL)
						return NULL;

					void *payload = (void *)last + sizeof(struct block_meta);

					return payload;
				}

				void *mem = sbrk(size_mem_block);

				if (mem == (void *)-1) {
					DIE(mem == (void *)-1, "MALLOC FAILED");
					return NULL;
				}
				struct block_meta *aux = (struct block_meta *)mem;

				block = aux;
				block->size = size_block_meta;
				block->status = STATUS_ALLOC;
				block->prev = last;
				block->next = NULL;
				last->next = block;

				void *payload = (void *)block + sizeof(struct block_meta);

				return payload;
			}
		}
	}
	if (size_mem_block > treshold) {
		void *mem = mmap(NULL, size_mem_block, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (start == NULL)
			start = (struct block_meta *)mem;

		struct block_meta *block = (struct block_meta *)mem;

		block->size = size_block_meta;
		block->status = STATUS_MAPPED;
		block->prev = NULL;
		block->next = NULL;

		void *payload = (void *)block + sizeof(struct block_meta);

		return payload;
	}
	return NULL;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL)
		return;

	struct block_meta *block = (struct block_meta *)((void *)ptr - sizeof(struct block_meta));

	if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
		coalesce_all();
	}
	if (block->status == STATUS_MAPPED) {
		block->status = STATUS_FREE;
		munmap(block, block->size + sizeof(struct block_meta));
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */

	if (nmemb == 0)
		return NULL;
	if (size == 0)
		return NULL;

	size_t total_size = size * nmemb;

	treshold = PAGE_SIZE;
	void *mem = os_malloc(total_size);

	status = STATUS_ALLOC;
	if (mem == NULL)
		return NULL;

	treshold = MMAP_THRESHOLD;
	memset(mem, 0, total_size);
	return mem;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */

	if (ptr == NULL) {
		void *new = os_malloc(size);
		return new;
	}
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = (struct block_meta *)((void *)ptr - sizeof(struct block_meta));
	size_t size_block_meta = ALIGN(size);

	coalesce_all();

	if (block->status == STATUS_MAPPED) {
		void *new_mem = os_malloc(size);

		if (new_mem == NULL) {
			DIE(new_mem == NULL, "REALLOC FAILED");
			return NULL;
		}
		if (size_block_meta > block->size)
			memcpy(new_mem, ptr, block->size);
		if (size_block_meta <= block->size)
			memcpy(new_mem, ptr, size_block_meta);
		os_free(ptr);
		return new_mem;
	}
	if (block->status == STATUS_ALLOC) {
		if (block->size >= size_block_meta) {
			split_block(&block, size);
			return ptr;
		}
		if (block->next == NULL) {
			void *new_mem = extend_block(block, size);

			if (new_mem == NULL)
				return NULL;

			return ptr;
		}

		if (block->next->status == STATUS_FREE) {
			size_t dimension = block->size + block->next->size + sizeof(struct block_meta);

			if (dimension >= size_block_meta) {
				coalesce(&block);
				split_block(&block, size);
				return ptr;
			}
		}

		if (size_block_meta > block->size) {
			void *new_mem = os_malloc(size);

			if (new_mem == NULL)
				return NULL;
			if (new_mem != NULL) {
				memcpy(new_mem, ptr, block->size);
			os_free(ptr);
			return new_mem;
			}
		}
	}
	return NULL;
}
