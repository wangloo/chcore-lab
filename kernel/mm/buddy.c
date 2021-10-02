#include <common/util.h>
#include <common/macro.h>
#include <common/kprint.h>

#include "buddy.h"

void page_append(struct phys_mem_pool *pool, struct page *page) {
	struct free_list *free_list = &pool->free_lists[page->order];
	list_add(&page->node, &free_list->free_list);
	free_list->nr_free++;
}

void page_del(struct phys_mem_pool *pool, struct page *page) {
	struct free_list *free_list = &pool->free_lists[page->order];
	list_del(&page->node);
	free_list->nr_free--;
}

/*
 * The layout of a phys_mem_pool:
 * | page_metadata are (an array of struct page) | alignment pad | usable memory |
 *
 * The usable memory: [pool_start_addr, pool_start_addr + pool_mem_size).
 */
/* 
 * start_page: 页元数据区的起始地址（经过对齐）
 * start_addr: 页面区的起始地址
 */
 
void init_buddy(struct phys_mem_pool *pool, struct page *start_page,
		vaddr_t start_addr, u64 page_num)
{
	int order;
	struct page *page;

	/* Init the physical memory pool. */
	pool->pool_start_addr = start_addr;
	pool->page_metadata = start_page;
	/* 页面区的大小 = page_num * 页面大小 */
	pool->pool_mem_size = page_num * BUDDY_PAGE_SIZE;
	/* This field is for unit test only. */
	pool->pool_phys_page_num = page_num;

	/* Init the free lists */
	for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
		pool->free_lists[order].nr_free = 0;
		init_list_head(&(pool->free_lists[order].free_list));
	}
	
	
	/* Clear the page_metadata area. */
	//memset((char *)start_page, 0, page_num * sizeof(struct page));
	//kinfo("init page_meta OK!\n");

	/* 初始化页面元数据区，即初始化每个struct page */
	/* 初始设定了page_num个空闲页块，每个页块的order=0 */
	for (long page_idx = 0; page_idx < page_num; ++page_idx) {
		page = start_page + page_idx; /* 结构体指针+1 */
		page->allocated = 1; /* 标记已使用，才能进一步使用buddy_free_pages回收合并 */
		page->order = 0;
	}

	/* 合并回收所有页块 */
	for (long page_idx = 0; page_idx < page_num; ++page_idx) {
		page = start_page + page_idx;
		buddy_free_pages(pool, page);
	}
}


static struct page *get_buddy_chunk(struct phys_mem_pool *pool,
				    struct page *chunk)
{
	u64 chunk_addr;
	u64 buddy_chunk_addr;
	int order;

	/* Get the address of the chunk. */
	chunk_addr = (u64) page_to_virt(pool, chunk);
	order = chunk->order;
	/*
	 * Calculate the address of the buddy chunk according to the address
	 * relationship between buddies.
	 */
#define BUDDY_PAGE_SIZE_ORDER (12)
	buddy_chunk_addr = chunk_addr ^
	    (1UL << (order + BUDDY_PAGE_SIZE_ORDER));

	/* Check whether the buddy_chunk_addr belongs to pool. */
	if ((buddy_chunk_addr < pool->pool_start_addr) ||
	    (buddy_chunk_addr >= (pool->pool_start_addr +
				  pool->pool_mem_size))) {
		return NULL;
	}

	return virt_to_page(pool, (void *)buddy_chunk_addr);
}

/*
 * split_page: split the memory block into two smaller sub-block, whose order
 * is half of the origin page.
 * pool @ physical memory structure reserved in the kernel
 * order @ order for origin page block
 * page @ splitted page
 * 
 * Hints: don't forget to substract the free page number for the corresponding free_list.
 * you can invoke split_page recursively until the given page can not be splitted into two
 * smaller sub-pages.
 */
static struct page *split_page(struct phys_mem_pool *pool, u64 order,
			       struct page *page)
{
	// <lab2>

	if (page->allocated) {
		/* 只能拆分空闲块 */
		return NULL;
	}

	/* 递归的界限：分割出目标order的页块 */
	if (page->order == order) {	
		return page;
	}
    
	page->order--; 

	struct page *buddy_page = get_buddy_chunk(pool, page);

	if (buddy_page != NULL) {
		buddy_page->allocated = 0;
		buddy_page->order = page->order;
		page_append(pool, buddy_page);
	} 

	/* 递归调用 */
	return split_page(pool, order, page);
}

/*
 * buddy_get_pages: get free page from buddy system.
 * pool @ physical memory structure reserved in the kernel
 * order @ get the (1<<order) continous pages from the buddy system
 * 
 * Hints: Find the corresonding free_list which can allocate 1<<order
 * continuous pages and don't forget to split the list node after allocation   
 */
struct page *buddy_get_pages(struct phys_mem_pool *pool, u64 order)
{
#if 1
	// <lab2>
	struct page *page = NULL;
	struct page *splitted_page = NULL;
	struct list_head *free_node = NULL;
	u64    order_index = order;

	if (order > BUDDY_MAX_ORDER) {
		/* error */
		return NULL;
	}

	while (order_index < BUDDY_MAX_ORDER && pool->free_lists[order_index].nr_free == 0) {
		order_index++;
	}

	if (order_index >= BUDDY_MAX_ORDER) {
		/* not find, error */
		kwarn("invalid order\n");
	}

	free_node = pool->free_lists[order_index].free_list.next;
	splitted_page = list_entry(free_node, struct page, node);

	/* mark this page is unallocated temp and delete from corresonding list */
	splitted_page->allocated = 0;
	page_del(pool, splitted_page);

	page = split_page(pool, order, splitted_page);

	page->allocated = 1;
	//pool->free_lists[page->order].nr_free--;
	//list_del(&(page->node));

	return page;
	// </lab2>


#else

	// <lab2>
    // 找到一个非空的，最够大的 free_list
	int current_order = order;
	while (current_order < BUDDY_MAX_ORDER && pool->free_lists[current_order].nr_free <= 0)
		current_order++;
	
    // 申请的 order 太大或者没有足够大的块能分配
	if (current_order >= BUDDY_MAX_ORDER) {
		kwarn("Try to allocate an buddy chunk greater than BUDDY_MAX_ORDER");
		return NULL;
	}

    // 得到指定 free_list 的表头块
	struct page *page = list_entry(pool->free_lists[current_order].free_list.next, struct page, node);
	if (page == NULL){
		kdebug("buddy get a NULL page\n");
		return NULL;
	}

    // 分割块
	split_page(pool, order, page);
	
	// 将返回的块标记为已分配
	page->allocated = 1;
	return page;
	// </lab2>
#endif
}

/*
 * merge_page: merge the given page with the buddy page
 * pool @ physical memory structure reserved in the kernel
 * page @ merged page (attempted)
 * 
 * Hints: you can invoke the merge_page recursively until
 * there is not corresponding buddy page. get_buddy_chunk
 * is helpful in this function.
 */
static struct page *merge_page(struct phys_mem_pool *pool, struct page *page)
{
	// <lab2>

	if (page->allocated) {
		/* error: can't merge allocated pages */
		return NULL;
	}

	struct page *buddy_page = get_buddy_chunk(pool, page);

	/* 递归的界限：order不合法或伙伴页块不可用 */
	if (page->order == BUDDY_MAX_ORDER-1 || buddy_page == NULL || \
	    buddy_page->allocated || page->order != buddy_page->order) {
		
        /* 经过可能的合并操作确定了page的最终位置，
           此时再将页块加入相应链表 */
		page_append(pool, page);
		return page;
	}
	
    /* 其伙伴页块可以合并， 先要将其移除原来的空闲链表 */
	page_del(pool, buddy_page);	

    /* 统一page页块和其伙伴页块的相对位置关系 */
	/* | (page) | (buddy_page) | */
	if(page > buddy_page) {
		struct page *tmp = buddy_page;
		buddy_page = page;
		page = tmp;
	}
	/* 确保调整位置之后的伙伴页块是已分配的状态 */
	buddy_page->allocated = 1;
    
	page->order++;

	return merge_page(pool, page);
}

/*
 * buddy_free_pages: give back the pages to buddy system
 * pool @ physical memory structure reserved in the kernel
 * page @ free page structure
 * 
 * Hints: you can invoke merge_page.
 */
void buddy_free_pages(struct phys_mem_pool *pool, struct page *page)
{
	// <lab2>

	/* 空闲的块不需要回收 */
	if (!page->allocated) {
		return;
	}

	page->allocated = 0;

	/* join in proper free_list after merging the buddy pages */
	
	merge_page(pool, page);
	// </lab2>
}

void *page_to_virt(struct phys_mem_pool *pool, struct page *page)
{
	u64 addr;

	/* page_idx * BUDDY_PAGE_SIZE + start_addr */
	addr = (page - pool->page_metadata) * BUDDY_PAGE_SIZE +
	    pool->pool_start_addr;
	return (void *)addr;
}

struct page *virt_to_page(struct phys_mem_pool *pool, void *addr)
{
	struct page *page;

	page = pool->page_metadata +
	    (((u64) addr - pool->pool_start_addr) / BUDDY_PAGE_SIZE);
	return page;
}

u64 get_free_mem_size_from_buddy(struct phys_mem_pool * pool)
{
	int order;
	struct free_list *list;
	u64 current_order_size;
	u64 total_size = 0;

	for (order = 0; order < BUDDY_MAX_ORDER; order++) {
		/* 2^order * 4K */
		current_order_size = BUDDY_PAGE_SIZE * (1 << order);
		list = pool->free_lists + order;
		total_size += list->nr_free * current_order_size;

		/* debug : print info about current order */
		kdebug("buddy memory chunk order: %d, size: 0x%lx, num: %d\n",
		       order, current_order_size, list->nr_free);
	}
	return total_size;
}
