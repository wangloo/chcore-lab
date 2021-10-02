#include "minunit.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#undef PAGE_SHIFT
#undef PAGE_SIZE

#include <common/mmu.h>

#undef phys_to_virt
#undef virt_to_phys
#define phys_to_virt(x) ((u64)x)
#define virt_to_phys(x) ((u64)x)

void *get_pages(int order)
{
	void *ptr;
	int err = posix_memalign(&ptr, 0x1000, 0x1000);
	if (err)
		return NULL;
	return ptr;
}

void free_page(void *page)
{
	mu_assert(page != NULL, "Freeing nullptr!");
	free(page);
}

#include "../../../kernel/mm/page_table.c"

void set_ttbr0_el1(paddr_t p)
{
}

void flush_tlb()
{
}

void printk(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

#define RND_MAPPING_PAGES (10000)
#define RND_VA_MAX (0x10000000)
#define RND_PA_MAX (0x10000000)
#define RND_SEED (1024)
#define DEFAULT_FLAGS (3)
#define ALTER_FLAGS (4)

static inline u64 rand_addr(u64 max)
{
	return (rand() % 0x10000) * (rand() % 0x10000) % max;
}

static inline u64 rand_page_addr(u64 max)
{
	u64 ret;

	do {
		ret = rand_addr(max) & (~PAGE_MASK);
	} while (ret == 0);
	return ret;
}

void test_page_mappings(vaddr_t * pgtbl, paddr_t * pas,
			vaddr_t * vas, int nr_pages)
{
	paddr_t pa;
	vaddr_t va;
	vmr_prop_t flags;
	int err;
	int i;
	int j;
	pte_t *entry;
	/* Query all pages  */
	for (i = 0; i < nr_pages; i++) {
		if (!vas[i])
			continue;
		err = query_in_pgtbl(pgtbl, vas[i], &pa, &entry);
		if (err != 0) {
			printf("vas[i]=%llx\n", (u64) vas[i]);
			exit(-1);
		}
		mu_assert_int_eq(0, err);
		if (pa != pas[i]) {
			printf("pa=0x%llx pas[i]=0x%llx\n", pa, pas[i]);
		}
		mu_check(pa == pas[i]);
	}

	/* Generate some VAs and query them */
	for (i = 0; i < nr_pages; i++) {
		va = rand_page_addr(RND_VA_MAX);
		err = query_in_pgtbl(pgtbl, va, &pa, &entry);
		for (j = 0; j < RND_MAPPING_PAGES; j++) {
			if (vas[j] != va)
				continue;
			mu_assert_int_eq(0, err);
			mu_check(pa == pas[j]);
			break;
		}
		if (j == RND_MAPPING_PAGES)
			mu_assert_int_eq(-ENOMAPPING, err);
	}
}

MU_TEST(test_map_unmap_page)
{
	/* Test both map_apge and unmap_page. */
	int err;
	paddr_t pa;
	vaddr_t va;
	vmr_prop_t flags;
	vaddr_t *root;
	pte_t *entry;

	paddr_t *pas;
	vaddr_t *vas;
	int i;
	int j;


	/* init vmspace */
	// err = init_vmspace(&space);
	//root = calloc(PAGE_SIZE, 1);
	root = get_pages(0);	/* 分配4K对齐的大小为4KB的内存地址 */
	// mu_assert_int_eq(0, err);

	/* 刚分配的页表root无内容，所以查询va对应的pa一定会触发error */
	printf("testing function 'query_in_pgtbl'...\n");
	va = 0x100000;
	err = query_in_pgtbl(root, va, &pa, &entry);
	printf("err = %d\n", err);
	mu_assert_int_eq(-ENOMAPPING, err);

	/* 在 [va, va+PAGE_SIZE] 到 [pa, pa+PAGE_SIZE] 之间建立映射 */
	printf("testing function 'map_range_in_pgtbl'...\n");
	err = map_range_in_pgtbl(root, va, 0x100000, PAGE_SIZE, DEFAULT_FLAGS);
	printf("err = %d\n", err);
	mu_assert_int_eq(0, err);

	/* 映射建立之后，再去查找va对应的pa，结果应该是0x100000 */
	printf("testing function 'query_in_pgtbl'...\n");
	err = query_in_pgtbl(root, va, &pa, &entry);
	printf("err = %d\n", err);
	printf("pa = 0x%llx\n", pa);
	mu_assert_int_eq(0, err);
	mu_check(pa == 0x100000);
	// mu_check(flags == DEFAULT_FLAGS);

	/* 测试取消va的映射关系 */
	printf("testing function 'unmap_range_in_pgtbl'...\n");
	err = unmap_range_in_pgtbl(root, va, PAGE_SIZE);
	printf("err = %d\n", err);
	mu_assert_int_eq(0, err);

	/* 取消映射后，再查找va对应的pa一定是出错的 */
	printf("testing function 'query_in_pgtbl'...\n");
	err = query_in_pgtbl(root, va, &pa, &entry);
	printf("err = %d\n", err);
	mu_assert_int_eq(-ENOMAPPING, err);

	srand(RND_SEED);
	vas = malloc(sizeof(*vas) * RND_MAPPING_PAGES);
	pas = malloc(sizeof(*pas) * RND_MAPPING_PAGES);
	/* Generate and map all pages */
	for (i = 0; i < RND_MAPPING_PAGES; i++) {
 rerand:
		vas[i] = rand_page_addr(RND_VA_MAX);
		pas[i] = rand_page_addr(RND_PA_MAX);
		for (j = 0; j < i; j++) {
			if (vas[i] == vas[j])
				goto rerand;
		}
		printf("map: 0x%llx -> 0x%llx\n", vas[i], pas[i]);
		err = map_range_in_pgtbl(root, vas[i], pas[i], PAGE_SIZE,
					 DEFAULT_FLAGS);
		mu_assert_int_eq(0, err);
	}

	test_page_mappings(root, pas, vas, RND_MAPPING_PAGES);

	/* Unmap some pages */
	for (i = 0; i < RND_MAPPING_PAGES; i++) {
		if (rand() & 1)
			continue;
		printf("unmap: 0x%llx -> 0x%llx\n", vas[i], pas[i]);
		err = unmap_range_in_pgtbl(root, vas[i], PAGE_SIZE);
		mu_assert_int_eq(0, err);
		vas[i] = 0;
		pas[i] = 0;
	}

	test_page_mappings(root, pas, vas, RND_MAPPING_PAGES);

	/* Unmap remaining pages */
	for (i = 0; i < RND_MAPPING_PAGES; i++) {
		if (!vas[i])
			continue;
		printf("unmap: 0x%llx -> 0x%llx\n", vas[i], pas[i]);
		err = unmap_range_in_pgtbl(root, vas[i], PAGE_SIZE);
		mu_assert_int_eq(0, err);
		vas[i] = 0;
		pas[i] = 0;
	}
	test_page_mappings(root, pas, vas, RND_MAPPING_PAGES);

	/* destroy vmspace */
	free(root);
}

MU_TEST_SUITE(test_suite)
{
	MU_RUN_TEST(test_map_unmap_page);
}

int main(int argc, char *argv[])
{
	// printf("pa =================== %llx\n", (u64)pa);
	
	MU_RUN_SUITE(test_suite);
	MU_REPORT();
	return minunit_status;
}
