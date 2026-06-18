// Vulnerable: VUL-CVE-2017-14749
* End of list marker.
 */
#define JMEM_HEAP_END_OF_LIST ((jmem_heap_free_t *const) ~((uint32_t) 0x0))

#if UINTPTR_MAX > UINT32_MAX
...

  region_p->size = JMEM_HEAP_AREA_SIZE;
  region_p->next_offset = JMEM_HEAP_GET_OFFSET_FROM_ADDR (JMEM_HEAP_END_OF_LIST);

  JERRY_HEAP_CONTEXT (first).size = 0;
...
      current_p = JMEM_HEAP_GET_ADDR_FROM_OFFSET (next_offset);
    }
  }
