#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define DEFAULT_MEM_SIZE 1<<20

/* Basic constants and macros */
#define WSIZE	4	 /* Word and header/footer size (bytes) */
#define DSIZE	8	/* Double word size (bytes) */
	
#define MAX(x, y) ((x) > (y)? (x) : (y))
	
/* Combine a size and allocated bit to pack into a word storable in header/footer*/
#define PACK(size, alloc) ((size)	|	(alloc))
	
/* Read and write a word at address p */
#define GET1(p)	(* (unsigned int *)(p))
#define PUT1(p, val)		(*(unsigned int *)(p) = (val))
	
/* Read the size and allocated fields from address p */
#define GET_SIZE(p)	(GET1(p) & ~0x7)
#define GET_ALLOC(p)	(GET1(p) & 0x1)
	
/* Given block ptr bp, compute address of its header and footer */
#define HDRP(bp)	((char *) (bp) - WSIZE)
#define FTRP(bp)	((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)
	
/* Given block ptr bp, compute address of next and previous blocks */
#define NEXT_BLKP(bp)	((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE)))
#define PREV_BLKP(bp)	((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE)))

/* Declaring types */
typedef void *any_t;
typedef char *addrs_t;

addrs_t baseptr;    

/* HEAPCHECKER VARIABLES*/   
int allocated_blocks = 0;  
int free_blocks = 0;
size_t raw_alloc = 0;
size_t padded_alloc = 0;
size_t raw_free;
size_t aligned_free = 0;
int Malloc_calls = 0;
int Free_calls = 0;
int failed_calls = 0;
size_t passed_size = 0;
size_t M1_size = 0;
size_t padded_bytes = 0;
int calls = 0;

/////////////////////////////////////////PA31/////////////////////////////////////////////
/* Use the system malloc() routine to allocate size bytes for the initial memory area, M1 */
void Init (size_t size) 
{
    size_t psize = size - (6 * WSIZE);                                /* Payload size */

    baseptr = (addrs_t)malloc(size);                                  /* starting address of M1 */ 
    PUT1(baseptr, 0);                                                  /* Alignment padding */ 
    PUT1(baseptr + (1 * WSIZE), PACK(DSIZE, 1));                       /* Prologue header */ 
    PUT1(baseptr + (2 * WSIZE), PACK(DSIZE, 1));                       /* Prologue footer */
    PUT1(baseptr + (3 * WSIZE), PACK(psize + DSIZE, 0));               /* Payload header */
    PUT1(baseptr + psize + (4 * WSIZE), PACK(psize + DSIZE, 0));       /* Payload footer */
    PUT1(baseptr + size - WSIZE, PACK(0, 1));                          /* Epilogue header */
    baseptr += (4 * WSIZE);                                           /* Payload pointer */ 
    
    /* HEAP CHECKER VARIABLES*/
    passed_size = (size - (4 * WSIZE)) / (2 * DSIZE);
    raw_free = size - (3 * WSIZE);
    M1_size = size;
    padded_bytes += (3 * WSIZE);
}   

/* Find a fit for a block with asize bytes */
void *find_first_fit (size_t asize)
{
	/* First fit search */
	addrs_t bp;

  //loops through heap block to block
	for (bp = baseptr; GET_SIZE (HDRP (bp)) > 0; bp = NEXT_BLKP (bp)) 
    {
    //if block free and payload size less than block size return block addrs
		if (!GET_ALLOC (HDRP (bp)) && (asize <= GET_SIZE (HDRP (bp)))) 
        {
			return bp;
		}
	}
	return NULL;				/* No fit return NULL*/
}

/* Place block of asize bytes at start of free block bp 
 * and split if remainder would be at least minimum block size */
void place (addrs_t bp, size_t asize)
{
  //size of block bp
	size_t csize = GET_SIZE (HDRP (bp));

  //if size of block - size of payload >= 16 bytes (min size of block)                                                           
	if ((csize - asize) >= (2 * DSIZE)) 
    {
    //designate size of payload as allocated and remaining block (size of block - size of payload) as free
		PUT1 (HDRP (bp), PACK (asize, 1));
		PUT1 (FTRP (bp), PACK (asize, 1));
		bp = NEXT_BLKP (bp);
		PUT1 (HDRP (bp), PACK (csize - asize, 0));
		PUT1 (FTRP (bp), PACK (csize - asize, 0));
	}
	else 
    {
    //designate entire block as allocated (with any extra space as padding)
		PUT1 (HDRP (bp), PACK (csize, 1));
		PUT1 (FTRP (bp), PACK (csize, 1));
	}
}

/*Implement your own memory allocation routine here.
  This should allocate the first contiguous size bytes available in M1.
  Since some machine architectures are 64-bit, it should be safe to allocate space starting
  at the first address divisible by 8. Hence align all addresses on 8-byte boundaries!

  If enough space exists, allocate space and return the base address of the memory.
  If insufficient space exists, return NULL
*/
addrs_t Malloc (size_t size) 
{
    size_t asize;	/* Adjusted block size */
    addrs_t bp;
    Malloc_calls++;
    /* if size is not an allocatable value or is greater than heap size return NULL */
    if(size <= 0 || size > DEFAULT_MEM_SIZE)                                               
    {
        failed_calls++;
        return NULL;
      
    }

	/* Adjust block size to include overhead and alignment reqs. */      
    //if size <= 8, asize = 16 (min block size)                     
	if (size <= DSIZE)    
    {
        asize = 2*DSIZE; 
    }                                                                    
    //size > 8, asize =  ((size + 15)/8)*8 = size + padding, which is then aligned                                                                     
	else
    {
        asize = DSIZE * ((size + (DSIZE) + (DSIZE-1)) / DSIZE);
        padded_bytes += asize - size;
    }

	/* Search the free list for a fit */
    //if there is a fit, place payload into block, then return block address 
	if((bp = find_first_fit(asize)) != NULL) 
    {
		place(bp, asize);
        allocated_blocks++;
        raw_alloc += size;
        padded_alloc += asize;
        raw_free -= size;
		return bp;
	}
    //if not fit, return NULL
    else
    {
      failed_calls++;
      return NULL;
    }
    
}

/* This frees the previously allocated size bytes starting from address addr in the
    memory area, M1. You can assume the size argument is stored in a data structure after
    the Malloc() routine has been called, just as with the UNIX free() command
*/
static void *coalesce(void *bp)                                                              
{
    //GET allocation status of previous block
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    //GET allocation status of next block
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    //size of block bp
    size_t size = GET_SIZE(HDRP(bp));
	
    /* Case 1: both previous and next blocks allocated, don't coalesce */
    if (prev_alloc && next_alloc)  
    {			
        return bp;
    }
    /* Case 2: previous allocated and next free */                             
    else if (prev_alloc && !next_alloc) 
    {		
        //combine size of block bp with next block
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        //place size info into header of bp and footer of next 
        PUT1(HDRP(bp), PACK(size, 0));
        PUT1 (FTRP(NEXT_BLKP(bp)), PACK(size,0));
    }
    /* Case 3: previous free and next allocated */
    else if (!prev_alloc && next_alloc)  
    {		
        //combine size of block bp with previous block
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        //place size info into header of previous and footer of bp 
        PUT1(FTRP(bp), PACK(size, 0));
        PUT1(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        //move bp pointer to previous
        bp = PREV_BLKP(bp);
    }
	/* Case 4: both previous and next free */
    else  
    {		
        //combine size of block bp, previous, next				
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp)));
        //place size info into header of previous and footer of next
        PUT1(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        PUT1(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
        //move bp pointer to previous
        bp = PREV_BLKP(bp);
    }
    return bp;
}

void Free (addrs_t addr)
{
    //checks if addr already free
    if(!GET_ALLOC(HDRP(addr)))
    {
        failed_calls--;
        return;
    }
    //size of addr
    size_t size = GET_SIZE(HDRP(addr)); 
    //frees up header and footer of addr
    PUT1(HDRP(addr), PACK(size, 0));
    PUT1(FTRP(addr), PACK(size, 0));
    coalesce(addr);
    allocated_blocks--;
    raw_alloc -= (size - (2 * WSIZE));
    padded_alloc -= size;
    raw_free += (size - (2 * WSIZE));
    Free_calls++;
    padded_bytes -= (2 * WSIZE);
    if(GET_ALLOC(HDRP(addr)))
    {
        failed_calls--;
    }
}

/*Allocate size bytes from M1 using Malloc(). Copy size bytes of data into Malloc'd memory.
  You can assume data is a storage area outside M1.
  Return starting address of data in Malloc'd memory
*/
addrs_t Put (any_t data, size_t size)
{
    //GET start addr from Malloc
    addrs_t start = Malloc(size);
    //if start addr not NULL, move in data and return addr
    if(start != NULL)
    {
        memcpy(start, data, size);
        if(call < 3)
        {
            heap_checker();
        }
        return start;   
    }
    if(call < 3)
    {
      heap_checker();
    }
    return NULL; //0?
}

/*Copy size bytes from addr in the memory area, M1, to data address.
    As with Put(), you can assume data is a storage area outside M1.
    De-allocate size bytes of memory starting from addr using Free()
*/
void GET (any_t return_data, addrs_t addr, size_t size)
{
    //GET data from addr and input into return_data 
    memcpy(return_data, addr, size);
    Free(addr);  
    if(call < 3)
    {
      heap_checker();
    }  
}

/////////////////////////////////////////PA32/////////////////////////////////////////////

/* Declaring Variables */      
int allocated_blocks = 0;             
int num_VM_success = 0;                                         /* tracks # of times mem successfully allocated NOT current # of allocated blocks */
addrs_t *R[DEFAULT_MEM_SIZE/(2 * DSIZE)];                       /* Redirection Table */                                        
int R_size;  
addrs_t freeptr;

/* HEAP CHECKER VARIABLES*/   
int Vallocated_blocks = 0;  
int Vfree_blocks = 0;
size_t Vraw_alloc = 0;
size_t Vpadded_alloc = 0;
size_t Vraw_free;
size_t Valigned_free = 0;
int VMalloc_calls = 0;
int VFree_calls = 0;
int Vfailed_calls = 0;
size_t Vpassed_size = 0;
size_t VM2_size = 0;
size_t Vpadded_bytes = 0;
int Vcalls = 0;

void VInit (size_t size) 
{
    size_t psize = size - (5 * WSIZE);                                /* Payload size */
    R_size = (psize/(2*DSIZE));                                       /* max # of elements that will be used in R */   
    size_t psize = size - (6 * WSIZE);                                /* Payload size */

    baseptr = (addrs_t)malloc(size);                                  /* starting address of M1 */ 
    PUT1(baseptr, 0);                                                  /* Alignment padding */ 
    PUT1(baseptr + (1 * WSIZE), PACK(DSIZE, 1));                       /* Prologue header */ 
    PUT1(baseptr + (2 * WSIZE), PACK(DSIZE, 1));                       /* Prologue footer */
    PUT1(baseptr + (3 * WSIZE), PACK(psize + DSIZE, 0));               /* Payload header */
    PUT1(baseptr + psize + (4 * WSIZE), PACK(psize + DSIZE, 0));       /* Payload footer */
    PUT1(baseptr + size - WSIZE, PACK(0, 1));                          /* Epilogue header */
    baseptr += (4 * WSIZE);                                           /* Payload pointer */ 
    freeptr = baseptr;                                                /* Free block pointer */

    /* HEAP CHECKER VARIABLES*/
    Vpassed_size = (size - (4 * WSIZE)) / (2 * DSIZE);
    Vraw_free = size - (3 * WSIZE);
    VM2_size = size;
    Vpadded_bytes += (3 * WSIZE);
}  

int Vplace (void *bp, size_t asize)
{
    //size of block bp
	  size_t csize = GET_SIZE (HDRP (bp));  
    
    //if size of block - size of payload >= 16 bytes (min size of block)                                                           
	if ((csize - asize) >= (2 * DSIZE)) 
    {
        //designate size of payload as allocated 
		PUT1 (HDRP (bp), PACK (asize, 1)); //makes new header
		PUT1 (FTRP (bp), PACK (asize, 1)); //gets the address of the footer by using new header
		bp = NEXT_BLKP (bp); //finds the new address of the new block's payload skipping header
        //designates remaining block (size of block - size of payload) as free
  	    PUT1 (HDRP (bp), PACK (csize - asize, 0));
		PUT1 (FTRP (bp), PACK (csize - asize, 0)); 
        return 1;
    }
	else //UNTESTED
    {
        //designate entire block as allocated (with any extra space as padding)
		PUT1 (HDRP (bp), PACK (csize, 1));
		PUT1 (FTRP (bp), PACK (csize, 1));
        return 0;   
	}
}

addrs_t *VMalloc (size_t size) //returns pointer in R that corresponds to passed in size 
//PASSED THE CASE WHEN INSERT THE FIRST ONE
{
    size_t asize;	/* Adjusted block size */
    VMalloc_calls++;
    
    /* Check if size is an allocatable value and if there is enough space in free block to fit size or is free address is NULL*/
    if(size <= 0 || size > GET_SIZE(HDRP(freeptr)))                                               
    {
        Vfailed_calls++;
        return NULL;
    }

  	/* Adjust block size to include overhead and alignment reqs */      
    //if size <= 8, asize = 16 (min block size)                     
  	if (size <= DSIZE)   
    {
        asize = 2*DSIZE; 
    }                                                                         
    //size > 8, asize =  ((size + 15)/8)*8 = size + padding, which is then aligned                                                                     
	else
    {
        asize = DSIZE * ((size + (DSIZE) + (DSIZE-1)) / DSIZE);
        Vpadded_bytes += asize - size;
    }

	/* check if address to free block is valid */
	if(freeptr != NULL) //catches freeptr==NULL cases, which might not be caught in size check above 
    {
        //assuming R elements added on all the way to end of array before filling in freed up spots
        //case where R runs out of elements so have to search array for NULL elements freed when corresponding M2 blocks freed
        if(num_VM_success >= R_size) //UNTESTED
        {
            //traverse thru to find freed up indicies 
            int i = 0;
            while(i < R_size || R[i] != NULL )  
            { 
                i++;        
            }
            //case where no free elements left in R
            if(i == R_size)
            {
                Vfailed_calls++;
                return NULL;
            }
            R[i] = freeptr - WSIZE;

            if(!Vplace(freeptr, asize))
            {
                //takes care of else case in VPlace where free block runs out of space and freeptr would be incremented to out of bounds
                freeptr = NULL;
            }
            else
            {
                freeptr = freeptr + asize;
            }
            //increment number of blocks allocated (this is only case allocation actually works so this only place we ++)
            addrs_t ret_add = R[i];
            num_VM_success++;
            Vallocated_blocks++;
            Vraw_alloc += size;
            Vpadded_alloc += asize;
            Vraw_free -= size;
            return ret_add;
        }
        else
        {
            // addrs_t temp = ((char *)freeptr - WSIZE) //MARKP
            //R[num_VM_success] = &(temp);//we want the address freeptr is pointing to, to be minused by WSIZE, then converting this new address back to pointer
            R[num_VM_success] = HDRP(freeptr); //we want the address freeptr is pointing to, to be minused by WSIZE, then converting this new address back to pointer
            //handles rerouting freeptr to point to new free block in M2
            if(!Vplace(freeptr, asize)) //takes care of else case in VPlace where free block runs out of space and freeptr would be incremented to out of bounds
            {
                Vfailed_calls++;
                freeptr = NULL; //UNTESTED
            }
            else
            {
                freeptr = freeptr + asize;
            }
            //increment number of blocks allocated (this is only case allocation actually works so this only place we ++)
            addrs_t ret_add = R[num_VM_success];
            num_VM_success++;
            Vallocated_blocks++;
            Vraw_alloc += size;
            Vpadded_alloc += asize;
            Vraw_free -= size;
            return ret_add;
        }
	}
    else
    {
        Vfailed_calls++;
        return NULL;
    }   
}

static addrs_t compaction (addrs_t addr, int index) //takes in address
{  
    //memcpy data into inputed addr that is now free
    memcpy(addr, R[index], GET_SIZE(R[index]));      

    //handles placing a value in R
    R[index] = addr;

    //return new free block address
    return addr + GET_SIZE(addr);  ////HDRP?
}

void VFree (addrs_t *addr) //takes in pointer to address
{
    int index;
    int i;    
    int j;
    int last_index;

    //checks if addr already free
    if(!GET_ALLOC(HDRP(*addr)))
    {
        Vfailed_calls--;
        return;
    }

    //loop through R to find index of pointer to passed in address
    for (i = 0; i < R_size - 1; i++) 
    {
        if (R[i] == addr) 
        {
            index = i;
            break;
        }
    }
    //SETTING THE INDEX AS NULL HERE
    R[index] = NULL;

    //initialize current address = to be pointer to address that can be taken in by compaction's memcpy
    addrs_t current_address = addr; //both pointers to addresses now 
    addrs_t comparison_address = addr;

    //loop through the R array checking the address of each index, if the indexed address > current address, we need to compact.
    //we then need to return from compaction with the new address of the free (freebptr), and then keep going always comparing with
    //original address

    for (j = 0; j < R_size; j++)
    {
        if (R[j] > comparison_address) 
        {
            current_address = compaction(current_address,j);     
            last_index = j;
        }
    }
    //set freeptr to pointer of new free block
    freeptr = current_address;
    //once exited, free last block/bytes not overwritten by memcpy
    // we need to potentially free everything from the last starting address to the end of the footer of the last index_address -1. 
    // This needs to be coalesced with the front, the only case.

    //if we potentially keep track of how much free space there is, update at this point 

    /*computes header of address then GETs size*/
    size_t size = GET_SIZE(HDRP(current_address)); 
    /*packs size|0 and puts in header of addr */
    PUT1(HDRP(current_address), PACK(size, 0));
    /*packs size|0 and puts in footer of addr */
    PUT1(FTRP(current_address), PACK(size, 0));
    //coalesce space from end of compacted allocated blocks with free block
    coalesce(R[last_index] + GET_SIZE(HDRP(R[last_index])));
    Vallocated_blocks--;
    Vraw_alloc -= (size - (2 * WSIZE));
    Vpadded_alloc -= size;
    Vraw_free += (size - (2 * WSIZE));
    VFree_calls++;
    Vpadded_bytes -= (2 * WSIZE);
    if(GET_ALLOC(HDRP(*addr)))
    {
        Vfailed_calls--;
    }
}

addrs_t *VPut (any_t data, size_t size) 
{
    //GET start addr from Malloc
    addrs_t *start = VMalloc(size);
    //if start addr not NULL, move in data and return addr
    if(start != NULL)
    {
        memcpy(start, data, size);
        if(call < 3)
        {
            Vheap_checker();
        }
        return start;
    }
    if(call < 3)
    {
      Vheap_checker();
    }
    return 0;
}

void VGet (any_t return_data, addrs_t *addr, size_t size) 
{
    //GET data from addr and input into return_data 
    memcpy(return_data, addr, size);
    VFree(addr); 
    if(call < 3)
    {
      Vheap_checker();
    }
}

void heap_checker()
{
    free_blocks = passed_size - allocated_blocks ;
    aligned_free = M1_size - padded_bytes;
    calls++;

    printf("\n\nCall Number: %d\n", calls);
    printf("Number of allocated blocks: %d\n", allocated_blocks);
    printf("Number of free blocks: %d\n", free_blocks);
    printf("Raw total number of bytes allocated: %zu\n", raw_alloc);
    printf("Padded total number of bytes allocated: %zu\n", padded_alloc);
    printf("Raw total number of bytes free: %zu\n", raw_free);
    printf("Aligned total number of bytes free: %zu\n", aligned_free);
    printf("Total number of Malloc requests: %d\n", Malloc_calls); 
    printf("Total number of Free requests: %d\n", Free_calls);
    printf("Total number of request failures: %d\n", failed_calls);
    printf("\n\n");
}

void Vheap_checker()
{
    Vfree_blocks = Vpassed_size - Vallocated_blocks ;
    Valigned_free = VM2_size - Vpadded_bytes;

    Vcalls++;

    printf("\n\nCall Number: %d\n", Vcalls);
    printf("Number of allocated blocks: %d\n", Vallocated_blocks);
    printf("Number of free blocks: %d\n", Vfree_blocks);
    printf("Raw total number of bytes allocated: %zu\n", Vraw_alloc);
    printf("Padded total number of bytes allocated: %zu\n", Vpadded_alloc);
    printf("Raw total number of bytes free: %zu"\n, Vraw_free);
    printf("Aligned total number of bytes free: %zu\n", Valigned_free);
    printf("Total number of Malloc requests: %d\n", VMalloc_calls); 
    printf("Total number of Free requests: %d\n", VFree_calls);
    printf("Total number of request failures: %d\n", Vfailed_calls);
    printf("\n\n");
}

void main (int argc, char **argv) {

  int i, n;
  char s[80];
  addrs_t *addr1, *addr2;
  char data[80];
  int mem_size = DEFAULT_MEM_SIZE; // Set DEFAULT_MEM_SIZE to 1<<20 bytes for a heap region
  if  (argc > 2) {
    fprintf (stderr, "Usage: %s [memory area size in bytes]\n", argv[0]);
    exit (1);
  }
  else if (argc == 2)
    mem_size = atoi (argv[1]);

  VInit(mem_size);

  for (i = 0; i < 10 ; i++) {
    n = sprintf (s, "String 1, the current count is %d\n", i);
    addr1 = VPut (s, n+1);
    addr2 = VPut (s, n+1);
    if (addr1)
      printf ("Data at %x is: %s", addr1, addr1);
    if (addr2)
      printf ("Data at %x is: %s", addr2, addr2);
    if (addr2)
      VGet ((any_t)data, addr2, n+1);
    if (addr1)
      VGet ((any_t)data, addr1, n+1);
  }
}