# Intro to memory
This is a very simple intro to Linux process memory usage and metadata. It is the result of exploring and learning to prepare for capturing interesting chunks of memory for analysis.

As the goal is learning and exploration, its being kept as simple as possible to inspect a system.

* You'll need root
* For this document, all data is available thru the /proc pseudo filesystem.
    * (find a good general reference for /proc)
* Initial examples will use simple shell commands to inspect

## Essential /proc Files for Beginners
Process Memory (pick your process first):

* `/proc/[pid]/maps` - Start here. Shows all memory regions.
* `/proc/[pid]/smaps` - Detailed stats per region (when you need more info).
* `/proc/[pid]/mem` - Read actual memory content.

System Overview:

* `/proc/meminfo` - System-wide memory summary.

That's it. Master maps first, add smaps when you need statistics, use mem when you need to read actual bytes.

# Exploring

Start with just inspecting the files with `less`. 

Count all the unique permissions defined.

```bash
$ sudo cat /proc/*/maps | cut -d\  -f 2 | sort | uniq -c
   1465 ---p
   1387 r--p
     21 r--s
   1163 r-xp
   3237 rw-p
     73 rw-s
     79 rwxp
```

Count all the unique files/things mapped. This is the last column of the maps file:

```bash
sudo cat /proc/*/maps | awk '{print $NF}' | sort | uniq -c | sort -n | more
```

## Shell tips and tricks

`uniq -c` will reduce to unique values and provide a count. It does this as data is streaming thru, so if your data isn't sorted, you'll multiple groups for repeating values. Thats why you'll see it used like:  `sort | uniq -c`.

After that, I like to add a `sort -n` which sorts the first column, the count, as a numeric.

Finally, if its a huge list, you can add `head -10` or `tail -10` to get the top/bottom 10 values.

# Appendix

## Full `/proc` Memory Files Reference

### Process-Specific (`/proc/[pid]/`)

- **`/proc/[pid]/maps`** - List of memory mappings showing address ranges, permissions, and backing files. Your primary starting point.

- **`/proc/[pid]/smaps`** - Detailed memory statistics per mapping including RSS, PSS, swap usage, and page state information.

- **`/proc/[pid]/smaps_rollup`** - Aggregated summary of all smaps data without per-mapping detail. Faster for overview statistics.

- **`/proc/[pid]/mem`** - Raw access to process memory content. Requires ptrace permissions. Seek to address and read.

- **`/proc/[pid]/pagemap`** - Physical page frame numbers for each virtual page. Shows physical memory mapping and page flags.

- **`/proc/[pid]/numa_maps`** - NUMA (Non-Uniform Memory Access) information showing which NUMA node pages reside on.

- **`/proc/[pid]/status`** - High-level process status including VmSize, VmRSS, VmSwap, and other memory totals.

- **`/proc/[pid]/statm`** - Memory statistics in pages: total size, resident, shared, text, data segments.

- **`/proc/[pid]/oom_score`** - Current out-of-memory killer score for this process.

- **`/proc/[pid]/clear_refs`** - Write-only file to clear referenced/dirty page bits for memory tracking experiments.

### System-Wide (`/proc/`)

- **`/proc/meminfo`** - System-wide memory statistics including total RAM, free memory, buffers, cache, swap.

- **`/proc/buddyinfo`** - Buddy allocator information showing available memory fragments by size.

- **`/proc/pagetypeinfo`** - Page type information organized by migration type and memory zone.

- **`/proc/slabinfo`** - Kernel slab allocator statistics showing cache usage for kernel objects.

- **`/proc/vmallocinfo`** - Kernel virtual memory allocations (vmalloc region).

- **`/proc/zoneinfo`** - Memory zone information (DMA, Normal, HighMem) with per-zone statistics.

- **`/proc/swaps`** - Active swap devices and their usage statistics.

- **`/proc/sys/vm/`** - Directory of tunable virtual memory parameters (overcommit, swappiness, etc.).