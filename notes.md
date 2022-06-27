# Things to deal with for caching 

* How will you ensure that files that are in use are not evicted? 
  For example, the server might be sending a cached file to the client.
  Evicting this file will deallocate the in-memory copy of the file,
  possibly sending garbage to the client, or crashing your server.

Lock the cache? Locking the cache would make sense, but from when to when?

Lock the moment a file checks the cache. Release the lock only once the request has been serviced, and the cache has been updated?
    But the issue with this is that the I/O is going to be really slow, if you lock a cache access for the entirety of grabbing the
    file, then you might hit huge performance losses. 

-----

* How will you ensure that files are not multiply cached?
  One option might be to allow threads to read the same file concurrently, if the file is not cached currently.
  On returning from the file read, a thread could check whether the file has already been cached (it lost the race). 
  If so, it can avoid caching its file copy (i.e., free the buffer containing the file contents). 
  Another better option might be to synchronize requests for reading the same file from disk. 
  In either case, make sure you think about locking and synchronization carefully.

Lock the operations on the cache. Right before

-----

* Are there any cases when enough files cannot be evicted, when the evict() function is called? 
  What should happen in this case?

-----

* What happens if the file size is greater than the cache size?


-----

* What data structure will you use to implement your cache eviction algorithm?
  Will it require its own lock and synchronization, or can you reuse any other locks?

-----


Hash-table deletion is complicated by linear probing.

### Pseudocode for worker thread


In a Loop:
    - With the request in hand, check if the requested file
      is in the cache.
        - If the requested file is in the cache (cache hit)
            - Return the corresponding file object of in the cache
        - Else on cache miss
            - Go read the file from disk
    - Send over the processed request to the client
    - Decrement the `num_using` in the hash table if there was a cache hit
    - Handle cleanup
        - If the cache was never used, cleanup the file resources
        - *NOTE: on write to cache, check is another thread already beat you to writing the file*, remember if you insert, don't free anything 
        - If the cache was used, then attempt to write to the cache, if file doesn't already exist (another thread wrote the file)
            - File fits in cache without needing to evict anything
                - Put it in cache, and *don't* clean up the file resources
            - If the file doesn't fit in cache, this could happen for two reasons
                - The file is larger than the cache to being with; don't bother writing; goto cleaningup file resources
                - We need to evict a bunch of files to make this happen
                    - Free up space in cache, and then write to it (don't free up any resources)


Cache hit:

- Update the request from the cache
- Add to the number of threads using the request
- Send the request to the user
- Sub the number of threads using the request

Cache miss:

- Go read the file from disk
- If there's an error reading the file, goto cleanup
- send the file to the user
- update the cache
    - Check if the file that we have is already in cache (another thread won the race)
        - If so, goto cleanup
    - Else if the file fits in the cache
        - If the cache has space, write the file in
        - Else evict enough files from cache to make space; then write file

* I'm going to assume we don't need to copy the file into memory once more because `request_readfile`
  is already going to `malloc()` the file buffer somewhere. 

```C

static void *
worker_handle_request(void *arg){
	struct server *sv = arg;
	while (1){
		req_t *rq = pop_buf(sv);
		if (sv->exiting)
			break;
		entry *e = cache_lookup(sv->cache, rq->data);
		// SHOULD BE LOCKED????!!!
		if (e != NULL){ // Cache hit
			rq->data = e->value;
			++e->num_using;
		}
		int ret = request_readfile(rq);
		if (ret == 0) { /* couldn't read file */
			goto out;
		}
		/* send file to client */
		request_sendfile(rq);
	out:
		file_data_free(rq->data);
		// Should decrement the num_using of entry in cache
		request_destroy(rq);
	}
	return NULL; 
}
```













