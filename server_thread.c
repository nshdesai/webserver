#include "request.h"
#include "server_thread.h"
#include "common.h"
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>


// These macros are taken from: 
// https://github.com/remzi-arpacidusseau/ostep-code/blob/0cd7a8be1a82772000f0854dec2dd8a17260a9df/intro/common_threads.h
#define Pthread_create(thread, attr, start_routine, arg) assert(pthread_create(thread, attr, start_routine, arg) == 0);
#define Pthread_join(thread, value_ptr)                  assert(pthread_join(thread, value_ptr) == 0);

#define Pthread_mutex_lock(m)                            assert(pthread_mutex_lock(m) == 0);
#define Pthread_mutex_unlock(m)                          assert(pthread_mutex_unlock(m) == 0);
#define Pthread_cond_signal(cond)                        assert(pthread_cond_signal(cond) == 0);
#define Pthread_cond_broadcast(cond)                     assert(pthread_cond_broadcast(cond) == 0);
#define Pthread_cond_wait(cond, mutex)                   assert(pthread_cond_wait(cond, mutex) == 0);

#define full(buf) ((buf->in - buf->out + buf->n) % (buf->n) == (buf->n - 1))
#define empty(buf) (buf->in == buf->out)
#define free_space(cache) ((cache).max_size - (cache).size)

#define DELETED_ENTRY ((void *) - 1)

/*
    Simple implementation of an open addressing hash table
    using linear probing. Although it would be nice to hash
    general types as keys, this implementation only allows 
    string keys. General pointers are used for values, so 
    the types on values are not restricted.
    
    I have tried several hash functions with several different
    parameters and measured their perfomance. In the end the
    djb2 hash function ended up giving me the best performance.
*/

#define STARTING_CAPACITY 16

// static char *DELETED_ENTRY = "DELETED";

typedef struct entry {
    char* key;
    void* value;
	int index;
	int num_using; // How many users are still using this file?
	void* next; // Used for LRU queue
} entry;

typedef struct ht {
    entry *entries;
    int num_entries;
    int capacity;
} ht;

ht *make_table(int);
void drop_table(ht *);
ht *expand_table(ht *);
void print_table(ht *);
unsigned long hash(char*);

entry *get_from_table(ht *, char *);
bool insert_table(ht *, char *, void *);
void _insert_table(ht *, char *, void *, int);

void print_table(ht *table)
{
    printf("table at %p contains %d/%d entries\n", table, table->num_entries, table->capacity);
    printf("----------------------------------------------\n");
    for (int i=0; i < table->capacity; i++){
        entry curr = table->entries[i];
        if (curr.key != NULL && curr.key != DELETED_ENTRY)
            printf("[%5d](\"%15s\"){%28lu} --> [%p]\n", i, curr.key, hash(curr.key), curr.value);
		else if (curr.key == DELETED_ENTRY)
			printf("[%5d](%p -- DELETED)\n", i, curr.key);
        else
            printf("[%5d]\n", i);
    }
    printf("----------------------------------------------\n");
}

ht* make_table(int capacity)
{
    ht *table = malloc(sizeof(ht));
    table->capacity = capacity;
    table->num_entries = 0;
    table->entries = calloc(table->capacity, sizeof(entry));

    return table;
}

void drop_table(ht* table)
{
    for (int i=0; i<table->capacity; i++){
        entry curr = table->entries[i];
        free((void *)curr.key);
        free(curr.value);
    }
    free((void*) table->entries);
    free(table);
}

ht* expand_table(ht* table){
    entry *new_entries = calloc(table->capacity * 2, sizeof(entry));

    // Orphan the table->entries pointer, hold it in a temp variable.
    // Then copy these entries into new_entries and free(temp_entries) 
    entry *temp_entries = table->entries;
    table->entries = new_entries;
    table->capacity *= 2;
    table->num_entries = 0;

    for (int i=0; i<table->capacity / 2; i++){
        entry curr = temp_entries[i];
        if (curr.key != NULL && curr.key != DELETED_ENTRY)
            insert_table(table, curr.key, curr.value);
    }
    free(temp_entries);
    return table;
}

/*
   Hash the given key, and use it to index into the table.
   If key does not exist at that index, linearly probe until
   an index with the key is found. If we hit a NULL entry
   during our probe, the key cannot exist in the table, so return NULL. 
 */
entry* get_from_table(ht *table, char* key)
{
    unsigned long hash_key = hash(key);
    int index = hash_key % table->capacity;
    while (table->entries[index].key != NULL){
        if (table->entries[index].key != DELETED_ENTRY && strcmp(table->entries[index].key, key) == 0){
            return &table->entries[index];
        }
        index++;
        index = index % table->capacity;
    }
    return NULL;    
}

/*
 * Function handles the insertion of a key while 
 * expanding the table if needed. Returns a flag
 * indicating whether the key was inserted or not.
 * 
 * If the key already exists in the table, it updates
 * the value of the key (if necessary) and returns false.
 */
bool insert_table(ht *table, char* key, void *value)
{
    assert(table != NULL && key != NULL && value != NULL && "insert: table, key, and value cannot be NULL");
    
    if ((double) table->num_entries / (double) table->capacity > 0.80){
        ht *new_table = expand_table(table);
        // print_table(new_table);
        if (new_table == NULL)
            return false;
        table = new_table;
    }
    unsigned long hash_key = hash(key);
    int index = hash_key % table->capacity;

    _insert_table(table, key, value, index);
    return true;
}

/*
 * Function handles the actual insertion of a key.
 * 
 * If the key already exists in the table, it updates
 * the value of the key (if necessary) and returns false.
 */
void _insert_table(ht *table, char* key, void *value, int index)
{
    assert(table != NULL && key != NULL && value != NULL && "insert: table, key, and value cannot be NULL");
    if (table->entries[index].key == NULL || table->entries[index].key == DELETED_ENTRY){
        table->entries[index].key = key;
        table->entries[index].value = value;
        table->entries[index].next = NULL;
		table->entries[index].index = index;
        table->num_entries++;
    }
    else if (strcmp(table->entries[index].key, key) == 0)
        table->entries[index].value = value;
    else 
        _insert_table(table, key, value, (++index) % table->capacity);
}

/*
    This hashing function is based on the djb2 hashing function
    code is taken from http://www.cse.yorku.ca/~oz/hash.html
    this algorithm's origin is usually credited to Dan Bernstien 

    I have tried the following hash functions:
    * Fowler-Noll-Vo hash function (version 1)
    * the hash() function given on p.144 of K&R second ed
    * sdbm hash function (seen in gawk also)
    
    I also tried many different ways to make this hash function my
    own, but they always ended up hurting performance.
 */
unsigned long
hash(char *str)
{
    assert(str != NULL && "hash: str cannot be NULL");
    if (str == NULL)
        return 0;

    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 6) + hash) + c; /* hash * 33 + c */

    return hash;
}

/* Queue stuff, used to track LRU */
typedef struct queue_t {
	entry *head;
	entry *tail;
	int size;
} queue_t;

/* Queue operations */

static
void print_queue(queue_t *q) {
	printf("================== DEBUG QUEUE =================\n");
	entry *curr = q->head;
	while (curr != NULL){
		printf("%s (%d | %d) --> \n", (char *) curr->key, ((struct file_data *)(curr->value))->file_size, curr->num_using);
		curr = curr->next;
	}
	printf("NULL\n");
	printf("------------------------------------------------\n");
	printf("head: %p, tail: %p, size: %d\n", q->head, q->tail, q->size);
	printf("================================================\n");
}

/* Append: Appends an element to a queue (on the right) */
static void
enqueue(queue_t *queue, entry *t){
	t->next = NULL;
	if (queue->tail == NULL) // queue is empty
		queue->head = queue->tail = t;
	else {
		queue->tail->next = t;
		queue->tail = t;
	}
	++queue->size;
	if (0)
		print_queue(queue);
}

/* Pops the first element from a queue */
// static
// entry* dequeue(queue_t* q){
// 	entry* curr = q->head;
// 	if (curr != NULL) {
// 		q->head = q->head->next;
// 		if (q->head == NULL)
// 			q->tail = NULL;
// 	}
// 	return curr; 
// }

static entry*
qremove(queue_t* q, entry *e){
	entry *prev = q->head, *curr, *temp;
	// Head holds the correct element
	if (q->head != NULL &&  q->head->key != NULL && strcmp(q->head->key, e->key) == 0) {
		curr = q->head;
		temp = curr->next;
		if (q->head == q->tail)
			q->tail = temp;
		q->head = temp;
		curr->next = NULL;
		(q->size)--;
		return curr;
	}

	while (prev){
		if ((curr = prev->next) != NULL && curr->key != NULL && strcmp(curr->key, e->key) == 0){
			if (curr == q->tail)
				q->tail = prev;
			prev->next = curr->next;
			curr->next = NULL;
			(q->size)--;
			return curr;	
		}
		prev = prev->next;
	}
	return NULL;
}

typedef struct request {
	int fd;		 /* descriptor for client connection */
	struct file_data *data;
} req_t;

typedef struct cache {
	ht *table;
	queue_t lru;
	int size;
	int max_size;
	pthread_mutex_t lock;
} cache_t;

/* Holds a bounded buffer of requests to the server */
typedef struct bbuf_t {
	int n;   // size of buffer
	int in;  // where should we insert? 
	int out; // where should we remove elements from? 
	// Lock and cv for the buffer 
	pthread_cond_t full;
	pthread_cond_t empty;
	pthread_mutex_t m;
	req_t *buf[];
} bbuf_t;

struct server {
	int nr_threads;
	int max_requests;
	int max_cache_size;
	int exiting;
	cache_t cache;
	bbuf_t *requests;
	pthread_t workers[];
};

/* initialize file data */
static struct file_data *
file_data_init(void)
{
	struct file_data *data;

	data = Malloc(sizeof(struct file_data));
	data->file_name = NULL;
	data->file_buf = NULL;
	data->file_size = 0;
	// printf("THREAD %ld [FILE INIT]: Empty alloc at %p\n", syscall(__NR_gettid), data);
	return data;
}

/* free all file data */
static void
file_data_free(struct file_data *data)
{
	// printf("THREAD %ld [FILE FREE]: %s with buffer @ %p\n", syscall(__NR_gettid), data->file_name, data->file_buf);
	free(data->file_name);
	free(data->file_buf);
	free(data);
	// printf("THREAD %ld [FILE FREE]: DONE! \n", syscall(__NR_gettid));
}

/* cache functions */

/* Dequeues the first element from queue that has num_using == 0*/
static entry*
dequeue_valid(queue_t *q)
{
	entry *prev = q->head, *curr, *temp;
	// Head holds required value
	if (q->head != NULL && q->head->key != NULL && q->head->num_using == 0) {
		curr = q->head;
		temp = curr->next;
		if (q->head == q->tail)
			q->tail = temp;
		q->head = temp;
		curr->next = NULL;
		(q->size)--;
		return curr;
	}

	while (prev){
		if ((curr = prev->next) != NULL && curr->key != NULL && curr->num_using == 0){
			if (curr == q->tail)
				q->tail = prev;
			prev->next = curr->next;
			curr->next = NULL;
			(q->size)--;
			return curr;	
		}
		prev = prev->next;
	}
	return NULL;
}

static entry* 
cache_lookup(cache_t *cache, struct file_data *data)
{
	Pthread_mutex_lock(&cache->lock);
	entry* e = get_from_table(cache->table, data->file_name);
	if (e != NULL){ // Update LRU queue
		e->num_using++;
		assert(qremove(&cache->lru, e) != NULL);
		enqueue(&cache->lru, e); // Move the entry to the end
	}
	// printf("THREAD %ld [LOOKUP]: %s in cache; found at: %p\n", syscall(__NR_gettid), data->file_name, e);
	Pthread_mutex_unlock(&cache->lock);
	return e;
}

static void
cache_insert(cache_t *cache, struct file_data *data)
{
	assert(data->file_size + cache->size <= cache->max_size);
	assert(data->file_size != 0);

	struct file_data *d = Malloc(sizeof(struct file_data));
	d->file_buf = Malloc(data->file_size);

	memcpy(d->file_buf, data->file_buf, data->file_size);
	d->file_name = strdup(data->file_name);
	d->file_size = data->file_size;

	bool inserted = insert_table(cache->table, d->file_name, d);
	if (inserted){ // Update LRU queue
		entry *e = get_from_table(cache->table, d->file_name);
		assert(e != NULL);
		enqueue(&cache->lru, e);
		cache->size += d->file_size;
	}
	// printf("THREAD %ld [INSERT]: Copied and inserted %s\n", syscall(__NR_gettid), data->file_name);
}

static void
cache_evict(cache_t *cache, int amount_to_evict)
{
	// Keep removing files as until we have freed at least amount_to_evict bytes
	if (amount_to_evict <= cache->size){
		while (amount_to_evict > 0){
			// Deque the first entry that is not in use
			entry *e = dequeue_valid(&cache->lru);
			assert(e->key != NULL);
			assert(e->num_using == 0);
			// Update the cache metrics
			int index = e->index;
			struct file_data *data = (struct file_data *) e->value;
			amount_to_evict -= (data->file_size);
			cache->size -= (data->file_size);
			// printf("THREAD %ld [EVICT]: Evicted %s\n", syscall(__NR_gettid), data->file_name);
			// Free up the file resources
			file_data_free(data);
			cache->table->entries[index].key = DELETED_ENTRY;
			cache->table->entries[index].value = DELETED_ENTRY;
			cache->table->entries[index].next = NULL;
			cache->table->entries[index].num_using = 0;
			// Update the hash table
			(cache->table->num_entries)--;
			// printf("THREAD %ld [EVICT]: Table after eviction: \n", syscall(__NR_gettid));
		}
	}
}

/* static functions */

static void
insert_buf(struct server *sv, req_t *elem){
	bbuf_t *buf = sv->requests; 
	Pthread_mutex_lock(&buf->m);
	while (full(buf) && !sv->exiting)
		Pthread_cond_wait(&buf->full, &buf->m);
	if (sv->exiting)
		goto out;
	buf->buf[buf->in] = elem;
	buf->in = (buf->in + 1) % buf->n;
	Pthread_cond_signal(&buf->empty); // not empty anymore
out:
	Pthread_mutex_unlock(&buf->m);
}

static req_t * 
pop_buf(struct server *sv){
	bbuf_t *buf = sv->requests; 
	Pthread_mutex_lock(&buf->m);
	while (empty(buf) && !sv->exiting)
		pthread_cond_wait(&buf->empty, &buf->m);
	if (sv->exiting){
		Pthread_mutex_unlock(&buf->m);
		return NULL;
	}
	req_t *rq = buf->buf[buf->out];
	buf->out = (buf->out + 1) % buf->n;
	Pthread_cond_signal(&buf->full); 
	Pthread_mutex_unlock(&buf->m);
	return rq;
}

static void
do_server_request(struct server *sv, int connfd)
{
	int ret;
	struct request *rq;
	struct file_data *data;

	data = file_data_init();

	/* fill data->file_name with name of the file being requested */
	rq = request_init(connfd, data);
	if (!rq) {
		file_data_free(data);
		return;
	}
	/* read file, 
	 * fills data->file_buf with the file contents,
	 * data->file_size with file size. */
	ret = request_readfile(rq);
	if (ret == 0) { /* couldn't read file */
		goto out;
	}
	/* send file to client */
	request_sendfile(rq);
out:
	request_destroy(rq);
	file_data_free(data);
}

static void *
worker_handle_request(void *arg){
	struct server *sv = arg;
	while (1){
		req_t *rq = pop_buf(sv);
		if (sv->exiting)
			break;
		entry *e = cache_lookup(&sv->cache, rq->data);
		if (e != NULL){  // Cache Hit
			Pthread_mutex_lock(&sv->cache.lock);
			// setup the request from cache	
			rq->data = e->value;

			// Update the LRU queue
			qremove(&sv->cache.lru, e);
			enqueue(&sv->cache.lru, e);
			Pthread_mutex_unlock(&sv->cache.lock);

			request_sendfile(rq);
			
			Pthread_mutex_lock(&sv->cache.lock);
			--e->num_using;
			Pthread_mutex_unlock(&sv->cache.lock);
			goto rqd;
		}
		else {  // Cache miss
			// Read the file from disk
			int ret = request_readfile(rq);
			if (ret == 0) { /* couldn't read file */
				goto out;
			}
			/* send file to client */
			request_sendfile(rq);

			/* Update Cache
			 * ------- 
			 * two cases where we don't write to cache
			 * 1. Another thread wrote the same file to cache before us
			 * 2. The file doesn't fit in the cache (size > cache_size)
			 */ 
			entry *e2 = cache_lookup(&sv->cache, rq->data);
			if (e2 != NULL){
				Pthread_mutex_lock(&sv->cache.lock);
				--e2->num_using;
				Pthread_mutex_unlock(&sv->cache.lock);
				goto out;
			}
			else if (rq->data->file_size > sv->cache.max_size)
				goto out;
			else { 	// We are responsible for writing this to cache
				Pthread_mutex_lock(&sv->cache.lock);
				int space_needed;
				if ((space_needed = rq->data->file_size - free_space(sv->cache)) > 0){
					cache_evict(&sv->cache, space_needed);
				}
				cache_insert(&sv->cache, rq->data);
				Pthread_mutex_unlock(&sv->cache.lock);
			}
		}
		// printf("rq->data->file_name: %s\n", rq->data->file_name);
		// printf("rq->data->file_size: %d\n", rq->data->file_size);
		// printf("rq->data->file_buf: %p\n", rq->data->file_buf);
	out:
		file_data_free(rq->data);
	rqd:
		request_destroy(rq);
	}
	return NULL; 
}

/* entry point functions */

struct server *
server_init(int nr_threads, int max_requests, int max_cache_size)
{
	struct server *sv;

	sv = Malloc(sizeof(struct server) + sizeof(pthread_t) * nr_threads);
	sv->nr_threads = nr_threads;
	sv->max_requests = max_requests;
	sv->max_cache_size = max_cache_size;
	sv->exiting = 0;
	
	if (nr_threads > 0 || max_requests > 0 || max_cache_size > 0) {
		// create request buffer
		sv->requests = Malloc(sizeof(bbuf_t) + sizeof(req_t *) * (sv->max_requests + 1));
		sv->requests->n = sv->max_requests + 1;
		sv->requests->in  = 0;
		sv->requests->out = 0;
		pthread_cond_init(&sv->requests->full, NULL);
		pthread_cond_init(&sv->requests->empty, NULL);
		pthread_mutex_init(&sv->requests->m, NULL);
		// Create cache
		sv->cache.size = 0;
		sv->cache.max_size = max_cache_size;
		sv->cache.table = make_table(STARTING_CAPACITY * 100);
		sv->cache.lru.head = NULL;
		sv->cache.lru.tail = NULL;
		sv->cache.lru.size = 0;

		// sv->cache.lock = &sv->requests->m;
		pthread_mutex_init(&sv->cache.lock, NULL);

		// create thread worker pool
		for (int i = 0; i < sv->nr_threads; i++)
			Pthread_create(&sv->workers[i], NULL, worker_handle_request, sv);
	}

	/* Lab 4: create queue of max_request size when max_requests > 0 */

	/* Lab 5: init server cache and limit its size to max_cache_size */

	/* Lab 4: create worker threads when nr_threads > 0 */

	return sv;
}

void
server_request(struct server *sv, int connfd)
{
	if (sv->nr_threads == 0) { /* no worker threads */
		do_server_request(sv, connfd);
	} else {
		/*  Save the relevant info in a buffer and have one of the
		 *  worker threads do the work. */
		struct request *rq;
		struct file_data *data;
		
		data = file_data_init();
		rq = request_init(connfd, data);
		
		if (!rq) {
			file_data_free(data);
			return;
		}
		insert_buf(sv, rq);
	}
}

void
server_exit(struct server *sv)
{
	/* when using one or more worker threads, use sv->exiting to indicate to
	 * these threads that the server is exiting. make sure to call
	 * pthread_join in this function so that the main server thread waits
	 * for all the worker threads to exit before exiting. */
	sv->exiting = 1;
	Pthread_cond_broadcast(&sv->requests->empty); // Wakeup all threads that are blocked
	for (int i = 0; i < sv->nr_threads; i++)
		Pthread_join(sv->workers[i], NULL);
	/* make sure to free any allocated resources */
	free(sv->requests);
	cache_evict(&sv->cache, sv->cache.size); // Remove all elements in cache
	free(sv->cache.table->entries);
	free(sv);
}
