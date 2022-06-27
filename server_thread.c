#include "request.h"
#include "server_thread.h"
#include "common.h"
#include <stdbool.h>

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

typedef struct entry {
    const char* key;
    void* value;
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
unsigned long hash(const char*);

void *get(ht *, const char *);
bool insert_table(ht *, const char *, void *);
void _insert(ht *, const char *, void *, int);

void print_table(ht *table)
{
    printf("table at %p contains %d/%d entries\n", table, table->num_entries, table->capacity);
    printf("----------------------------------------------\n");
    for (int i=0; i < table->capacity; i++){
        entry curr = table->entries[i];
        if (curr.key != NULL)
            printf("[%5d](\"%15s\"){%28lu} --> [%d]\n", i, curr.key, hash(curr.key), *(int *) curr.value);
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
        if (curr.key != NULL)
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
void* get(ht *table, const char* key)
{
    unsigned long hash_key = hash(key);
    int index = hash_key % table->capacity;
    while (table->entries[index].key != NULL){
        if (strcmp(table->entries[index].key, key) == 0){
            return table->entries[index].value;
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
bool insert_table(ht *table, const char* key, void *value)
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

    _insert(table, key, value, index);
    return true;
}

/*
 * Function handles the actual insertion of a key.
 * 
 * If the key already exists in the table, it updates
 * the value of the key (if necessary) and returns false.
 */
void _insert(ht *table, const char* key, void *value, int index)
{
    assert(table != NULL && key != NULL && value != NULL && "insert: table, key, and value cannot be NULL");
    if (table->entries[index].key == NULL){
        table->entries[index].key = key;
        table->entries[index].value = value;
        table->num_entries++;
    }
    else if (strcmp(table->entries[index].key, key) == 0)
        table->entries[index].value = value;
    else 
        _insert(table, key, value, (++index) % table->capacity);
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
hash(const char *str)
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


typedef struct request {
	int fd;		 /* descriptor for client connection */
	struct file_data *data;
} req_t;

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
	bbuf_t *requests;
	pthread_t workers[];
};

/* cache functions */

static void
cache_lookup(int *fp)
{
	TBD();
}

static void
cache_insert(int *fp)
{
	TBD();
}

static void
cache_evict(int amount_to_evict)
{
	TBD();
}

/* static functions */

static void
insert(struct server *sv, req_t *elem){
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
pop(struct server *sv){
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
/* initialize file data */
static struct file_data *
file_data_init(void)
{
	struct file_data *data;

	data = Malloc(sizeof(struct file_data));
	data->file_name = NULL;
	data->file_buf = NULL;
	data->file_size = 0;
	return data;
}

/* free all file data */
static void
file_data_free(struct file_data *data)
{
	free(data->file_name);
	free(data->file_buf);
	free(data);
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
		req_t *rq = pop(sv);
		if (sv->exiting)
			break;
		int ret = request_readfile(rq);
		if (ret == 0) { /* couldn't read file */
			goto out;
		}
		/* send file to client */
		request_sendfile(rq);
	out:
		file_data_free(rq->data);
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
		insert(sv, rq);
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
	free(sv);
}
