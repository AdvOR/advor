#ifndef _TOR_BUFFERS_H
#define _TOR_BUFFERS_H

/** A single chunk on a buffer or in a freelist. */
typedef struct chunk_t {
  struct chunk_t *next; /**< The next chunk on the buffer or freelist. */
  size_t datalen; /**< The number of bytes stored in this chunk */
  size_t memlen; /**< The number of usable bytes of storage in <b>mem</b>. */
  char *data; /**< A pointer to the first byte of data stored in <b>mem</b>. */
  char mem[1]; /**< The actual memory used for storage in this chunk. May be
                * more than one byte long. */
} chunk_t;

#define CHUNK_HEADER_LEN STRUCT_OFFSET(chunk_t, mem[0])

/** Magic value for buf_t.magic, to catch pointer errors. */
#define BUFFER_MAGIC 0xB0FFF312u
/** A resizeable buffer, optimized for reading and writing. */
struct buf_t {
  uint32_t magic; /**< Magic cookie for debugging: Must be set to
                   *   BUFFER_MAGIC. */
  size_t datalen; /**< How many bytes is this buffer holding right now? */
  size_t default_chunk_size; /**< Don't allocate any chunks smaller than
                              * this for this buffer. */
  chunk_t *head; /**< First chunk in the list, or NULL for none. */
  chunk_t *tail; /**< Last chunk in the list, or NULL for none. */
};

/** Return the number of bytes needed to allocate a chunk to hold
 * <b>memlen</b> bytes. */
#define CHUNK_ALLOC_SIZE(memlen) (CHUNK_HEADER_LEN + (memlen))
/** Return the number of usable bytes in a chunk allocated with
 * malloc(<b>memlen</b>). */
#define CHUNK_SIZE_WITH_ALLOC(memlen) ((memlen) - CHUNK_HEADER_LEN)

char *CHUNK_WRITE_PTR(chunk_t *chunk);
size_t CHUNK_REMAINING_CAPACITY(const chunk_t *chunk);

void buf_pullup(buf_t *buf, size_t bytes);
void buf_remove_from_front(buf_t *buf, size_t n);
int buf_find_string_offset(const buf_t *buf, const char *s, size_t n);

buf_t *buf_new(void);
buf_t *buf_new_with_capacity(size_t size);
void buf_free(buf_t *buf);
void buf_clear(buf_t *buf);
void buf_shrink(buf_t *buf);
void buf_shrink_freelists(int free_all);
void buf_dump_freelist_sizes(int severity);

size_t buf_datalen(const buf_t *buf);
size_t buf_allocation(const buf_t *buf);
size_t buf_slack(const buf_t *buf);

int read_to_buf(tor_socket_t s, size_t at_most, buf_t *buf, int *reached_eof,
                int *socket_error);
int read_to_buf_tls(tor_tls_t *tls, size_t at_most, buf_t *buf);

int flush_buf(tor_socket_t s, buf_t *buf, size_t sz, size_t *buf_flushlen);
int flush_buf_tls(tor_tls_t *tls, buf_t *buf, size_t sz, size_t *buf_flushlen);

int write_to_buf(const char *string, size_t string_len, buf_t *buf);
int write_to_buf_zlib(buf_t *buf, tor_zlib_state_t *state,
                      const char *data, size_t data_len, int done);
int move_buf_to_buf(buf_t *buf_out, buf_t *buf_in, size_t *buf_flushlen);
int fetch_from_buf(char *string, size_t string_len, buf_t *buf);
int fetch_var_cell_from_buf(buf_t *buf, var_cell_t **out, int linkproto);
int fetch_from_buf_http(buf_t *buf,
                        char **headers_out, size_t max_headerlen,
                        char **body_out, size_t *body_used, size_t max_bodylen,
                        int force_complete);
int fetch_from_buf_socks(buf_t *buf, socks_request_t *req,
                         int log_sockstype, int safe_socks);
int fetch_from_buf_line(buf_t *buf, char *data_out, size_t *data_len);

int peek_buf_has_control0_command(buf_t *buf);

void assert_buf_ok(buf_t *buf);
void chunk_repack(chunk_t *chunk);

#endif
