 /* Nibbler based encrypted buffer
 *
 * Basic buffer structre:
 *
 * [ Encrypted Key][ char IV_len][ IV ][Encrypted Data][ Encrypted Data length ]
 *
 * The IV is prepended onto the encrypted data because to the decryption, it
 * looks like a block of cipher text.
 *
 * The encrypted key will be a randomly generated (long?) key that is encrypted
 * with the user's password.
 *
 * The data length is at the end so it can be encrypted. It will probably be a 
 * whole block (128 or 256 bits) but contain a single uint32 representing the 
 * number of BYTES in the message
 *
 */


/* Necessary includes for device drivers */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/fs.h> /* everything... */
#include <linux/errno.h> /* error codes */
#include <linux/types.h> /* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h> /* O_ACCMODE */
#include <asm/system.h> /* cli(), *_flags */
#include <asm/uaccess.h> /* copy_from/to_user */

#include <linux/err.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/highmem.h>
//#include <linux/moduleparam.h>
#include <linux/timex.h>
#include <linux/interrupt.h>
#include <linux/random.h>
#include "aes_test.h"

MODULE_LICENSE("Dual BSD/GPL");

/* Declaration of memory.c functions */
static int encrypt_open(struct inode *inode, struct file *filp);
static int encrypt_release(struct inode *inode, struct file *filp);
static ssize_t encrypt_read(struct file *filp,
		char *buf, size_t count, loff_t *f_pos);
static ssize_t encrypt_write(struct file *filp,
		const char *buf, size_t count, loff_t *f_pos);
static int encrypt_fasync(int fd, struct file *filp, int mode);

static void encrypt_exit(void);
static int encrypt_init(void);

static void hexdump(unsigned char *buf, unsigned int len);

static int proc_read( char *page, char **start, off_t off,
    int count, int *eof, void *data);
static int proc_write( struct file *filp, const char __user *buff,
    unsigned long len, void *data);

/* Structure that declares the usual file */
/* access functions */
static struct file_operations encrypt_fops = {
	.read = encrypt_read,
	.write = encrypt_write,
	.open = encrypt_open,
  .fasync = encrypt_fasync,
	.release = encrypt_release,
};

/* Declaration of the init and exit functions */
module_init(encrypt_init);
module_exit(encrypt_exit);


/* Module Parameters */
static unsigned capacity = 1024;
static unsigned bite = 256;
static char algo[] = "cbc(aes)";
module_param(capacity, uint, S_IRUGO);
/* module_param(bite, uint, S_IRUGO); */
/* module_param(algo, charp, S_IRUGO); */

/* Global variables of the driver */
/* Major number */
static int encrypt_major = 61;

/* Buffer to store data */
static char *block_buffer;
static int block_len;
static char *encrypt_buffer;
static int encrypt_len;

/* Encrption variables */
#define IV_LEN 16
static char *iv_len;
static int new_iv;
static struct crypto_blkcipher *tfm;
static struct blkcipher_desc desc;

/* TODO: REPLACE THE HARD CODED KEY!!! */
char key[] = { 0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0,
			    0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a };
unsigned char klen = 16;
/* char iv[] = { 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28,
			    0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58 }; */
static char *iv;

/* Sample Input
		.input  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
		.ilen   = 32,
*/
/* Sample Result 
		.result = { 0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a,
			    0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1, 0xdc, 0x0a,
			    0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9,
			    0x1b, 0x82, 0x66, 0xbe, 0xa6, 0xd6, 0x1a, 0xb1 },
		.rlen   = 32,
*/


/* Proc File Stuff */
#define MAX_PROC_LEN 4096
#define MAX_PATH_LEN 4096
static struct proc_dir_entry *proc_entry;
static char *proc_buffer;
static char *file_path;

/* Fasync Stuff */
int writing_data;
struct fasync_struct *async_queue; /* asynchronous readers */

/*******************************************************************************
 * Functions
 ******************************************************************************/

static int encrypt_init(void)
{
	int result;

	/* Registering device */
	result = register_chrdev(encrypt_major, "/dev/encrypt", &encrypt_fops);

	if (result < 0)
	{
		printk(KERN_ALERT
			"encrypt: cannot obtain major number %d\n", encrypt_major);
		return result;
	}

	/* Allocating memory for the buffer */
  /* [ iv_len] [ iv ] [ encrypted data ] */
	//encrypt_buffer = kmalloc(capacity, GFP_KERNEL);
  block_len = 1 + IV_LEN + capacity;
	block_buffer = kmalloc(block_len, GFP_KERNEL);

	if (!block_buffer)
	{
		printk(KERN_ALERT "Insufficient kernel memory\n"); 
		result = -ENOMEM;
		goto fail;
	}

	memset(block_buffer, 0, block_len);

  iv_len = &block_buffer[0];
  iv = &block_buffer[1];
  encrypt_buffer = &block_buffer[1 + IV_LEN];

	encrypt_len = 1 + IV_LEN;

  /* Set up Proc file */
  proc_entry = create_proc_entry( "encrypt", 0644, NULL );

  if (proc_entry == NULL) {
    result = -ENOMEM;
    printk(KERN_INFO "Encrypt error: Couldn't create proc entry\n");
    goto fail;
  }

  proc_entry->read_proc = proc_read;
  proc_entry->write_proc = proc_write;
  proc_entry->owner = THIS_MODULE;

	proc_buffer= kmalloc( MAX_PROC_LEN, GFP_KERNEL);

	if (!proc_buffer)
	{
		printk(KERN_ALERT "Encrypt: Insufficient kernel memory for proc_buffer\n"); 
		result = -ENOMEM;
		goto fail;
	}

	memset(proc_buffer, 0, MAX_PROC_LEN);

	file_path = kmalloc( MAX_PATH_LEN, GFP_KERNEL);

	if (!file_path)
	{
		printk(KERN_ALERT "Encrypt: Insufficient kernel memory for file_path\n"); 
		result = -ENOMEM;
		goto fail;
	}

	memset(file_path, 0, MAX_PATH_LEN);


  /* TODO: Load encrypted key */
  /* Use One password for entire drive */

  /* Misc initializations */
  writing_data = 0;
  new_iv = 1;
  *iv_len = 16;

	printk(KERN_ALERT "Inserting encrypt module\n");
	return 0;

fail:
	encrypt_exit();
	return result;
}

static void encrypt_exit(void)
{
	/* Freeing the major number */
	unregister_chrdev(encrypt_major, "encrypt");

	/* Freeing buffer memory */
	if (encrypt_buffer) kfree(encrypt_buffer);
	if (proc_buffer) kfree(proc_buffer);
  if (file_path) kfree(file_path);

	printk(KERN_ALERT "Removing encrypt module\n");

}

static int encrypt_open(struct inode *inode, struct file *filp)
{
	/* Success */
	return 0;
}

static int encrypt_release(struct inode *inode, struct file *filp)
{
  printk("Release Called, writing_data=%d\n", writing_data);

  /* Fasync cleanup */
  if( writing_data ) encrypt_fasync(-1, filp, 0);

	/* Success */
	return 0;
}

static ssize_t encrypt_read(struct file *filp, char *buf,
							size_t count, loff_t *f_pos)
{
  //int ret;
  char *local_buf;
	//char *plain_text;
	//struct scatterlist sg[1]; // does this need to be protected? can it be global?

  printk("READ CALLED\n");
  writing_data = 0;

  /* CRYPTO STUFF */

  /* TODO: Un-pad the stored data */
  /* TODO: Load IV for file */

  /*
	tfm = crypto_alloc_blkcipher(algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	desc.tfm = tfm;
	desc.flags = 0;

	crypto_blkcipher_clear_flags(tfm, ~0);

  */
  /*  TODO: Handle Key. Get it, decrypt it, call setkey */
  /*
	ret = crypto_blkcipher_setkey(tfm, key, klen);
	if (ret) {
		printk("setkey() failed flags=%x\n", crypto_blkcipher_get_flags(tfm));
    printk(KERN_ALERT "Open Failed!\n");
	}
  */
  /* REGULAR FILE IO STUFF */

	/* end of buffer reached */
	if (*f_pos >= block_len)
	{
		return 0;
	}

	/* do not go over then end */
	if (count > block_len - *f_pos)
		count = block_len - *f_pos;

	/* do not send back more than a bite */
	/* if (count > bite) count = bite; */

  /* Allocate memory for local buffer. 
   * Plain text will exist here, assuming the encryption happens in place */
  /*
	local_buf = kmalloc(count, GFP_KERNEL);
	if (!local_buf)
	{
    printk(KERN_ALERT "Read Error: ");
		printk(KERN_ALERT "Insufficient kernel memory for local buffer\n"); 
    return 0; // no data read
	}
  */

  /* Move the encrypted data the local buffer */
  /*
  memcpy(local_buf, encrypt_buffer + *f_pos, count);

  printk("Encrypted data from buffer:\n");
  hexdump(local_buf, count);
  */
  /* Set up decryption */
  /*
	sg_set_buf(&sg[0], local_buf, count);
	iv_len = crypto_blkcipher_ivsize(tfm);
	if (iv_len) crypto_blkcipher_set_iv(tfm, iv, iv_len);

  */
  /* Decrypt the data */
  /*
	ret = crypto_blkcipher_decrypt(&desc, sg, sg, count);


	if (ret) {
		printk("Decription failed flags=%x\n", desc.flags);
    printk("Failed to decrypt during read!\n");
    return 0; // no data read
	}
  */

  /* This appears to get the decrypted data */
  /*
	plain_text = kmap(sg->page) + sg->offset;

	hexdump(plain_text, count);

  */
	/* Transfering data to user space */
	if (copy_to_user(buf, block_buffer + *f_pos, count)) return -EFAULT;

  printk("encrypt_read count=%lu\n", (long unsigned)count);

  printk("Encrypted data passed to user:\n");
  hexdump(block_buffer + *f_pos, count);


  /* Overwrite plaintext in temporary buffer */
  /*
  memcpy(local_buf, encrypt_buffer + *f_pos, count);
  kfree(local_buf);
  */
  /* Free Transform */
  /* crypto_free_blkcipher(tfm); */

	/* Changing reading position as best suits */
	*f_pos += count;
	return count;
}

static ssize_t encrypt_write(struct file *filp, const char *buf,
							size_t count, loff_t *f_pos)
{
	int ret;
  char *local_buf;
  char *cipher_text;
	struct scatterlist sg[1]; // does this need to be protected? can it be global?

  printk(KERN_ALERT "Write Called, Count=%d\n",count);
  writing_data = 1;

  /* CRYTO STUFF */

  /* TODO: Pad the input to match the key size */
  /* TODO: Load IV for file */
  /* TODO: Store the last encrypted block of a write to use as the next IV */
  /* TODO: Check that data is appropriate length: len % key_len == 0 */

	tfm = crypto_alloc_blkcipher(algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	desc.tfm = tfm;
	desc.flags = 0;

	crypto_blkcipher_clear_flags(tfm, ~0);
  /*
	if (cipher_tv[0].wk)
		crypto_blkcipher_set_flags( tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	key = cipher_tv[0].key;
  */

  /*  TODO: Handle Key. Get it, decrypt it, call setkey */
	ret = crypto_blkcipher_setkey(tfm, key, klen);
	if (ret) {
		printk("setkey() failed flags=%x\n", crypto_blkcipher_get_flags(tfm));
    printk(KERN_ALERT "Open Failed!\n");
	}

	/* end of buffer reached */
	if (*f_pos >= capacity)
	{
		printk(KERN_INFO
			"write called: process id %d, command %s, count %d, buffer full\n",
			current->pid, current->comm, count);
		return -ENOSPC;
	}

	/* do not eat more than a bite */
	/* if (count > bite) count = bite; */

	/* do not go over the end */
	if (count > capacity - *f_pos)
		count = capacity - *f_pos;

  /* Allocate memory for local buffer.
   * Plain text will exist here, assuming the encryption happens in place */
	local_buf = kmalloc(count, GFP_KERNEL);
	if (!local_buf)
	{
    printk(KERN_ALERT "Write Error: ");
		printk(KERN_ALERT "Insufficient kernel memory for local buffer\n");
    return 0; // no data written
	}


  /* Get plain text from user */
	if (copy_from_user(local_buf, buf, count)) return -EFAULT;

  printk(KERN_ALERT "Plain text from user:\n");
  hexdump(local_buf, count);

  /* Encrypt plain text from user */
	sg_set_buf(&sg[0], local_buf, count);
	//iv_len = crypto_blkcipher_ivsize(tfm); // FOR NOW THE IV HAS TO BE 16 BYTES
  if(new_iv) get_random_bytes( iv, (int)*iv_len);
  crypto_blkcipher_set_iv(tfm, iv, (int)*iv_len);
	ret = crypto_blkcipher_encrypt(&desc, sg, sg, count);

	if (ret) {
		printk("Encryption failed flags=%x\n", desc.flags);
    return 0; // no data written
	}


  printk(KERN_ALERT "Encryption Done!\n");
  /* This appears to get the decrypted data */
	cipher_text = kmap(sg->page) + sg->offset;

  printk("Cipher text:\n");
	hexdump(cipher_text, count);

  /*  Save last block as next IV */
  memcpy(iv, &cipher_text[ count - (int)*iv_len], (int)*iv_len);
  printk("NEW IV VALUE:\n");
  hexdump(iv, (int)*iv_len);

  /* Copy the cipher text into the buffer */
  memcpy(encrypt_buffer + *f_pos, cipher_text, count);


  /* Free local_buf. This should not contain plain text anymore
   * and is less sensitive now
   */
  kfree(local_buf);

  /* Free Transform */
  crypto_free_blkcipher(tfm);

	*f_pos += count;

  /* Add constants for iv_len and iv because they will always be read */
	encrypt_len = *f_pos + 1 + IV_LEN;
  printk("ENCRYPT_LEN @ write: %d\n",encrypt_len);

  /* Send async signal */
	if (async_queue) kill_fasync(&async_queue, SIGIO, POLL_IN);

	return count;
}


static int check_password(char* input ) {

  char* input_hash;
  char* stored_hash;


  // TODO: Make sure password is salted

  // Hash input password to generate AES encryption key


  // Hash the hashed password to compare it to the stored hash


  if( strcmp(stored_hash, input_hash) ) {
    // The passwords did not match

    // clear memory

    return -1;
  }

  return 0;
}

static void hexdump(unsigned char *buf, unsigned int len)
{
  while (len--)
    printk("%02x", *buf++);

  printk("\n");
}

static int proc_read( char *page, char **start, off_t off,
                   int count, int *eof, void *data )
{
  // TODO: print new_iv
  int proc_len;
  printk("PROC_READ\n");

  if (off > 0) {
    *eof = 1;
    return 0;
  }

  proc_len = sprintf(proc_buffer, "File_Path:\t%s\nBuffer_Length:\t%d\nNew_IV:\t%d\n",
      file_path, encrypt_len, new_iv );

  printk("PROC_LEN = %d\n",proc_len);
  printk("%s\n", proc_buffer);
  memcpy(page, proc_buffer, proc_len);

  return proc_len;
}

static int proc_write( struct file *filp, const char __user *buff,
    unsigned long count, void *data)
{

  // TODO write new_iv
  if ( count > MAX_PATH_LEN) {
    printk(KERN_ALERT "Encrypt: Proc file too large for proc buffer!\n");
    return -ENOSPC;
  }

  memset(proc_buffer, 0, MAX_PROC_LEN);
  if (copy_from_user( proc_buffer, buff, count )) {
    printk("Encrypt: Proc write copy from user error\n");
    return -EFAULT;
  }

  sscanf(proc_buffer, "%s %d", file_path, &new_iv);

  printk("Encrypt: Proc write copy from user success\n");
  return count;
}


static int encrypt_fasync(int fd, struct file *filp, int mode) {
  printk("FASYNC Called\n");
	return fasync_helper(fd, filp, mode, &async_queue);
}


