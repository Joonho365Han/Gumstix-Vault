 /* Nibbler based encrypted buffer
 *
 * Basic buffer structre:
 *
 * [ Key/Password ][ Data ]
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
static int file_crypto_open(struct inode *inode, struct file *filp);
static int file_crypto_release(struct inode *inode, struct file *filp);
static ssize_t file_crypto_read(struct file *filp,
		char *buf, size_t count, loff_t *f_pos);
static ssize_t file_crypto_write(struct file *filp,
		const char *buf, size_t count, loff_t *f_pos);
static int file_crypto_fasync(int fd, struct file *filp, int mode);

static void file_crypto_exit(void);
static int file_crypto_init(void);

static void hexdump(unsigned char *buf, unsigned int len);

int encrypt_data(const char *buf, char *cipher_text);
int decrypt_data(const char *buf, char *plain_text);

/* Structure that declares the usual file */
/* access functions */
static struct file_operations file_crypto_fops = {
	.read = file_crypto_read,
	.write = file_crypto_write,
	.open = file_crypto_open,
  .fasync = file_crypto_fasync,
	.release = file_crypto_release,
};

/* Declaration of the init and exit functions */
module_init(file_crypto_init);
module_exit(file_crypto_exit);

/* Global variables of the driver */
/* Major number */
static int file_crypto_major = 61;

/* Buffer to store data */
static char *local_buf;
static char *text;
int text_size;

/* Encrption variables */
#define IV_LEN 16
#define KEY_LEN 16
static unsigned int iv_len;
static struct crypto_blkcipher *tfm;
static struct blkcipher_desc desc;
static char algo[] = "cbc(aes)";

/* TODO: REPLACE THE HARD CODED KEY!!! */
/*char key[] = { 0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0,
			    0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a };*/
unsigned char klen = 16;
/* char iv[] = { 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28,
			    0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58 }; */

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


/* Fasync Stuff */
int writing_data;
struct fasync_struct *async_queue; /* asynchronous readers */

/*******************************************************************************
 * Functions
 ******************************************************************************/

static int file_crypto_init(void)
{
	int result;

  printk(KERN_ALERT "init called\n");
	/* Registering device */
	result = register_chrdev(file_crypto_major, "/dev/file_crypto", &file_crypto_fops);

	if (result < 0)
	{
		printk(KERN_ALERT
			"encrypt: cannot obtain major number %d\n", file_crypto_major);
		return result;
	}


  /* Misc initializations */
  writing_data = 0;
  iv_len = 16;
  text_size = 0;

	//printk(KERN_ALERT "Inserting encrypt module\n");
	return 0;
}

static void file_crypto_exit(void)
{
	/* Freeing the major number */
	unregister_chrdev(file_crypto_major, "file_crypto");

	/* Freeing buffer memory */
	if (local_buf) kfree(local_buf);
	if (text) kfree(text);

	printk(KERN_ALERT "Removing encrypt module\n");
}

static int file_crypto_open(struct inode *inode, struct file *filp)
{
	/* Success */
	return 0;
}

static int file_crypto_release(struct inode *inode, struct file *filp)
{
  /* Fasync */
  if( writing_data ) file_crypto_fasync(-1, filp, 0);

	/* Success */
	return 0;
}

static ssize_t file_crypto_read(struct file *filp, char *buf,
							size_t count, loff_t *f_pos)
{

  printk("\n\nREAD CALLED\n");
  printk("RAW:\nread fpos = %d\n, count = %d\ntext_size = %d\n", *f_pos, count, text_size);
  writing_data = 0;

  printk("Text:\n");
  hexdump(text, text_size);
	/* end of buffer reached */
  /*
	if (*f_pos >= text_size) {
    printk(KERN_ALERT "end of buffer reached\n");
    return 0;
  }
  */

	/* do not go over then end */
  /*
	if (count > text_size - *f_pos) {
    printk(KERN_ALERT "Reading to end of buffer\n");
    count = text_size - *f_pos;
  }
  */

  if( text_size < 1 ) {
    printk(KERN_ALERT "text buffer empty\n");
    return 0;
  }

  // force read of text size
  count = text_size;

  //printk("read fpos = %d, count = %d\ntext_size = %d\n", *f_pos, count, text_size);
  /* Transfering data to user space */
	//if (copy_to_user(buf, text + *f_pos, count)) return -EFAULT;
	if (copy_to_user(buf, text, count)) return -EFAULT;

  //printk("Encrypted data passed to user:\n");
  //hexdump(text + *f_pos, count);

  if(local_buf) kfree(local_buf);
  if(text) kfree(text);

  text_size = 0;

	*f_pos += count;
	return count;
}

/* [ Content Size ][ Content ][ Key ][ e|d ] */
static ssize_t file_crypto_write(struct file *filp, const char *buf,
							size_t count, loff_t *f_pos)
{
  int bytes_encrypted;
  int content_size;
  char *content;
  char *key;



  printk(KERN_ALERT "Write Called, Count=%d\n",count);
  writing_data = 1; // for fasync

	local_buf = kmalloc(count, GFP_KERNEL);

	if (!local_buf)
	{
		printk(KERN_ALERT "Insufficient kernel memory\n"); 
		return -ENOMEM;
	}

  if (copy_from_user( local_buf, buf, count ))
  {
    printk("crypto module: copy from user error\n");
    return -EFAULT;
  }

  content_size = 0;
  content_size |= ((int)local_buf[0]) << 24;
  content_size |= ((int)local_buf[1]) << 16;
  content_size |= ((int)local_buf[2]) << 8;
  content_size |= ((int)local_buf[3]);

  printk(KERN_ALERT"Content Size: %d\n", content_size);

  content = &local_buf[4];

  key = &local_buf[ 4+content_size ];


	text = kmalloc(content_size, GFP_KERNEL);
	if (!text)
	{
		printk(KERN_ALERT "Insufficient kernel memory for text buffer\n"); 
		return -ENOMEM;
	}

  printk(KERN_ALERT"ED flag: %02x\n",local_buf[count-1]);

  if ( local_buf[count-1] ) { // encrypt
    bytes_encrypted = encrypt_data(local_buf, text);
  }
  else { // decrypt
    bytes_encrypted = decrypt_data(local_buf, text);
  }

  if ( bytes_encrypted != content_size )
  {
    printk(KERN_ALERT "Did not encrypt or decrypt the right amount of data!\nBytes_encrypted: %d\ncontent_size: %d\n",bytes_encrypted,content_size);
    return -EFAULT;
  }

  text_size = bytes_encrypted;
  printk(KERN_ALERT "Text Size: %d\n", text_size);

  /* Send async signal */
	if (async_queue) kill_fasync(&async_queue, SIGIO, POLL_IN);

	return count;
}

static void hexdump(unsigned char *buf, unsigned int len)
{
  while (len--)
    printk("%02x", *buf++);

  printk("\n");
}


static int file_crypto_fasync(int fd, struct file *filp, int mode) {
  printk("FASYNC Called\n");
	return fasync_helper(fd, filp, mode, &async_queue);
}

/* [ Size ][ Contnet ][ Key ][ e|d ] */
/* IV is stored at the begining of the cipher text buffer */
int encrypt_data(const char *buf, char *cipher_text)
{
	int ret;

  int content_size;
  char *content;
  char *key;
  char *tmp_txt;

  char *iv;
	struct scatterlist sg[1]; // does this need to be protected? can it be global?

  printk(KERN_ALERT"Encrypting Data");

  content_size = 0;
  content_size |= ((int)buf[0]) << 24;
  content_size |= ((int)buf[1]) << 16;
  content_size |= ((int)buf[2]) << 8;
  content_size |= ((int)buf[3]);

  content = (char*)&buf[4];

  key =  (char*)&buf[ 4+content_size ];


	iv = kmalloc(iv_len, GFP_KERNEL);
  if(!iv)
  {
		printk(KERN_ALERT "Insufficient kernel memory for IV\n"); 
		return -ENOMEM;
	}

  /* CRYTO STUFF */

  /* TODO: Pad the input to match the key size */
  /* TODO: Check that data is appropriate length: len % key_len == 0 */

	tfm = crypto_alloc_blkcipher(algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk("failed to load transform for %s: %ld\n", algo, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	desc.tfm = tfm;
	desc.flags = 0;

	crypto_blkcipher_clear_flags(tfm, ~0);

  /*  TODO: Handle Key. Get it, decrypt it, call setkey */
	ret = crypto_blkcipher_setkey(tfm, key, klen);
	if (ret) {
		printk("setkey() failed flags=%x\n", crypto_blkcipher_get_flags(tfm));
    printk(KERN_ALERT "Open Failed!\n");
	}


  printk(KERN_ALERT "Plain text from user:\n");
  hexdump(content, content_size);

  /* Encrypt plain text from user */
	sg_set_buf(&sg[0], content, content_size);
  get_random_bytes( iv, iv_len);
  crypto_blkcipher_set_iv(tfm, iv, iv_len);
	ret = crypto_blkcipher_encrypt(&desc, sg, sg, content_size);

	if (ret) {
		printk("Encryption failed flags=%x\n", desc.flags);
    return 0; // no data written
	}


  printk(KERN_ALERT "Encryption Done!\n");
  /* This appears to get the decrypted data */
	tmp_txt = kmap(sg->page) + sg->offset;
  memcpy(cipher_text, tmp_txt, content_size);


  printk("Cipher text:\n");
	hexdump(cipher_text, content_size);

  /*  Save last block as next IV */
  //memcpy(iv, &cipher_text[ count - (int)*iv_len], (int)*iv_len);
  //printk("NEW IV VALUE:\n");
  //hexdump(iv, (int)*iv_len);

  /* Free Transform */
  crypto_free_blkcipher(tfm);

	return content_size;
}


/* [ Size ][ Contnet ][ Key ][ e|d ] */
/* The first 16 bytes of content is the IV */
int decrypt_data(const char *buf, char *plain_text)
{
  int content_size;
  char *iv;
  char *content;
  char *key;

	struct scatterlist sg[1]; // does this need to be protected? can it be global?
  int ret;

  printk(KERN_ALERT"Encrypting Data");

  content_size = 0;
  content_size |= ((int)buf[0]) << 24;
  content_size |= ((int)buf[1]) << 16;
  content_size |= ((int)buf[2]) << 8;
  content_size |= ((int)buf[3]);

  iv = (char*)&buf[4];
  content = (char*)&buf[20];

  key = (char*)&buf[ 4+content_size ];

  /* CRYPTO STUFF */

  /* TODO: Un-pad the stored data */
  /* TODO: Load IV for file */

	tfm = crypto_alloc_blkcipher(algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	desc.tfm = tfm;
	desc.flags = 0;

	crypto_blkcipher_clear_flags(tfm, ~0);

	ret = crypto_blkcipher_setkey(tfm, key, klen);
	if (ret) {
		printk("setkey() failed flags=%x\n", crypto_blkcipher_get_flags(tfm));
    printk(KERN_ALERT "Open Failed!\n");
	}

  //printk("Encrypted data from buffer:\n");
  //hexdump(content, content_size);

  /* Decrypt the data */
	sg_set_buf(&sg[0], content, content_size);
	crypto_blkcipher_set_iv(tfm, iv, iv_len);
	ret = crypto_blkcipher_decrypt(&desc, sg, sg, content_size);

	if (ret) {
		printk("Decription failed flags=%x\n", desc.flags);
    printk("Failed to decrypt during read!\n");
    return 0; // no data read
	}

  /* This appears to get the decrypted data */
	plain_text = kmap(sg->page) + sg->offset;
	//hexdump(plain_text, count);

  /* Free Transform */
  crypto_free_blkcipher(tfm);

	return content_size;
}

