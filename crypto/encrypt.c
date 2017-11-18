/* Nibbler based encrypted buffer 
 *
 * Basic buffer structre:
 *
 * [ Encrypted Key][ IV ][Encrypted Data][ Encrypted Data length ]
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

#include "aes_test.h"
#include "file_struct.h"


MODULE_LICENSE("Dual BSD/GPL");

/* Declaration of memory.c functions */
static int encrypt_open(struct inode *inode, struct file *filp);
static int encrypt_release(struct inode *inode, struct file *filp);
static ssize_t encrypt_read(struct file *filp,
		char *buf, size_t count, loff_t *f_pos);
static ssize_t encrypt_write(struct file *filp,
		const char *buf, size_t count, loff_t *f_pos);
static void encrypt_exit(void);
static int encrypt_init(void);

static void hexdump(unsigned char *buf, unsigned int len);



/* Structure that declares the usual file */
/* access functions */
struct file_operations encrypt_fops = {
	read: encrypt_read,
	write: encrypt_write,
	open: encrypt_open,
	release: encrypt_release
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


static struct crypto_data {
	char key[MAX_KEYLEN] __attribute__ ((__aligned__(4)));
	char iv[MAX_IVLEN];
	char input[bite];
	unsigned char klen;
	unsigned short ilen;
};


/* Global variables of the driver */
/* Major number */
static int encrypt_major = 61;

/* Buffer to store data */
static char *encrypt_buffer;
static int encrypt_len;


/* Encrption variables */
static unsigned int iv_len;
static struct crypto_blkcipher *tfm;
static struct blkcipher_desc desc;

/* TODO: REPLACE THE HARD CODED KEY!!! */
char key[] = { 0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0,
			    0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a };
unsigned char klen   = 16;
char iv[] = { 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28,
			    0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58 };

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
	encrypt_buffer = kmalloc(capacity, GFP_KERNEL);
	if (!encrypt_buffer)
	{
		printk(KERN_ALERT "Insufficient kernel memory\n"); 
		result = -ENOMEM;
		goto fail;
	}
	memset(encrypt_buffer, 0, capacity);
	encrypt_len = 0;


  /* TODO: Load encrypted key */
  /* Use One password for entire drive */


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
	if (encrypt_buffer)
	{
		kfree(encrypt_buffer);
	}

	printk(KERN_ALERT "Removing encrypt module\n");

}

static int encrypt_open(struct inode *inode, struct file *filp)
{
	unsigned int ret;

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

  /* This stuff does not need to be in open 
	sg_set_buf(&sg[0], cipher_tv[0].input, cipher_tv[0].ilen);

	iv_len = crypto_blkcipher_ivsize(tfm);
  
	if (iv_len)
		crypto_blkcipher_set_iv(tfm, cipher_tv[0].iv, iv_len);

	len = cipher_tv[0].ilen;
	ret = enc ?
		crypto_blkcipher_encrypt(&desc, sg, sg, len) :
		crypto_blkcipher_decrypt(&desc, sg, sg, len);

	if (ret) {
		printk("%s () failed flags=%x\n", e, desc.flags);
		goto out;
	}

	q = kmap(sg[0].page) + sg[0].offset;
	hexdump(q, cipher_tv[0].rlen);

	printk("%s\n", memcmp(q, cipher_tv[0].result, cipher_tv[0].rlen) ? "fail" : "pass");

out:
	crypto_free_blkcipher(tfm);

  */
	/* Success */
	return 0;
}

static int encrypt_release(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO "release called: process id %d, command %s\n",
		current->pid, current->comm);
	/* Success */
	return 0;
}

static ssize_t encrypt_read(struct file *filp, char *buf, 
							size_t count, loff_t *f_pos)
{ 
  int ret;
  char *local_buf;
	char *plain_text;
	struct scatterlist sg[1]; // does this need to be protected? can it be global?

  /* TODO: Un-pad the stored data


	/* end of buffer reached */
	if (*f_pos >= encrypt_len)
	{
		return 0;
	}

	/* do not go over then end */
	if (count > encrypt_len - *f_pos)
		count = encrypt_len - *f_pos;

	/* do not send back more than a bite */
	if (count > bite) count = bite;

  /* Allocate memory for local buffer. 
   * Plain text will exist here, assuming the encryption happens in place */
	local_buf = kmalloc(count, GFP_KERNEL);
	if (!local_buf)
	{
    printk(KERN_ALERT "Read Error: ");
		printk(KERN_ALERT "Insufficient kernel memory for local buffer\n"); 
    return 0; // no data read
	}

  /* Move the encrypted data the local buffer */
  memcpy(local_buf, encrypt_buffer + *f_pos, count);

  printk("Encrypted data from buffer:\n");
  hexdump(local_buf, count);

  /* Set up decryption */
	sg_set_buf(&sg[0], local_buf, count);
	iv_len = crypto_blkcipher_ivsize(tfm);
	if (iv_len) crypto_blkcipher_set_iv(tfm, iv, iv_len);

  /* Decrypt the data */
	ret = crypto_blkcipher_decrypt(&desc, sg, sg, count);

  
	if (ret) {
		printk("Decription failed flags=%x\n", desc.flags);
    printk("Failed to decrypt during read!\n");
    return 0; // no data read
	}

  /* This appears to get the decrypted data */
	plain_text = kmap(sg->page) + sg->offset;

  printk("Decrypted data passed to user:\n");
	hexdump(plain_text, count);



	/* Transfering data to user space */ 
	if (copy_to_user(buf, plain_text, count))
	{
		return -EFAULT;
	}

  /* Overwrite plaintext in temporary buffer */
  memcpy(local_buf, encrypt_buffer + *f_pos, count);
  kfree(local_buf);
  
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


  /* TODO: Pad the input to match the key size

  printk(KERN_ALERT "Write Called Count=%d\n",count);

	/* end of buffer reached */
	if (*f_pos >= capacity)
	{
		printk(KERN_INFO
			"write called: process id %d, command %s, count %d, buffer full\n",
			current->pid, current->comm, count);
		return -ENOSPC;
	}

	/* do not eat more than a bite */
	if (count > bite) count = bite;

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
	if (copy_from_user(local_buf, buf, count))
	{
		return -EFAULT;
	}

  printk(KERN_ALERT "Plain text from user:\n");
  hexdump(local_buf, count);

  /* Encrypt plain text from user */
	sg_set_buf(&sg[0], local_buf, count);

  printk(KERN_ALERT "SG set!\n");
	iv_len = crypto_blkcipher_ivsize(tfm);
  
	if (iv_len) crypto_blkcipher_set_iv(tfm, iv, iv_len);
  printk(KERN_ALERT "IV set!\n");

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

  /* Copy the cipher text into the buffer */
  memcpy(encrypt_buffer + *f_pos, cipher_text, count);


  /* Free local_buf. This should not contain plain text anymore
   * and is less sensitive now
   */
  kfree(local_buf);

	*f_pos += count;
	encrypt_len = *f_pos;

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


