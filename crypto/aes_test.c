#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/highmem.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/interrupt.h>
#include "aes_test.h"

/*
 * Need to kmalloc() memory for testing kmap().
 */
#define TVMEMSIZE 16384
#define XBUFSIZE  32768

/*
 * Used by test_cipher()
 */
#define ENCRYPT 1
#define DECRYPT 0


static char *tvmem;



static void hexdump(unsigned char *buf, unsigned int len)
{
  while (len--)
    printk("%02x", *buf++);

  printk("\n");
}


static void test_cipher(char *algo, int enc,
			struct cipher_testvec *template )
{
	unsigned int ret;
	unsigned int tsize;
	unsigned int iv_len;
	unsigned int len;
	char *q;
	struct crypto_blkcipher *tfm;
	char *key;
	struct cipher_testvec *cipher_tv;
	struct blkcipher_desc desc;
	struct scatterlist sg[8];
	const char *e;

	if (enc == ENCRYPT)
	  e = "encryption";
	else
		e = "decryption";

	printk("\ntesting %s %s\n", algo, e);

	tsize = sizeof (struct cipher_testvec);

	if (tsize > TVMEMSIZE) {
		printk("template (%u) too big for tvmem (%u)\n", tsize, TVMEMSIZE);
		return;
	}

	memcpy(tvmem, template, tsize);
	cipher_tv = (void *)tvmem;

	tfm = crypto_alloc_blkcipher(algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	printk("test 1 (%d bit key):\n", cipher_tv[0].klen * 8);

	crypto_blkcipher_clear_flags(tfm, ~0);
	if (cipher_tv[0].wk)
		crypto_blkcipher_set_flags( tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	key = cipher_tv[0].key;

	ret = crypto_blkcipher_setkey(tfm, key, cipher_tv[0].klen);
	if (ret) {
		printk("setkey() failed flags=%x\n", crypto_blkcipher_get_flags(tfm));

		if (!cipher_tv[0].fail)
			goto out;
	}

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
}





static int __init init(void)
{
	tvmem = kmalloc(TVMEMSIZE, GFP_KERNEL);
	if (tvmem == NULL)
		return -ENOMEM;

  test_cipher("cbc(aes)", ENCRYPT, aes_cbc_enc_tv_template );
  test_cipher("cbc(aes)", DECRYPT, aes_cbc_dec_tv_template );
	kfree(tvmem);


  char* vp;

  vp = vmalloc(4*1024*1024);
  if(vp) {
    vfree(vp);
    printk(KERN_ALERT"Allocation Successful");
  }
  else {
    printk(KERN_ALERT"Allocation Failed");
    return -ENOMEM;
  }

	/* We intentionaly return -EAGAIN to prevent keeping
	 * the module. It does all its work from init()
	 * and doesn't offer any runtime functionality 
	 * => we don't need it in the memory, do we?
	 *                                        -- mludvig
	 */
	return -EAGAIN;
}

static void __exit fini(void) { }

module_init(init);
module_exit(fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Module to test understanding of crypto API");
