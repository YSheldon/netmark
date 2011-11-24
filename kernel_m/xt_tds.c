#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/kernel.h>

#include <linux/netfilter_ipv4/ip_tables.h>

//module macros
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dunin A.V.");
MODULE_DESCRIPTION("Trafic Difference System's kernel module");

//tdskm struct 4 xtables param
struct xtparam_tdskm_struct
{
	u_int8_t test;
};

//match function
static bool tdskm_match(const struct sk_buff *skb, const struct xt_match_param *param)
{
	const struct iphdr *ip_header;
	const struct xtparam_tdskm_struct *xtp_tds_s = param->matchinfo;

	ip_header = ip_hdr(skb);

	return (ip_header->id % 10 == xtp_tds_s->test);
}

//register struct
static struct xt_match tdskm_struct =
{
	.name = "tds",
	.match = tdskm_match,
	.matchsize = sizeof(struct xtparam_tdskm_struct),
	.me = THIS_MODULE,
};

//initialization
static int __init tdskm_init(void)
{
	return xt_register_match(&tdskm_struct);
}

static void __exit tdskm_unload(void)
{
	xt_unregister_match(&tdskm_struct);
}

module_init(tdskm_init);
module_exit(tdskm_unload);
