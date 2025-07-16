#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

#define NUM_BUF (4096-1)

#define BURST_SIZE 32

#define ENABLE_SEND 1

#ifdef ENABLE_SEND
static uint32_t gSrcIp;
static uint32_t gDstIp;
static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];
static uint16_t gSrcPort;
static uint16_t gDstPort;
#endif

int gDpdkPortId = 0;

// 以太网端口默认配置
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

// 初始化以太网端口
static void ng_init_port(struct rte_mempool *mbuf_pool)
{
	// 检查可用的以太网设备数量
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if(nb_sys_ports == 0)
    {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

	// 获取设备信息
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

	// 配置端口：1个接收队列，1个发送队列
    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;

    // 设置接收队列
    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);
    if(rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0)
    {
        rte_exit(EXIT_FAILURE, "could not set up rx\n");
    }

#ifdef ENABLE_SEND
    // 设置发送队列（仅在启用发送功能时）
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if(rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0)
    {
        rte_exit(EXIT_FAILURE, "could not set up tx\n");
    }
#endif
    // 启动以太网端口
    if(rte_eth_dev_start(gDpdkPortId) < 0)
    {
        rte_exit(EXIT_FAILURE, "could not start\n");
    }

}



static int ng_encode_udp_pkt(uint8_t* msg, unsigned char* data, uint16_t total_len)
{
    // 1. 构建以太网帧头
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    
    // 2. 构建IPv4头
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = gSrcIp;
    ip->dst_addr = gDstIp;
    ip->hdr_checksum = 0; // 先清零后计算校验和
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3. 构建UDP头
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = gSrcPort;
    udp->dst_port = gDstPort;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);
    rte_memcpy((uint8_t*)(udp+1), data, udplen); // 封装回显数据
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	// struct in_addr addr;
	// addr.s_addr = gSrcIp;
	// printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort));

	// addr.s_addr = gDstIp;
	// printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));
    return 0;
}

// 准备发送的UDP包
static struct rte_mbuf * ng_send(struct rte_mempool *mbuf_pool, unsigned char* data, uint16_t length)
{
    const unsigned total_len = length + 14 + 20 + 8;

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf)
    {
        rte_exit(EXIT_FAILURE, "Error With mbuf\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    // 获取mbuf的数据区域指针
    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    // 构建UDP包
    ng_encode_udp_pkt(pktdata, data, total_len);

    return mbuf;
}

int main(int argc, char *argv[])
{
	// 1.初始化
	// 初始化DPDK环境抽象层(EAL)
    if(rte_eal_init(argc, argv) < 0)
    {
        rte_exit(EXIT_FAILURE, "Error With EAL init\n");
    }

	// 创建mbuf内存池
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_BUF, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(mbuf_pool == NULL)
    {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

	// 初始化以太网端口
    ng_init_port(mbuf_pool);

	// 获取本机MAC地址
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr*) gSrcMac);

    // 2. 主处理循环
    while(1)
    {
        // 接收缓冲区数组
        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
        if(num_recvd > BURST_SIZE)
        {
            rte_exit(EXIT_FAILURE, "error recv\n");
        }

        // 处理每个接收到的数据包
        unsigned i = 0;
        for(i = 0; i < num_recvd; i++)
        {
           // 解析以太网头
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            // 只处理IPv4包
            if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
            {
                rte_pktmbuf_free(mbufs[i]);
                continue;
            }
            // 解析IPv4头
            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct  rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));
            
            // 只处理UDP包
            if(iphdr->next_proto_id == IPPROTO_UDP)
            {
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)((unsigned char*)iphdr + sizeof(struct rte_ipv4_hdr));
#ifdef ENABLE_SEND
                // 为回显设置五元组（全局变量）
                rte_memcpy(gDstMac ,ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

                rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
                rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

                rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
                rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));
#endif
                // 获取UDP包总长度
                uint16_t length = ntohs(udphdr->dgram_len);
                *((char*)udphdr + length) = '\0';

                // 打印接收信息
                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("src: %s:%d  ", inet_ntoa(addr), ntohs(udphdr->src_port));

                addr.s_addr = iphdr->dst_addr;
                printf("dst: %s:%d %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), (char*)(udphdr+1));
#ifdef ENABLE_SEND
                struct rte_mbuf *txbuf = ng_send(mbuf_pool, (uint8_t*)(udphdr+1), length);
                rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                rte_pktmbuf_free(txbuf);
#endif
                rte_pktmbuf_free(mbufs[i]);
            }
        }


    }
    return 0;
}