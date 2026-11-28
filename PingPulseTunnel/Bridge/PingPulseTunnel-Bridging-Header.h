#ifndef PingPulseTunnel_Bridging_Header_h
#define PingPulseTunnel_Bridging_Header_h

#include <stdint.h>
#include <sys/ioctl.h>

#define PINGPULSE_CTLIOCGINFO 0xc0644e03UL

struct pingpulse_ctl_info {
    uint32_t ctl_id;
    char     ctl_name[96];
};

struct pingpulse_sockaddr_ctl {
    uint8_t  sc_len;
    uint8_t  sc_family;
    uint16_t ss_sysaddr;
    uint32_t sc_id;
    uint32_t sc_unit;
    uint32_t sc_reserved[5];
};

#endif
