#ifndef _WIFI_SCANNER_H_
#define _WIFI_SCANNER_H_

#include <string>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>

class WiFiScanner
{

public:
    WiFiScanner(const std::string& wirelesInterface);

    void scan();
private:
    int32_t mInterfaceIndex{-1};
    int32_t mDriverId{-1};

    struct TrigerResult
    {
        int done;
        int aborted;
    };

    nl_sock * mSocket{nullptr};

    int requestScan();

    static int scanDoneCallback(nl_msg* msg, void* arg);
    static int scanDumpCallback(nl_msg *msg, void *arg);
    static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
    static int finish_handler(struct nl_msg *msg, void *arg);
    static int ack_handler(struct nl_msg *msg, void *arg);
    static int no_seq_check(struct nl_msg *msg, void *arg);


};


#endif // _WIFI_SCANNER_H_
