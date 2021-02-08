#include "WiFiScanner.h"
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>
#include <netlink/genl/family.h>
#include <linux/nl80211.h>
#include <net/if.h>

static void mac_addr_n2a(char *mac_addr, unsigned char *arg) {
   // From http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c.
   int i, l;

   l = 0;
   for (i = 0; i < 6; i++) {
       if (i == 0) {
           sprintf(mac_addr+l, "%02x", arg[i]);
           l += 2;
       } else {
           sprintf(mac_addr+l, ":%02x", arg[i]);
           l += 3;
       }
   }
}


static void print_ssid(unsigned char *ie, int ielen) {
   uint8_t len;
   uint8_t *data;
   int i;

   while (ielen >= 2 && ielen >= ie[1]) {
       if (ie[0] == 0 && ie[1] >= 0 && ie[1] <= 32) {
           len = ie[1];
           data = ie + 2;
           for (i = 0; i < len; i++) {
               if (isprint(data[i]) && data[i] != ' ' && data[i] != '\\') printf("%c", data[i]);
               else if (data[i] == ' ' && (i != 0 && i != len -1)) printf(" ");
               else printf("\\x%.2x", data[i]);
           }
           break;
       }
       ielen -= ie[1] + 2;
       ie += ie[1] + 2;
   }
}


WiFiScanner::WiFiScanner(const std::string & wirelesInterface)
{

    mInterfaceIndex = if_nametoindex(wirelesInterface.c_str());

    mSocket = nl_socket_alloc();
    genl_connect(mSocket);

    mDriverId = genl_ctrl_resolve(mSocket, "nl80211");

    
}

void WiFiScanner::scan()
{

    int err = requestScan();
    if (err != 0) {
        printf("do_scan_trigger() failed with %d.\n", err);
        //return err
        return;
    }


    // Now get info for all SSIDs detected.
    struct nl_msg *msg = nlmsg_alloc();  // Allocate a message.
    genlmsg_put(msg, 0, 0, mDriverId, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);  // Setup which command to run.
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, mInterfaceIndex);  // Add message attribute, which interface to use.
    nl_socket_modify_cb(mSocket, NL_CB_VALID, NL_CB_CUSTOM, WiFiScanner::scanDumpCallback, NULL);  // Add the callback.
    int ret = nl_send_auto(mSocket, msg);  // Send the message.
    printf("NL80211_CMD_GET_SCAN sent %d bytes to the kernel.\n", ret);
    ret = nl_recvmsgs_default(mSocket);  // Retrieve the kernel's answer. callback_dump() prints SSIDs to stdout.
    nlmsg_free(msg);
    if (ret < 0) {
        printf("ERROR: nl_recvmsgs_default() returned %d (%s).\n", ret, nl_geterror(-ret));
        return;
    }

}

int WiFiScanner::requestScan()
{
    // Starts the scan and waits for it to finish. Does not return until the scan is done or has been aborted.
    struct nl_msg *msg;
    struct nl_cb *cb;
    struct nl_msg *ssids_to_scan;
    TrigerResult results;
    int err;
    int ret;
    int mcid = genl_ctrl_resolve_grp(mSocket, "nl80211", "scan");
    nl_socket_add_membership(mSocket, mcid);  // Without this, callback_trigger() won't be called.

    msg = nlmsg_alloc();
    if (!msg) {
        printf("ERROR: Failed to allocate netlink message for msg.\n");
        return -ENOMEM;
    }
    ssids_to_scan = nlmsg_alloc();
    if (!ssids_to_scan) {
        printf("ERROR: Failed to allocate netlink message for ssids_to_scan.\n");
        nlmsg_free(msg);
        return -ENOMEM;
    }
    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        printf("ERROR: Failed to allocate netlink callbacks.\n");
        nlmsg_free(msg);
        nlmsg_free(ssids_to_scan);
        return -ENOMEM;
    }

    // Setup the messages and callback handler.
    genlmsg_put(msg, 0, 0, mDriverId, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);  // Setup which command to run.
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, mInterfaceIndex);  // Add message attribute, which interface to use.
    nla_put(ssids_to_scan, 1, 0, "");  // Scan all SSIDs.
    nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids_to_scan);  // Add message attribute, which SSIDs to scan for.
    nlmsg_free(ssids_to_scan);  // Copied to `msg` above, no longer need this.
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, WiFiScanner::scanDoneCallback, &results);  // Add the callback.
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);  // No sequence checking for multicast messages.

    // Send NL80211_CMD_TRIGGER_SCAN to start the scan. The kernel may reply with NL80211_CMD_NEW_SCAN_RESULTS on
    // success or NL80211_CMD_SCAN_ABORTED if another scan was started by another process.
    err = 1;
    ret = nl_send_auto(mSocket, msg);  // Send the message.
    printf("NL80211_CMD_TRIGGER_SCAN sent %d bytes to the kernel.\n", ret);
    printf("Waiting for scan to complete...\n");
    while (err > 0) ret = nl_recvmsgs(mSocket, cb);  // First wait for ack_handler(). This helps with basic errors.
    if (err < 0) {
        printf("WARNING: err has a value of %d.\n", err);
    }
    if (ret < 0) {
        printf("ERROR: nl_recvmsgs() returned %d (%s).\n", ret, nl_geterror(-ret));
        return ret;
    }
    while (!results.done) nl_recvmsgs(mSocket, cb);  // Now wait until the scan is done or aborted.
    if (results.aborted) {
        printf("ERROR: Kernel aborted scan.\n");
        return 1;
    }
    printf("Scan is done.\n");

    // Cleanup.
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_drop_membership(mSocket, mcid);  // No longer need this.
    return 0;
}

int WiFiScanner::scanDoneCallback(nl_msg *msg, void *arg)
{   
    genlmsghdr * gnlh = static_cast<genlmsghdr*>(nlmsg_data(nlmsg_hdr(msg)));
    TrigerResult *results = static_cast<TrigerResult*>(arg);

    switch (gnlh->cmd) {
    case NL80211_CMD_SCAN_ABORTED:
    {
        results->aborted = 1;
        results->done = 1;
        break;
    }
    case NL80211_CMD_NEW_SCAN_RESULTS:
    {
        results->aborted = 0;
        results->done = 1;
        break;
    }

    }
    return NL_SKIP;
}

int WiFiScanner::scanDumpCallback(nl_msg *msg, void *arg)
{
    genlmsghdr *gnlh = static_cast<genlmsghdr*>(nlmsg_data(nlmsg_hdr(msg)));
    char mac_addr[20];
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    struct nlattr *auth[NL80211_AUTHTYPE_MAX + 1];
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1];
    static struct nla_policy auth_policy[NL80211_AUTHTYPE_MAX + 1];

    bss_policy[NL80211_BSS_TSF].type = NLA_U64;
    bss_policy[NL80211_BSS_FREQUENCY].type = NLA_U32;
    bss_policy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
    bss_policy[NL80211_BSS_CAPABILITY].type = NLA_U16;
    bss_policy[NL80211_BSS_SIGNAL_MBM].type = NLA_U32;
    bss_policy[NL80211_BSS_SIGNAL_UNSPEC].type = NLA_U8;
    bss_policy[NL80211_BSS_STATUS].type = NLA_U32;
    bss_policy[NL80211_BSS_SEEN_MS_AGO].type = NLA_U32;

    // Parse and error check.
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (!tb[NL80211_ATTR_BSS]) {
        printf("bss info missing!\n");
        return NL_SKIP;
    }
    if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy)) {
        printf("failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    if (!bss[NL80211_BSS_BSSID]) return NL_SKIP;
    if (!bss[NL80211_BSS_INFORMATION_ELEMENTS]) return NL_SKIP;

    // Start printing.
    mac_addr_n2a(mac_addr, static_cast<unsigned char*>(nla_data(bss[NL80211_BSS_BSSID])));
    printf("%s, ", mac_addr);
    printf("%d MHz, ", nla_get_u32(bss[NL80211_BSS_FREQUENCY]));
    printf("OpenShare:%d", nla_get_u8(tb[NL80211_ATTR_AUTH_TYPE]));
    print_ssid(static_cast<unsigned char*>(nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS])), nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]));
    printf("\n");

    return NL_SKIP;
}

int WiFiScanner::error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
   // Callback for errors.
   printf("error_handler() called.\n");
   int *ret = static_cast<int*>(arg);
   *ret = err->error;
   return NL_STOP;
}


int WiFiScanner::finish_handler(struct nl_msg *msg, void *arg) {
   // Callback for NL_CB_FINISH.
      int *ret = static_cast<int*>(arg);
   *ret = 0;
   return NL_SKIP;
}


int WiFiScanner::ack_handler(struct nl_msg *msg, void *arg) {
   // Callback for NL_CB_ACK.
      int *ret = static_cast<int*>(arg);
   *ret = 0;
   return NL_STOP;
}

int WiFiScanner::no_seq_check(struct nl_msg *msg, void *arg) {
   // Callback for NL_CB_SEQ_CHECK.
   return NL_OK;
}



