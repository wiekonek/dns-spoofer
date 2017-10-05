#include <iostream>
#include "GatewayInfo.h"

struct reqhdr {
    struct nlmsghdr nl;
    struct rtmsg    rt;
};

char *GatewayInfo::getGateway() {
    int sfd, rclen, nllen, atlen;
    char *ptr;
    char buf[8192];
    char gwy[32];
    struct sockaddr_nl snl;
    struct reqhdr req;
    struct nlmsghdr *nlp;
    struct rtmsg *rtp;
    struct rtattr *atp;

    sfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    memset(&snl, 0, sizeof(struct sockaddr_nl));
    snl.nl_family = AF_NETLINK;
    snl.nl_pid = 0;
    memset(&req, 0, sizeof(struct reqhdr));
    req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nl.nlmsg_type = RTM_GETROUTE;
    req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    req.nl.nlmsg_seq = 0;
    req.nl.nlmsg_pid = getpid();
    req.rt.rtm_family = AF_INET;
    req.rt.rtm_table = RT_TABLE_MAIN;
    sendto(sfd, (void*) &req, sizeof(struct reqhdr), 0, (struct sockaddr*) &snl,
           sizeof(struct sockaddr_nl));

    memset(&buf, 0, sizeof(buf));
    ptr = buf;
    nllen = 0;
    do {
        rclen = recv(sfd, ptr, sizeof(buf) - nllen, 0);
        nlp = (struct nlmsghdr*) ptr;
        ptr += rclen;
        nllen += rclen;
    } while(nlp->nlmsg_type == NLMSG_DONE);

    nlp = (struct nlmsghdr*) buf;
    for(;NLMSG_OK(nlp, nllen); nlp = NLMSG_NEXT(nlp, nllen)) {
        rtp = (struct rtmsg*) NLMSG_DATA(nlp);
        if(rtp->rtm_table == RT_TABLE_MAIN) {
            atp = (struct rtattr *) RTM_RTA(rtp);
            atlen = RTM_PAYLOAD(nlp);
            memset(gwy, 0, sizeof(gwy));
            for (; RTA_OK(atp, atlen); atp = RTA_NEXT(atp, atlen)) {
                if(atp->rta_type == RTA_GATEWAY) {
                    inet_ntop(AF_INET, RTA_DATA(atp), gwy, sizeof(gwy));
                    close(sfd);
                    return gwy;
                }
            }

        }
    }
    std::cout << "Returning default gateway" << std::endl;
    return "192.168.43.1";
}
