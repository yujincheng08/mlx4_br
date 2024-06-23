#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <functional>
#include <linux/limits.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <map>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

using MAC = std::array<uint8_t, 6>;
static_assert(sizeof(MAC) == sizeof(uint8_t) * 6);
constexpr auto RTNL_HANDLE_F_LISTEN_ALL_NSID = 0x01;
constexpr auto RTNL_HANDLE_F_SUPPRESS_NLERR = 0x02;
constexpr auto RTNL_HANDLE_F_STRICT_CHK = 0x04;
constexpr int sndbuf = 32768;
constexpr int rcvbuf = 1024 * 1024;
constexpr int one = 1;

struct RTNLGroup {
  unsigned int group;

  constexpr RTNLGroup(unsigned int group) : group(group) {}

  constexpr RTNLGroup &operator|=(unsigned int other) {
    group |= other ? (1 << (other - 1)) : 0;
    return *this;
  }

  constexpr operator unsigned int() const { return group; }
};

class RTAttr : protected rtattr {
  char data_[0];

public:
  RTAttr(const RTAttr &) = delete;
  RTAttr &operator=(const RTAttr &) = delete;
  template <typename T>
  std::enable_if_t<!std::is_pointer_v<T>, const T &> data() const {
    return *reinterpret_cast<const T *>(data_);
  }
  template <typename T> std::enable_if_t<std::is_pointer_v<T>, T> data() const {
    return reinterpret_cast<T>(data_);
  }
  size_t len() const { return rta_len - sizeof(rtattr); }
};

template <typename T> class BaseMsg : protected T {
public:
  BaseMsg(const BaseMsg<T> &) = delete;
  BaseMsg &operator=(const BaseMsg &) = delete;
  template <size_t MAX>
  const std::array<const RTAttr *, MAX> attr(int len, int flags = 0) const;
};

class NDMsg : public BaseMsg<ndmsg> {
public:
  const auto family() const { return ndm_family; }
  const auto ifindex() const { return ndm_ifindex; }
  const auto state() const { return ndm_state; }
  const auto flags() const { return ndm_flags; }
  const auto type() const { return ndm_type; }
};

class IfInfoMsg : public BaseMsg<ifinfomsg> {
public:
  const auto type() const { return ifi_type; }
  const auto family() const { return ifi_family; }
  const auto index() const { return ifi_index; }
  const auto flags() const { return ifi_flags; }
  const auto change() const { return ifi_change; }
};

class NLMsgHdr : protected nlmsghdr {
private:
  template <typename T> class BaseIter {
    friend class NLMsgHdr;
    BaseIter(T *current, int len) : current_(current), len_(len) {}

  protected:
    T *current_;
    int len_;

  public:
    auto &operator*() const { return *current_; }
    auto &operator*() { return *current_; }
    auto operator->() { return current_; }
    auto operator->() const { return current_; }
    auto operator++() {
      current_ = reinterpret_cast<decltype(current_)>(
          NLMSG_NEXT(const_cast<NLMsgHdr *>(current_), len_));
      return *this;
    }
    auto operator++(int) {
      auto n = typedecl(*this)(*this);
      return n++;
    }
    operator bool() const { return len_ > 0; }
  };

public:
  NLMsgHdr(const NLMsgHdr &) = delete;
  template <typename T> const T &msg() const {
    return *static_cast<T *>(NLMSG_DATA(this));
  }
  const auto type() const { return nlmsg_type; }
  const auto len() const { return nlmsg_len; }
  const auto flags() const { return nlmsg_flags; }
  const auto seq() const { return nlmsg_seq; }
  const auto pid() const { return nlmsg_pid; }

  using Iterator = BaseIter<NLMsgHdr>;
  using ConstIterator = BaseIter<const NLMsgHdr>;
  Iterator IteratorOf(int len) { return Iterator{this, len}; }
  ConstIterator IteratorOf(int len) const { return ConstIterator{this, len}; }

  template <typename T> void AddAttr(int type, const T &attr) {
    rtattr *rta = reinterpret_cast<rtattr *>(reinterpret_cast<char *>(this) +
                                             NLMSG_ALIGN(len()));
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(sizeof(T));
    memcpy(RTA_DATA(rta), &attr, sizeof(T));
    nlmsg_len = NLMSG_ALIGN(len()) + RTA_ALIGN(rta->rta_len);
  }
};

class ErrorMsg : public BaseMsg<nlmsgerr> {
public:
  const auto error() const { return nlmsgerr::error; }
  const NLMsgHdr &msg() const {
    return *reinterpret_cast<const NLMsgHdr *>(&(nlmsgerr::msg));
  }
};

class RTNLHandle {
  struct If {
    uint32_t idx;
    std::string name;
    unsigned short type;
    unsigned flags;
    std::vector<std::string> alt_names;
  };
  int fd{0};
  sockaddr_nl local{};
  //   sockaddr_nl peer{};
  int proto{0};
  //   FILE *dump_fp{nullptr};
  int flags{0};

  mutable uint32_t seq{0};
  mutable std::map<uint32_t, If> ifs;
  mutable std::map<std::string_view, If> ifnames;

  bool UpdateIfs() const;
  using DumpHandler = std::function<bool(const NLMsgHdr &hdr)>;
  bool ReceiveDump(int s, const DumpHandler &handler) const;

  void FdbModifyMac(const MAC &mac, uint32_t ifindex, uint16_t cmd,
                    uint16_t flags) const;

  int Recvmsg(struct msghdr *msg, int flags) const;
  std::tuple<std::unique_ptr<char[]>, int> Recvmsg(struct msghdr *msg) const;

public:
  using Listener = std::function<bool(const int &, const NLMsgHdr &)>;
  RTNLHandle(unsigned int subscriptions, int protocol) noexcept;

  constexpr auto IsValid() const noexcept { return fd >= 0; }

  inline bool AddNLGroup(int group) noexcept {
    return setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group,
                      sizeof(group)) >= 0;
  }

  std::vector<std::pair<uint32_t, MAC>> DumpFDB(uint32_t ifindex) const;

  [[noreturn]] void Listen(const Listener &listener) const;

  const If *FindIf(uint32_t index) const {
    if (auto iter = ifs.find(index); iter != ifs.end()) {
      return &iter->second;
    }
    UpdateIfs();
    if (auto iter = ifs.find(index); iter != ifs.end()) {
      return &iter->second;
    }
    return nullptr;
  }

  const If *FindIf(std::string_view ifname) const {
    if (auto iter = ifnames.find(ifname); iter != ifnames.end()) {
      return &iter->second;
    }
    UpdateIfs();
    if (auto iter = ifnames.find(ifname); iter != ifnames.end()) {
      return &iter->second;
    }
    return nullptr;
  }

  void FdbAddMac(const MAC &mac, const If *iface) const {
    printf("fdb add %02x:%02x:%02x:%02x:%02x:%02x to %s\n", mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5], iface->name.data());
    FdbModifyMac(mac, iface->idx, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL);
  }
  void FdbDelMac(const MAC &mac, const If *iface) const {
    printf("fdb del %02x:%02x:%02x:%02x:%02x:%02x from %s\n", mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5], iface->name.data());
    FdbModifyMac(mac, iface->idx, RTM_DELNEIGH, 0);
  }

  inline ~RTNLHandle() noexcept;
};

RTNLHandle::RTNLHandle(unsigned int subscriptions, int protocol) noexcept
    : proto(protocol) {
  struct finally {
    int *fd;
    bool ok = false;
    ~finally() {
      if (!ok) {
        if (*fd > 0) {
          close(*fd);
        }
        *fd = -1;
      }
    }
  } finally{&fd};

  if ((fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, proto)) < 0) {
    perror("socket");
    return;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
    perror("setsockopt");
    return;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
    perror("setsockopt");
    return;
  }

  setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));

  memset(&local, 0, sizeof(local));
  local.nl_family = AF_NETLINK;
  local.nl_groups = subscriptions;
  if (bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) < 0) {
    perror("bind");
    return;
  }

  socklen_t addr_len = sizeof(local);
  if (getsockname(fd, reinterpret_cast<sockaddr *>(&local), &addr_len) < 0) {
    perror("getsockname");
    return;
  }

  if (addr_len != sizeof(local)) {
    return;
  }

  if (local.nl_family != AF_NETLINK) {
    return;
  }

  seq = time(nullptr);
  if (!UpdateIfs()) {
    fprintf(stderr, "Failed to dump interfaces\n");
    return;
  }
  finally.ok = true;
}

RTNLHandle::~RTNLHandle() noexcept {
  if (fd > 0) {
    fd = -1;
    close(fd);
  }
}

[[noreturn]] void RTNLHandle::Listen(const Listener &listener) const {
  sockaddr_nl nladdr{.nl_family = AF_NETLINK};
  iovec iov;
  msghdr msg = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };
  char buf[16384];
  char cmsgbuf[BUFSIZ];
  iov.iov_base = buf;

  while (true) {
    int nsid = 0;
    cmsghdr *cmsg;

    if (flags & RTNL_HANDLE_F_LISTEN_ALL_NSID) {
      msg.msg_control = &cmsgbuf;
      msg.msg_controllen = sizeof(cmsgbuf);
    }

    iov.iov_len = sizeof(buf);
    int status = recvmsg(fd, &msg, 0);

    if (status < 0) {
      if (errno == EINTR || errno == EAGAIN)
        continue;

      fprintf(stderr, "netlink receive error %s (%d)\n", strerror(errno),
              errno);

      if (errno == ENOBUFS)
        continue;

      break;
    }

    if (status == 0) {
      fprintf(stderr, "EOF on netlink\n");
      break;
    }

    if (msg.msg_namelen != sizeof(nladdr)) {
      fprintf(stderr, "Sender address length == %d\n", msg.msg_namelen);
      exit(1);
    }

    if (flags & RTNL_HANDLE_F_LISTEN_ALL_NSID) {
      nsid = -1;
      for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
        if (cmsg->cmsg_level == SOL_NETLINK &&
            cmsg->cmsg_type == NETLINK_LISTEN_ALL_NSID &&
            cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
          int *data = (int *)CMSG_DATA(cmsg);

          nsid = *data;
        }
    }

    auto *hdr = reinterpret_cast<NLMsgHdr *>(buf);
    for (auto h = hdr->IteratorOf(status); h; ++h) {
      if (!listener(nsid, *h))
        break;
    }

    if (msg.msg_flags & MSG_TRUNC) {
      fprintf(stderr, "Message truncated\n");
      continue;
    }
  }

  exit(2);
}

template <typename T>
template <size_t MAX>
const std::array<const RTAttr *, MAX> BaseMsg<T>::attr(int len,
                                                       int flags) const {
  const auto *rta = reinterpret_cast<const rtattr *>(
      reinterpret_cast<const char *>(this) + NLMSG_ALIGN(sizeof(T)));
  std::array<const RTAttr *, MAX> tb;
  tb.fill(nullptr);
  len = len - NLMSG_SPACE(sizeof(T));
  while (RTA_OK(rta, len)) {
    const auto type = rta->rta_type & ~flags;
    if ((type <= MAX) && (!tb[type])) {
      tb[type] = reinterpret_cast<const RTAttr *>(rta);
    }
    rta = RTA_NEXT(rta, len);
  }
  if (len)
    fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);

  return tb;
}

int RTNLHandle::Recvmsg(struct msghdr *msg, int flags) const {
  int len;

  do {
    len = recvmsg(fd, msg, flags);
  } while (len < 0 && (errno == EINTR || errno == EAGAIN));

  if (len < 0) {
    fprintf(stderr, "netlink receive error %s (%d)\n", strerror(errno), errno);
    return -errno;
  }

  if (len == 0) {
    fprintf(stderr, "EOF on netlink\n");
    return -ENODATA;
  }

  return len;
}

std::tuple<std::unique_ptr<char[]>, int>
RTNLHandle::Recvmsg(struct msghdr *msg) const {
  struct iovec *iov = msg->msg_iov;
  int len;

  iov->iov_base = NULL;
  iov->iov_len = 0;

  len = Recvmsg(msg, MSG_PEEK | MSG_TRUNC);
  if (len < 0)
    return {nullptr, len};

  if (len < 32768)
    len = 32768;
  auto buf = std::make_unique<char[]>(len);
  if (!buf) {
    fprintf(stderr, "malloc error: not enough buffer\n");
    return {nullptr, -ENOMEM};
  }

  iov->iov_base = buf.get();
  iov->iov_len = len;

  len = Recvmsg(msg, 0);
  if (len < 0) {
    return {nullptr, len};
  }

  return {std::move(buf), len};
}

bool RTNLHandle::ReceiveDump(int s, const DumpHandler &handler) const {
  struct sockaddr_nl nladdr;
  struct iovec iov;
  struct msghdr msg = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };
  char *buf;
  int dump_intr = 0;
  while (true) {
    const struct rtnl_dump_filter_arg *a;
    int found_done = 0;

    auto [buf, msglen] = Recvmsg(&msg);
    if (msglen < 0)
      return false;

    const auto *hdr = reinterpret_cast<const NLMsgHdr *>(buf.get());

    for (auto h = hdr->IteratorOf(msglen); h; ++h) {
      int err = 0;

      //   struct ll_cache *im;
      struct rtattr *tb[IFLA_MAX + 1];

      if (nladdr.nl_pid != 0 || h->pid() != local.nl_pid || h->seq() != s)
        continue;

      if (h->flags() & NLM_F_DUMP_INTR)
        dump_intr = 1;

      if (h->type() == NLMSG_DONE) {
        found_done = 1;
        break; /* process next filter */
      }

      if (h->type() == NLMSG_ERROR) {
        // err = rtnl_dump_error(rth, h, a);
        continue;
      }

      if (!handler(*h)) {
        break;
      }
      // TODO: alt_names
    }

    if (found_done) {
      if (dump_intr)
        fprintf(stderr, "Dump was interrupted and may be inconsistent.\n");
      return true;
    }

    if (msg.msg_flags & MSG_TRUNC) {
      fprintf(stderr, "Message truncated\n");
      continue;
    }
  }
}

bool RTNLHandle::UpdateIfs() const {
  if (!IsValid())
    return false;
  struct {
    struct nlmsghdr nlh;
    struct ifinfomsg ifm;
    /* attribute has to be NLMSG aligned */
    struct rtattr ext_req alignas(NLMSG_ALIGNTO);
    uint32_t ext_filter_mask;
  } req{
      .nlh{
          .nlmsg_len = sizeof(req),
          .nlmsg_type = RTM_GETLINK,
          .nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
          .nlmsg_seq = ++seq,
      },
      .ifm{
          .ifi_family = AF_UNSPEC,
      },
      .ext_req{
          .rta_len = RTA_LENGTH(sizeof(uint32_t)),
          .rta_type = IFLA_EXT_MASK,
      },
      .ext_filter_mask = RTEXT_FILTER_VF,
  };

  if (send(fd, &req, sizeof(req), 0) < 0) {
    fprintf(stderr, "Cannot send dump if request: %s\n", strerror(errno));
    return false;
  }

  ReceiveDump(req.nlh.nlmsg_seq, [this](const NLMsgHdr &hdr) {
    const auto &ifi = hdr.msg<IfInfoMsg>();
    if (hdr.type() != RTM_NEWLINK && hdr.type() != RTM_DELLINK)
      return true;

    if (hdr.len() < NLMSG_LENGTH(sizeof(ifi))) {
      return false;
    }
    auto im = ifs.find(ifi.index());
    if (hdr.type() == RTM_DELLINK) {
      if (im != ifs.end()) {
        ifs.erase(im);
      }
      return true;
    }
    auto attrs = ifi.template attr<IFLA_MAX>(hdr.len(), NLA_F_NESTED);
    if (im != ifs.end()) {
      im->second.flags = ifi.flags(); //   ll_entries_update(im, ifi, tb);
    } else if (const auto *ifname_attr = attrs[IFLA_IFNAME]; ifname_attr) {
      printf("Get if %d -> %s\n", ifi.index(),
             ifname_attr->template data<const char *>());
      auto [iter, repaced] = ifs.emplace(
          ifi.index(), If{
                           .idx = static_cast<uint32_t>(ifi.index()),
                           .name = ifname_attr->template data<const char *>(),
                           .type = ifi.type(),
                           .flags = ifi.flags(),
                           .alt_names = {},
                       });
      ifnames.emplace(iter->second.name, iter->second);
    };
    // TODO: alt_names
    return true;
  });

  return true;
}

std::vector<std::pair<uint32_t, MAC>>
RTNLHandle::DumpFDB(uint32_t ifindex) const {
  std::vector<std::pair<uint32_t, MAC>> fdb;
  struct {
    struct nlmsghdr nlh;
    struct ndmsg ndm;
    char buf[256];
  } req{.nlh{
            .nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
            .nlmsg_type = RTM_GETNEIGH,
            .nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
            .nlmsg_seq = ++seq,
        },
        .ndm{
            .ndm_family = PF_BRIDGE,
        }};

  if (send(fd, &req, sizeof(req), 0) < 0) {
    fprintf(stderr, "Failed to send fdb dump request: %s\n", strerror(errno));
    return fdb;
  }

  reinterpret_cast<NLMsgHdr *>(&req.nlh)->AddAttr(IFLA_MASTER, ifindex);

  auto master = FindIf(ifindex);

  if (!master)
    return fdb;

  printf("Dump fdb of %s\n", master->name.data());

  ReceiveDump(req.nlh.nlmsg_seq, [this, &fdb, &ifindex](const auto &hdr) {
    if (hdr.type() != RTM_NEWNEIGH && hdr.type() != RTM_DELNEIGH) {
      fprintf(stderr, "Not support msg: %08x %08x %08x\n", hdr.len(),
              hdr.type(), hdr.flags());
      return true;
    }
    auto &msg = hdr.template msg<NDMsg>();

    if (hdr.len() < sizeof(msg)) {
      fprintf(stderr, "BUG: wrong nlmsg len %d\n", hdr.len());
      return false;
    }

    if (msg.family() != AF_BRIDGE && msg.family() != AF_UNSPEC) {
      return true;
    }

    auto attrs = msg.template attr<NDA_MAX>(hdr.len());

    if (const auto *addr_attr = attrs[NDA_LLADDR];
        addr_attr && !attrs[NDA_VLAN] &&
        (attrs[NDA_MASTER] || msg.ifindex() == ifindex)) {
      auto addr = addr_attr->template data<const uint8_t *>();
      if (addr_attr->len() == 6) {
        fdb.emplace_back(
            std::make_pair(msg.ifindex(), MAC{addr[0], addr[1], addr[2],
                                              addr[3], addr[4], addr[5]}));
      }
    }
    return true;
  });

  for (const auto &[idx, mac] : fdb) {
    auto slave = FindIf(idx);
    printf("\tfdb of %s addr %02x:%02x:%02x:%02x:%02x:%02x from %s\n",
           master->name.data(), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           slave->name.data());
  }

  return fdb;
}

void RTNLHandle::FdbModifyMac(const MAC &mac, uint32_t ifindex, uint16_t cmd,
                              uint16_t flags) const {
  struct {
    struct nlmsghdr nhl;
    struct ndmsg ndm;
    char buf[256];
  } req{
      .nhl{.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
           .nlmsg_type = cmd,
           .nlmsg_flags =
               static_cast<uint16_t>(flags | NLM_F_REQUEST | NLM_F_ACK),
           .nlmsg_seq = ++seq},
      .ndm{
          .ndm_family = PF_BRIDGE,
          .ndm_ifindex = static_cast<int32_t>(ifindex),
          .ndm_state = NUD_NOARP | NUD_PERMANENT,
          .ndm_flags = NTF_SELF,
      },
  };
  auto *hdr = reinterpret_cast<NLMsgHdr *>(&req.nhl);
  hdr->AddAttr(NDA_LLADDR, mac);
  struct iovec iov = {.iov_base = hdr, .iov_len = hdr->len()};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct iovec riov;
  struct msghdr msg = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };
  struct nlmsghdr *h;

  int status = sendmsg(fd, &msg, 0);
  if (status < 0) {
    perror("Cannot talk to rtnetlink");
    return;
  }

  msg.msg_iov = &riov;
  msg.msg_iovlen = 1;
  auto [buf, msglen] = Recvmsg(&msg);

  if (msglen < 0)
    return;

  if (msg.msg_namelen != sizeof(nladdr)) {
    fprintf(stderr, "sender address length == %d\n", msg.msg_namelen);
    exit(1);
  }

  hdr = reinterpret_cast<NLMsgHdr *>(buf.get());
  for (auto h = hdr->IteratorOf(msglen); h; ++h) {
    if (nladdr.nl_pid != 0 || h->pid() != local.nl_pid ||
        h->seq() != req.nhl.nlmsg_seq) {
      continue;
    }

    if (h->type() == NLMSG_ERROR) {
      const auto &err = h->template msg<ErrorMsg>();
      if (err.error() != 0 && err.error() != -EEXIST && err.error() != -ENOENT)
        fprintf(stderr, "error add fdb: %s\n", strerror(-err.error()));
      return;
    }

    fprintf(stderr, "Unexpected reply!!!\n");
  }

  if (msg.msg_flags & MSG_TRUNC) {
    fprintf(stderr, "Message truncated\n");
    return;
  }
}

std::vector<std::string> IsMlx4Driver(std::string_view ifname) {
  using namespace std::string_literals;
  using namespace std::string_view_literals;
  std::array<char, PATH_MAX> buf;

  std::vector<std::string> ifs;

  if (std::unique_ptr<FILE, decltype(&fclose)> slaves(
          fopen(("/sys/class/net/"s + ifname.data() + "/bonding/slaves").data(),
                "r"),
          fclose);
      slaves) {
    while (fscanf(slaves.get(), "%s", buf.data()) == 1) {
      ifs.emplace_back(buf.data());
    }
  } else {
    ifs.emplace_back(ifname);
  }

  std::vector<std::string> ret;
  ret.reserve(ifs.size());
  for (auto &ifname : ifs) {
    if (auto len = readlink(
            ("/sys/class/net/"s + ifname.data() + "/device/driver").data(),
            buf.data(), buf.size());
        len > 0) {
      buf[len] = '\0';
      std::string_view name = basename(buf.data());
      if (name == "mlx4_core" || name == "iavf" || name == "ixgbevf" || name == "mlx5_core")
        ret.emplace_back(std::move(ifname));
    }
  }
  return ret;
}

void PropagateMac(RTNLHandle &handle, uint32_t master_idx,
                  const std::vector<std::pair<uint32_t, MAC>> &mac,
                  bool remove) {
  const auto *iface = handle.FindIf(master_idx);
  if (!iface) {
    fprintf(stderr, "Cannot find if %u\n", master_idx);
    return;
  }
  auto dir = std::unique_ptr<DIR, decltype(&closedir)>{
      opendir(("/sys/class/net/" + iface->name).data()), &closedir};
  auto subdir = std::unique_ptr<DIR, decltype(&closedir)>{
      fdopendir(openat(dirfd(dir.get()), "brif", O_DIRECTORY)), &closedir};
  if (!subdir)
    return;
  const auto &all_mac = mac.empty() ? handle.DumpFDB(master_idx) : mac;
  for (dirent *subentry; (subentry = readdir(subdir.get()));) {
    if (subentry->d_type != DT_LNK)
      continue;
    std::string_view ifname = subentry->d_name;

    const auto *iface = handle.FindIf(ifname);
    if (!iface)
      continue;

    if (auto subifs = IsMlx4Driver(ifname); !subifs.empty()) {
      for (const auto &subifname : subifs) {
        const auto *subiface = handle.FindIf(subifname);
        if (!subiface)
          continue;
        for (const auto &[idx, mac] : all_mac) {
          if (iface->idx == idx || subiface->idx == idx)
            continue;
          if (remove)
            handle.FdbDelMac(mac, subiface);
          else
            handle.FdbAddMac(mac, subiface);
        }
      }
    }
  }
}

void ScanIfs(RTNLHandle &handle) {
  using namespace std::string_view_literals;
  using namespace std::string_literals;
  auto dir = std::unique_ptr<DIR, decltype(&closedir)>{
      opendir("/sys/class/net"), &closedir};
  if (!dir) {
    fprintf(stderr, "Failed to open /sys/class/net: %s", strerror(errno));
    exit(1);
  }
  for (dirent *entry; (entry = readdir(dir.get()));) {
    if (entry->d_type != DT_LNK)
      continue;
    if (const auto *iface = handle.FindIf(entry->d_name); iface) {
      PropagateMac(handle, iface->idx, {}, false);
    }
  }
}

bool OnLink(RTNLHandle &handle, const NLMsgHdr &hdr) {
  auto &msg = hdr.template msg<IfInfoMsg>();

  if (hdr.len() < sizeof(msg)) {
    fprintf(stderr, "BUG: wrong nlmsg len %d\n", hdr.len());
    return false;
  }

  if (msg.family() != AF_BRIDGE && msg.family() != AF_UNSPEC) {
    return true;
  }

  auto attrs = msg.template attr<IFLA_MAX>(hdr.len());

  const auto *iface = handle.FindIf(msg.index());
  if (!iface)
    return true;

  if (const auto *master = attrs[IFLA_MASTER]; master) {
    auto master_idx = master->template data<uint32_t>();
    if (auto m = handle.FindIf(master_idx);
        !m ||
        access(("/sys/class/net/" + m->name + "/brif").data(), F_OK) != 0) {
      return true;
    }

    if (auto subifs = IsMlx4Driver(iface->name); !subifs.empty()) {
      for (const auto &subifname : subifs) {
        auto subiface = handle.FindIf(subifname);
        if (!subiface)
          continue;
        auto fdb = handle.DumpFDB(master_idx);
        if (hdr.type() == RTM_NEWLINK) {
          for (const auto &[slave_idx, mac] : fdb) {
            if (iface->idx != slave_idx && subiface->idx != slave_idx)
              handle.FdbAddMac(mac, subiface);
          }
        } else if (hdr.type() == RTM_DELLINK) {
          for (const auto &[slave_idx, mac] : fdb) {
            if (iface->idx != slave_idx && subiface->idx != slave_idx)
              handle.FdbDelMac(mac, subiface);
          }
        }
      }
    }
  }

  return true;
}

bool OnFdb(RTNLHandle &handle, const NLMsgHdr &hdr) {
  auto &msg = hdr.template msg<NDMsg>();

  if (hdr.len() < sizeof(msg)) {
    fprintf(stderr, "BUG: wrong nlmsg len %d\n", hdr.len());
    return false;
  }

  if (msg.family() != AF_BRIDGE && msg.family() != AF_UNSPEC) {
    return true;
  }

  auto attrs = msg.template attr<NDA_MAX>(hdr.len());

  // skip vlan entries first
  if (attrs[NDA_VLAN])
    return true;

  if (const auto *master = attrs[NDA_MASTER]; master) {
    auto master_idx = master->template data<uint32_t>();
    if (const auto *addr_attr = attrs[NDA_LLADDR]; addr_attr) {
      auto addr = addr_attr->template data<const uint8_t *>();
      if (addr_attr->len() == 6) {
        MAC mac{addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]};
        PropagateMac(handle, master_idx, {{msg.ifindex(), mac}},
                     hdr.type() == RTM_DELNEIGH);
      }
    }
  }

  return true;
}

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  RTNLGroup groups = 0U;
  groups |= RTNLGRP_NEIGH;
  groups |= RTNLGRP_LINK;
  RTNLHandle listener(groups, NETLINK_ROUTE);

  RTNLHandle handle(0, NETLINK_ROUTE);

  if (!listener.IsValid()) {
    return 1;
  }

  ScanIfs(handle);

  listener.Listen([&handle](const auto &nsid, const auto &hdr) {
    if (hdr.type() != RTM_NEWNEIGH && hdr.type() != RTM_DELNEIGH &&
        hdr.type() != RTM_NEWLINK && hdr.type() != RTM_DELLINK) {
      fprintf(stderr, "Not support msg: %08x %08x %08x\n", hdr.len(),
              hdr.type(), hdr.flags());
      return true;
    }

    if (hdr.type() == RTM_NEWNEIGH || hdr.type() == RTM_DELNEIGH) {
      return OnFdb(handle, hdr);
    }

    if (hdr.type() == RTM_NEWLINK || hdr.type() == RTM_DELLINK) {
      return OnLink(handle, hdr);
    }

    return true;
  });
}
