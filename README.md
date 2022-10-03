# mlx4_br
"Driver" to allow adding mlx4 vf into linux bridge

作用：解决 CX341 在开启 SR-IOV 之后，把 VF/PF 加到 Linux Bridge 之后无法通讯的问题

使用：
- 如果需要在 openwrt 中把 VF 放到 br-lan 或者其他 linux bridge 中，在 openwrt 中安装 mlx4_br_1.0_x86-64.ipk 即可，命令：`opkg install mlx4_br_1.0_x86-64.ipk`
- 如果需要在 PVE 中把 VF/PF 放到 vmbr 或者其他 linux bridge 中，在 PVE 中安装 mlx4_br.1.0.deb 即可，命令：`dpkg -i mlx4_br.1.0.deb`

理论支持所有 linux 系统，其他系统可自行编译。
