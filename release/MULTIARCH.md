# Kuaiyun XrayR Linux 多架构测试发行

XrayR 仍为 0.9.4，Xray-core 仍为 26.7.28，使用 Go 1.26.5、CGO_ENABLED=0。
ky.2 的 REALITY MinClientVer 可选本地回退保持不变。业务 Go 源码、配置格式、服务文件及管理命令不因架构支持而改变。

| CPU / uname -m | 安装包 | 最低指令集选项 | CI 运行验证方式 |
| --- | --- | --- | --- |
| x86_64 / amd64 | XrayR-linux-64.zip | GOAMD64=v1 | 原生 Linux AMD64 |
| aarch64 / arm64 | XrayR-linux-arm64-v8a.zip | GOARM64=v8.0 | 原生 Linux ARM64 |
| armv7l | XrayR-linux-armv7.zip | GOARM=7 | qemu-arm 用户态模拟 |
| i386 / i686 | XrayR-linux-386.zip | GO386=sse2，CPU 必须具备 SSE2 | AMD64 Linux 的 32 位兼容执行 |
| riscv64 | XrayR-linux-riscv64.zip | GORISCV64=rva20u64 | qemu-riscv64 用户态模拟 |
| s390x | XrayR-linux-s390x.zip | Go 工具链默认目标 | qemu-s390x 用户态模拟 |

所有平台必须通过编译、ELF 架构/字节序、静态链接、核心模块、ZIP 结构/权限、校验及隔离运行门禁。CI 结果才代表该提交的实际通过状态。模拟执行不等于对应硬件或 VPS 验收，32 位兼容执行不等于独立 386 VPS 验收。

运行验收使用临时目录、回环面板和临时凭据，实际启动打包程序，执行 VLESS TCP 认证、40 KiB 双向回显、流量上报、未知用户拒绝及 SIGTERM 退出。目标核心默认阻止私有目的地址，因此测试临时自定义路由/出站仅放行本次回环回显端口，不修改发行配置或核心默认策略。

## 相同安装入口

在隔离、全新测试 VPS 上以 root 执行同一入口，并指定 v0.9.4-ky.3。安装器按 CPU 选择包；未知架构明确退出。它先下载校验 ZIP、必要文件及对应版本的服务/管理脚本，再进入原安装步骤。缺包、下载或校验失败会提前退出。

保留原安装器删除并重建 `/usr/local/XrayR/` 的行为；现有 `/etc/XrayR/config.yml` 继续保留。未增加升级备份、回滚或监控系统。网络下载设置超时，不强制改变系统 IPv6。管理菜单的三个来源 URL 指向多架构开发分支，防止后续下载旧的 AMD64 专用安装器。

每个平台的 ZIP、`.zip.sha256`、`BUILD-INFO-linux-*.json`、`RUNTIME-linux-*.json` 分别发布，ZIP 内仍为根目录 `XrayR`、`config.yml`、DNS、路由、自定义入站/出站、rulelist、geoip/geosite 及许可证文件。二进制具有 Unix 0755 权限。

## ARM64 VPS 验收

1. 使用独立 Debian/Ubuntu ARM64 测试 VPS，`uname -m` 应为 `aarch64` 或 `arm64`。
2. 使用发行报告中的统一安装命令，观察选择 `arm64-v8a`，确认 ZIP SHA256 校验成功。
3. 执行 `file /usr/local/XrayR/XrayR` 和 `/usr/local/XrayR/XrayR version`，应为 AArch64、XrayR 0.9.4。
4. 在原有完整配置中填写独立测试节点参数，执行 `XrayR start`、`XrayR status`、`XrayR log`，核对核心为 26.7.28。
5. 验证 `XrayR stop/restart/status/log`、systemd 开机启动及原配置路径，再做独立客户端协议连接、认证、流量统计与限速测试。

未执行实际 VPS 安装、systemd 或生产面板操作。真实 V2Board、Windows Mihomo、Shadowrocket、REALITY/Vision、UDP、其他协议/传输及长时间负载仍需独立验收，不能仅凭架构编译和 VLESS 回环收发宣称全部兼容。
