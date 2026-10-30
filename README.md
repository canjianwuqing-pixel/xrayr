# Kuaiyun XrayR

快云维护的 XrayR 定制项目。

- 唯一业务源码上游：https://github.com/leaderen/wyx2685-XrayR
- 固定源码提交：`0bb4713626128849da0d2437defea1a1322c44cc`
- 目标仓库：https://github.com/canjianwuqing-pixel/xrayr
- 开发分支：`feature/xray-core-26.7.28`
- 当前阶段：仅导入源码和完整历史，尚未升级核心、编译或完成兼容性测试。
- 原有 MPL-2.0 LICENSE 及上游说明完整保留。

## 上游历史归档

本次导入保留全部公开分支与标签可达的 509 个原始提交。合并提交的父提交包含原目标分支、固定上游 master 和另外五个分支的尖端；其他分支仅保留历史，不采用其依赖更新，工作树以固定 master 为准。

仅推送目标开发分支，没有在目标 GitHub 仓库创建或移动其他分支及标签。以下清单保留原始 refs 名称及 SHA，所有 SHA 均为导入提交的祖先，可在新克隆中按需恢复 refs；本地另有 upstream 命名空间 refs。

| 原始上游 ref | SHA |
| --- | --- |
| `refs/heads/dependabot/go_modules/github.com/eko/gocache/lib/v4-4.2.2` | `a24c37a62a3507bd9d7f7a50b2e18002d06d3364` |
| `refs/heads/dependabot/go_modules/github.com/fsnotify/fsnotify-1.9.0` | `58e032c91df53c2c254c73c092da53cfd9f6fa3a` |
| `refs/heads/dependabot/go_modules/github.com/go-resty/resty/v2-2.16.5` | `5f139b6a6a890f899cc6c97fea15bbbf34557326` |
| `refs/heads/dependabot/go_modules/github.com/gogf/gf/v2-2.9.4` | `6ffa60cd3718f44e2a88fa2821d7865b1205e4f7` |
| `refs/heads/dependabot/go_modules/github.com/spf13/cobra-1.10.1` | `7a3706bed423f3c09f4573981b63bb043d52d24a` |
| `refs/heads/master` | `0bb4713626128849da0d2437defea1a1322c44cc` |
| `refs/tags/v0.9.2` | `b97856484191145343eb30fd392cf3aacedae102` |
| `refs/tags/v0.9.3` | `0a2c3e3236e750406f541cff9c3689f09e2f0e93` |

## 原目标仓库说明

# xrayr


---

## 完整上游项目说明

## 本分支需要配合修改过的V2board面板进行使用
https://github.com/wyx2685/v2board

# XrayR
[![](https://img.shields.io/badge/TgChat-@UnOfficialV2board讨论-blue.svg)](https://t.me/unofficialV2board)
[![](https://img.shields.io/badge/TgChat-@XrayR讨论-blue.svg)](https://t.me/XrayR_project)
[![](https://img.shields.io/badge/Channel-@XrayR通知-blue.svg)](https://t.me/XrayR_channel)
![](https://img.shields.io/github/stars/wyx2685/XrayR)
![](https://img.shields.io/github/forks/wyx2685/XrayR)
![](https://github.com/wyx2685/XrayR/actions/workflows/release.yml/badge.svg)
![](https://github.com/wyx2685/XrayR/actions/workflows/docker.yml/badge.svg)
[![Github All Releases](https://img.shields.io/github/downloads/wyx2685/XrayR/total.svg)]()


[English](https://github.com/wyx2685/XrayR/blob/master/README-en.md)|[Iranian](https://github.com/wyx2685/XrayR/blob/master/README_Fa.md)|[Vietnamese](https://github.com/wyx2685/XrayR/blob/master/README-vi.md)

A Xray backend framework that can easily support many panels.

一个基于Xray的后端框架，支持V2ay,Trojan,Shadowsocks协议，极易扩展，支持多面板对接。

如果您喜欢本项目，可以右上角点个star+watch，持续关注本项目的进展。

使用教程：[详细使用教程](https://xrayr-project.github.io/XrayR-doc/)


## 免责声明

本项目只是本人个人学习开发并维护，本人不保证任何可用性，也不对使用本软件造成的任何后果负责。

## 特点

* 永久开源且免费。
* 支持V2ray，Trojan， Shadowsocks多种协议。
* 支持Vless和XTLS等新特性。
* 支持单实例对接多面板、多节点，无需重复启动。
* 支持限制在线IP
* 支持节点端口级别、用户级别限速。
* 配置简单明了。
* 修改配置自动重启实例。
* 方便编译和升级，可以快速更新核心版本， 支持Xray-core新特性。

## 功能介绍

| 功能        | vmess | vless | trojan | shadowsocks |
|-----------|-------|-------|--------|-------------|
| 获取节点信息| √ | √ | √ |√ |
| 获取用户信息| √ | √ | √ |√ |
| 用户流量统计| √ | √ | √ |√ |
| 服务器信息上报| √ | √ | √ |√ |
| 自动申请tls证书| √ | √ | √ |√ |
| 自动续签tls证书| √ | √ | √ |√ |
| 在线人数统计| √ | √ | √ |√ |
| 在线用户限制| √ | √ | √ |√ |
| 审计规则| √ | √ | √ |√ |
| 节点端口限速| √ | √ | √ |√ |
| 按照用户限速| √ | √ | √ |√ |
| 自定义DNS| √ | √ | √ |√ |

## 支持前端


| 前端                                                     | vmess | vless | trojan | shadowsocks |
|--------------------------------------------------------|-------|-------|--------|-------------------------|
| sspanel-uim                                            | √     | √     | √      | √ (单端口多用户和V2ray-Plugin) |
| v2board                                                | √     | √     | √      | √                       |
| [PMPanel](https://github.com/ByteInternetHK/PMPanel)   | √     | √     | √      | √                       |
| [ProxyPanel](https://github.com/ProxyPanel/ProxyPanel) | √     | √     | √      | √                       |
| [WHMCS (V2RaySocks)](https://v2raysocks.doxtex.com/)   | √     | √     | √      | √                       |
| [GoV2Panel](https://github.com/pingProMax/gov2panel)   | √     | √     | √      | √                       |
| [BunPanel](https://github.com/pennyMorant/bunpanel-release)   | √     | √     | √      | √                       |

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/leaderen/wyx2685-XrayR-scripts/refs/heads/master/install.sh && bash install.sh
```

### 手动安装

[手动安装教程](https://xrayr-project.github.io/XrayR-doc/xrayr-xia-zai-he-an-zhuang/install/manual)

## 配置文件及详细使用教程

[详细使用教程](https://xrayr-project.github.io/XrayR-doc/)

## Thanks

* [Project X](https://github.com/XTLS/)
* [V2Fly](https://github.com/v2fly)
* [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
* [Air-Universe](https://github.com/crossfw/Air-Universe)

## Licence

[Mozilla Public License Version 2.0](https://github.com/wyx2685/XrayR/blob/master/LICENSE)

## Telgram

[XrayR后端讨论](https://t.me/XrayR_project)

[XrayR通知](https://t.me/XrayR_channel)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/wyx2685/XrayR.svg)](https://starchart.cc/wyx2685/XrayR)


