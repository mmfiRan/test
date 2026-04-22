# mdnsscan

一个简单的 mDNS 资产发现 CLI：输入 `-cidr` 和 `-ports`，输出该网段/端口范围内通过 mDNS 广播出来的服务资产信息（包含 `ip/port/host/TXT banner`）。

## 运行

```bash
GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomodcache go run . -cidr 192.168.1.0/24 -ports 1-65535 -timeout 5s
```

说明：
- mDNS 是二层广播/组播协议，扫描结果只会覆盖当前网卡所在的同一广播域内的设备。
- `-ports` 支持 `80,443,5000-6000` 这种写法。
