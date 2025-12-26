# TQP 协议集成指南

本目录包含 TQP 协议的核心代码实现，需要分别复制到对应的项目中。

## 📁 文件清单

```
tqp_code/
├── singbox_inbound.go    → 复制到 sing-box_mod/protocol/tqp/inbound.go
├── singbox_option.go     → 复制到 sing-box_mod/option/tqp.go
├── mihomo_outbound.go    → 复制到 mihomo/adapter/outbound/tqp.go
└── README.md             → 本文件
```

## 🔧 集成步骤

### 1. sing-box_mod (服务端)

```bash
cd e:\GitHub\sing-box_mod

# 创建 TQP 协议目录
mkdir -p protocol/tqp

# 复制文件
cp e:\GitHub\V2bX\docs\tqp_code\singbox_inbound.go protocol/tqp/inbound.go
cp e:\GitHub\V2bX\docs\tqp_code\singbox_option.go option/tqp.go
```

还需要修改以下文件：

**a. `constant/protocol.go` - 添加协议类型**
```go
const (
    // ... existing types
    TypeTQP = "tqp"
)
```

**b. `include/inbound.go` - 注册 inbound**
```go
import "github.com/sagernet/sing-box/protocol/tqp"

func InboundRegistry() *inbound.Registry {
    registry := inbound.NewRegistry()
    // ... existing registrations
    tqp.RegisterInbound(registry)
    return registry
}
```

### 2. mihomo (客户端)

```bash
cd e:\GitHub\mihomo

# 复制文件
cp e:\GitHub\V2bX\docs\tqp_code\mihomo_outbound.go adapter/outbound/tqp.go
```

还需要修改以下文件：

**a. `constant/adapters.go` - 添加协议类型**
```go
const (
    // ... existing types
    TQP AdapterType = "tqp"
)
```

**b. `adapter/parser.go` - 添加解析器**
```go
case "tqp":
    proxy, err = outbound.NewTQP(option)
```

### 3. V2bX (后端)

在 `core/sing/node.go` 的 `getInboundOptions` 函数中添加 TQP case：

```go
case "tqp":
    in.Type = "tqp"
    in.Options = &option.TQPInboundOptions{
        ListenOptions: listen,
        Users: []option.TQPUser{
            // ... users from panel
        },
        TLS: &tls,
        Fallback: &option.TQPFallbackOptions{
            Server: "127.0.0.1",
            ServerPort: "8080",
        },
    }
```

### 4. V2Board (面板)

创建 `app/Protocols/TQP.php` 用于订阅下发。

## ⚠️ 注意事项

1. 确保两端使用相同的密钥派生算法
2. 确保时间同步（服务器和客户端时间差不超过 2 分钟）
3. Fallback 地址必须配置，用于抵御主动探测

## 🧪 测试

1. 先测试 sing-box 能否编译通过
2. 再测试 mihomo 能否编译通过
3. 最后进行端到端连接测试
