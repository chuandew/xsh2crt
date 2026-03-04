# xsh2scrt

XShell to SecureCRT Session Converter

将 XShell 会话文件（.xsh）批量转换为 SecureCRT 会话文件（.ini），保留所有连接配置和加密密码。

## 功能特点

- 批量转换 XShell 会话目录中的所有 .xsh 文件
- 自动解密 XShell 密码并重新加密为 SecureCRT 格式
- 保留目录结构
- 支持 SSH、Telnet 等协议
- 密码认证设置为第一优先级

## 安装

```bash
go build -o xsh2scrt .
```

或者安装到系统 PATH：

```bash
go install .
```

## 使用方法

```bash
./xsh2scrt <xshell_sessions_dir> <securecrt_sessions_dir> <master_password>
```

### 示例

```bash
./xsh2scrt ~/Documents/XShell/Sessions ~/Documents/SecureCRT/Sessions mypassword
```

## 密码加密算法

### XShell 密码解密
- 使用 RC4 加密
- 密钥：`SHA256(masterPassword)`
- 格式：`Base64(RC4(key, plaintext) || SHA256(plaintext))`

### SecureCRT 密码加密
- 使用 AES-256-CBC 加密
- 密钥派生：`bcrypt_pbkdf2(password, salt, rounds=16, keyLen=48)`
- 格式：`"03:" + hex(salt || ciphertext)`

## 文件结构

```
.
├── main.go          # 程序入口，命令行处理
├── xshell.go        # XShell 会话解析和密码解密
├── securecrt.go     # SecureCRT 会话生成和密码加密
├── bcrypt_pbkdf.go  # bcrypt_pbkdf2 密钥派生实现
├── go.mod           # Go 模块定义
├── go.sum           # Go 模块校验
└── README.md        # 项目说明
```

## 依赖

- Go 1.21+
- golang.org/x/crypto/blowfish

## 注意事项

1. 主密码必须正确，否则无法解密 XShell 密码
2. 转换后的会话文件权限设置为 0600（仅所有者可读写）
3. 部分 XShell 会话可能使用不同的加密方式，转换时会跳过并显示警告

## License

MIT
