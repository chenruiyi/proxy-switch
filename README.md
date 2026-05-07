# ProxySwitch

内网代理一键切换工具 —— 把当前网卡的网关与 DNS 切到代理服务器,用完一键还原 DHCP。

> Go + Wails 重写自原 Python tkinter 版,体积更小、视觉更精致、错误处理更可靠。

## 功能

- 自动检测当前活跃网卡(Win 物理网卡 / Mac 网络服务)
- 一键切换:网关 + DNS 指向 `PROXY_IP`(默认 `10.0.0.232`)
- 一键还原:网卡回到 DHCP
- 启动时自动检测残留状态(上次未正常关闭也能恢复)
- 严格化错误处理:DNS 失败自动回滚,无"半启用"中间态
- 跟随系统亮暗主题,200x220 无边框圆角小窗
- 支持启动后临时修改 PROXY_IP(不持久化,几乎用不到)

## 下载与安装

最新版从 GitHub Actions 的 Artifacts 拿:

- **Windows**:`ProxySwitch-Windows` → `ProxySwitch.exe`
- **macOS Apple Silicon (M1/M2/M3...)**:`ProxySwitch-Mac-ARM` → 解压 → `ProxySwitch.app`
- **macOS Intel**:`ProxySwitch-Mac-Intel` → 解压 → `ProxySwitch.app`

## 首次启动会有"安全警告"——这是正常的

为了控制成本,本工具**未购买代码签名证书**,所以系统第一次见到它时会给警告。处理一次即可,之后再启动不会再提示。

### Windows 首次启动

双击 `ProxySwitch.exe`,可能会弹出蓝底白字 **"Windows 已保护你的电脑"**。

1. 点蓝色文字 **"更多信息"**
2. 点右下角出现的 **"仍要运行"** 按钮
3. 系统会再弹 **UAC**(管理员授权)对话框,点"是"

之后每次启动只会有 UAC 一步,不再有 SmartScreen 警告。

### macOS 首次启动

双击 `ProxySwitch.app`,会弹出 **"无法打开,因为 Apple 无法检查其是否包含恶意软件"**。

1. 在 Finder 里 **右键(或 Control+点击)** `ProxySwitch.app`
2. 选 **"打开"**(必须从右键菜单走,直接双击不行)
3. 系统会再弹一次确认框,有 **"打开"** 按钮,点它

之后双击就能正常启动。

## 使用

- **大圆按钮**:点击切换 ON/OFF
- **下方 IP 文字**:点一下进入编辑模式,Enter 保存,Esc 取消(只有 OFF 状态可改)
- **右上角小圆点**:关闭程序(开启状态下会自动还原 DHCP 后退出)
- **Esc 键**:同关闭

### macOS 额外的密码流程

第一次按下大圆按钮时会弹密码框 —— 输入你的 macOS 管理员密码即可。**密码只在内存里缓存,程序退出即销毁**,整个会话内不再询问。密码错可以重试,不会强退。

## 开发

### 依赖

- Go 1.23+
- Node.js 20+
- Wails v2 CLI:`go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0`

### 本地构建

```bash
wails build                     # 当前平台
wails build -platform darwin/arm64
wails build -platform windows/amd64
```

构建产物在 `build/bin/`。

### CI 构建

任何 push 都会触发 `.github/workflows/build.yml`,产出三平台 artifact。

## 技术决策摘要

详见提交历史。关键点:

- **窗口**:200x220 无边框 + 圆角(目标 Win 11 / macOS 11+)
- **主题**:跟随系统亮暗
- **前端**:纯 Vanilla(无框架)
- **macOS 提权**:懒加载密码 modal + 内存缓存,失败可重试
- **Windows 提权**:manifest `requireAdministrator`,启动时一次 UAC
- **错误处理**:全平台严格化,DNS 失败自动回滚 address
- **代码签名**:不买证书,首次启动警告靠这份 README 引导

## 许可

供内部使用。
