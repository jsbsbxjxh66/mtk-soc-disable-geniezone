# mtk-soc-disable-geniezone

通过修改 GPT 分区表禁用联发科 GenieZone (GZ) 虚拟化管理程序，不破坏 preloader 代码签名。

> **免责声明**
>
> 本工具仅供安全研究和个人设备调试使用。使用本工具修改设备分区表存在**变砖风险**，包括但不限于：设备无法启动、需要通过底层工具救砖、丢失保修资格等。作者不对因使用本工具造成的任何损失承担责任。**使用前请务必备份原始分区表，风险自负。**

## 项目结构

| 工具 | 用途 |
|------|------|
| `detect_gz_bypass.py` | 分析 preloader 固件，检测 GPT 修改方案是否可用 |
| `patch_gz_gpt.py` | 修改 GPT 分区表，将 gz 分区 LBA 指向无效地址 |

## 快速开始

### 1. 检测可行性

先用 `detect_gz_bypass.py` 分析你的设备 preloader，确认 GPT 方案是否适用：

```bash
python3 detect_gz_bypass.py preloader.img
```

输出示例（GPT 可用）：
```
============================================================
  preloader.img
============================================================

文件大小: 434,300 bytes (0.4 MB)
GFH: load_addr=0x00201000  BASE=0x00200000  Thumb PIC

  NoGZ: 2 处  CMP #512: 0x260BC  set_nogz: 0x269A8
  assert_fatal: 0x2A280  halt_on_assert: 0x002E84F4

============================================================
  GPT 修改方案: 可用
  halt_on_assert 未强制置 1, assert 非致命

  python3 patch_gz_gpt.py <pgpt.bin>
  fastboot flash pgpt <输出文件>
```

输出示例（GPT 不可用）：
```
============================================================
  GPT 修改方案: 不可用
  halt_on_assert 被无条件置 1, assert_fatal 触发 WDT reset
```

### 2. 修改分区表

确认 GPT 方案可用后，提取设备的 `pgpt.bin` 并修改：

```bash
# 分析分区表（不修改）
python3 patch_gz_gpt.py pgpt.bin --dry-run

# 修改 gz 分区 LBA
python3 patch_gz_gpt.py pgpt.bin

# 指定输出文件名
python3 patch_gz_gpt.py pgpt.bin -o my_output.bin
```

### 3. 刷写

```bash
# 使用底层工具刷写修补后的 pgpt_patched.bin 到 pgpt 分区
# mtkclient / geekflashtool / unlocktool 等均可

# 或通过 fastboot
fastboot flash pgpt pgpt_patched.bin
```

### 4. 还原

```bash
# 使用脚本还原
python3 patch_gz_gpt.py pgpt.bin --restore

# 或直接刷回备份
fastboot flash pgpt pgpt_backup.bin
```

---

## detect_gz_bypass.py

分析 MediaTek preloader 固件二进制文件，自动判定 GPT 修改方案是否可用。

### 检测流程

1. **GFH 头解析** — 扫描 GFH magic (`0x014D4D4D`)，提取 load_addr、BASE 地址、代码范围
2. **架构识别** — 自动区分 Thumb / Thumb PIC / AArch64
3. **GenieZone 代码检测** — 搜索 `bldr_load_gz_part`、`gz_init` 等特征字符串和 NoGZ 常量 (`0x4E6F475A`)
4. **halt_on_assert 分析** — 定位 `assert_fatal` 函数，检查 `halt_on_assert` 变量是否被无条件置 1
5. **GPT 可行性判定** — 综合以上信息给出结论

### 用法

```bash
# 分析单个固件
python3 detect_gz_bypass.py preloader.img

# 批量分析多个固件
python3 detect_gz_bypass.py preloader_*.img

# 带 UFS_BOOT 磁盘头的固件也能自动识别
python3 detect_gz_bypass.py preloader_k6983v1_64.bin
```

### 支持的架构

| 架构 | 特征 | 已测试平台 |
|------|------|-----------|
| Thumb (非 PIC) | 直接地址引用 | MT6895 |
| Thumb PIC | LDR + ADD PC 位置无关代码 | MT6833 |
| AArch64 | ADRP + ADD 页相对寻址 | MT6983 |

架构自动检测，无需手动指定。

### 输入文件

- 标准 preloader 固件 (`preloader.img`)
- 带 UFS_BOOT 磁盘头的固件 (`preloader_k6895v1_64.bin`)，GFH 通常在 0x2000 偏移处
- 脚本在前 64KB 范围内扫描 GFH magic，兼容各种头部格式

### GPT 判定逻辑

修改 gz 分区 LBA 使其越界 → I/O 失败 → preloader 设置 NoGZ 标志 → 跳过 GZ 加载。

但如果 `halt_on_assert` 被无条件置为 1，`assert_fatal` 会触发 WDT reset，设备重启进入 BROM 模式。此时 GPT 方案**不可用**。

| halt_on_assert 状态 | GPT 结论 | 含义 |
|---------------------|---------|------|
| 未强制置 1 | **可用** | assert 非致命，I/O 失败后正常设置 NoGZ 并继续启动 |
| 无条件置 1 | **不可用** | assert 致命，I/O 失败触发 WDT reset |
| 无法检测 | **未知** | 需要手动逆向分析 |

### 输出字段说明

| 字段 | 含义 |
|------|------|
| `GFH` | load_addr / BASE 地址 / 架构类型 / GFH 偏移 |
| `NoGZ` | NoGZ 常量 (0x4E6F475A) 的引用数量 |
| `CMP #512` | `bldr_load_gz_part` 函数中 CMP Rn, #0x200 的位置 |
| `set_nogz` | 设置 NoGZ 标志的函数地址 |
| `assert_fatal` | assert_fatal 函数的文件偏移 |
| `halt_on_assert` | halt_on_assert BSS 变量的内存地址 |
| `写入点` | 无条件 STRB #1 的位置（强制置 1 的证据）|

---

## patch_gz_gpt.py

修改 GPT 分区表中 gz 分区的 LBA 地址，使其指向紧贴设备末尾的无效地址 (`total_lbas`)。

### 用法

```bash
# 分析分区表（不修改）
python3 patch_gz_gpt.py pgpt.bin --dry-run

# 修改 gz 分区 LBA（自动备份到 pgpt_backup.bin）
python3 patch_gz_gpt.py pgpt.bin

# 指定输出文件
python3 patch_gz_gpt.py pgpt.bin -o modified.bin

# 从备份还原
python3 patch_gz_gpt.py pgpt.bin --restore
```

### 特性

- 自动检测扇区大小（512 字节 eMMC / 4096 字节 UFS）
- 自动备份原始文件
- CRC32 校验自动更新（Header CRC + Entries CRC）
- 支持 gz/gz1/gz2/gz_a/gz_b 等所有 A/B 分区命名
- 仅修改主 GPT (Primary GPT)

### 提取 pgpt.bin

使用 mtkclient / geekflashtool / unlocktool 等工具从设备提取 `pgpt` 分区。部分设备也支持 fastboot，具体分区路径视设备而定。

---

## 原理

### 启动流程中的 GenieZone

```
BROM → preloader (签名验证) → ATF → LK → kernel
              │
              ├─ gz_init(): 读取 gz 分区配置 → 设置 NoGZ 标志
              ├─ 分区加载循环: 加载 tee/gz/scp 等分区镜像
              └─ ATF 跳转: 根据 NoGZ 决定是否将 EL2 移交给 GZ
```

### 无效 LBA 欺骗

核心发现：`get_part_info()` 只做名称匹配，不验证 LBA 地址有效性。而实际的存储 I/O 由 `func_40974` 执行，它在读取失败时返回 -1。

将 gz1 分区的 LBA 改为超出设备容量的值后：

```
阶段 1: gz_init()
  read_part("gz")
    func_36d68("gz") → "gz1" → get_part_info("gz1") → 找到 ✓
    func_40974 → 读取无效 LBA → 失败 → return -1
  read_part 返回 -1 → 设置 NoGZ = 0x4E6F475A  ✓

阶段 2: 主分区加载循环
  func_36d68("gz") → "gz1" → get_part_info("gz1") → 找到 → return 0  ✓
  bldr_load_gz_part()
    is_el2_enabled() → 0 (NoGZ 已设置)
    skip load gz → return 0  ✓
```

### 为什么其他方案不可行

| 策略 | 问题 |
|------|------|
| 删除 gz 分区 | `gz_init` 正确设 NoGZ，但主循环的 `func_36d68` 也找不到分区 → 致命错误 |
| 改分区名 | 和删除一样：`get_part_info("gz1")` 找不到 → 同一个 Catch-22 |
| 擦除/清零 gz 数据 | I/O 成功返回 0x200，NoGZ 不被触发，解析全零数据行为不可预测 |
| LBA 指向 GPT 头区域 | I/O 成功读取非 GZ 数据 → 实测黑砖 |

**触发 NoGZ 的唯一路径是让存储 I/O 返回 -1（I/O 失败）。**

### halt_on_assert 与 GPT 方案的关系

部分平台（如 MT6895、MT6983）的 preloader 会无条件将 `halt_on_assert` 置为 1。此时 `assert_fatal` 被触发后调用 WDT reset，设备直接重启进入 BROM 模式，而不是继续执行设置 NoGZ 的代码路径。

`detect_gz_bypass.py` 的检测步骤：

1. 定位 `bldr_load_gz_part` 函数（CMP #512 + 条件分支）
2. 在错误路径中找到 `assert_fatal` 的 BL 调用
3. 在 `assert_fatal` 内部查找对 `halt_on_assert` 变量的 LDRB + CBZ/CBNZ 读取
4. 全局扫描是否存在无条件 STRB #1 写入该变量
5. 如果存在 → GPT 方案不可用

---

## 故障排查

**亮一下 logo 就重启**

Preloader 阶段成功，但 LK 或 kernel 阶段失败。可能原因：

1. **LK/kernel 阶段 UFS 崩溃** — preloader 正常返回错误，但后续阶段读取无效 LBA 时控制器崩溃

2. **当前版本preloader不适用** — halt_on_assert 被无条件置 1, assert_fatal 触发 WDT reset

**完全无响应（黑砖）**

UFS 控制器在 preloader 阶段读取越界 LBA 时崩溃（控制器 bug）。需要通过 mtkclient 或 SP Flash Tool 底层恢复刷回备份 GPT。

---

## 兼容性

### 已测试设备

| 设备 | SoC | 系统 | 架构 | GPT 方案 |
|------|-----|------|------|---------|
| OPPO A55 | MT6833 | Android 13 | Thumb PIC | **可用** |
| OPPO K9 Pro | MT6893 | Android 13 | Thumb PIC | **可用** |
| Realme GT Neo 闪速版 | MT6893 | Android 13 | Thumb PIC | **可用** |

### 其他

| 项目 | 说明 |
|------|------|
| 扇区大小 | 自动检测 512 字节 (eMMC) / 4096 字节 (UFS) |
| 分区名称 | 支持 gz/gz1/gz2/gz_a/gz_b/gz1_a/gz1_b/gz2_a/gz2_b |
| Python | 3.6+，无第三方依赖 |

## 风险与注意事项

- **检测脚本不是万能的**：成功与否你都得有能够救砖的能力
- **适用平台**：同处理器有失败的不代表不行可能你只是缺少一个合适的preloader固件
- **UFS 崩溃**：部分 UFS 控制器在遇到越界 LBA 时会崩溃而非返回错误
- **OTA 更新**：系统 OTA 可能还原 GPT 到原始状态，需要重新修改
- **可恢复性**：修改仅涉及 GPT 分区表，可随时通过 fastboot 或底层工具刷回备份
- **备份 GPT**：本工具仅修改主 GPT，设备末尾的备份 GPT 可能需要同步修改
- **功能影响**：禁用 GenieZone 后，依赖 GZ 虚拟化服务的功能（如部分 DRM、安全容器等）可能不可用

## License

MIT — 详见 [LICENSE](LICENSE) 文件。
