# mtk-soc-disable-geniezone

禁用联发科 GenieZone (GZ) 虚拟化管理程序。支持两种方案：修改 GPT 分区表（preloader 层面）或修补 LK 固件（LK 层面）。LK 方案支持 bl2_ext GZ 初始化管线补丁和 DTB VCP 节点禁用。

> **免责声明**
>
> 本工具仅供安全研究和个人设备调试使用。使用本工具修改设备固件存在**变砖风险**，包括但不限于：设备无法启动、需要通过底层工具救砖、丢失保修资格等。作者不对因使用本工具造成的任何损失承担责任。**使用前请务必备份原始固件，风险自负。**

## 项目结构

| 工具 | 用途 |
|------|------|
| `detect_gz_bypass.py` | 分析 preloader 固件，检测 GPT 修改方案是否可用，推荐无效 LBA 或重名子方案 |
| `patch_gz_gpt.py` | 修改 GPT 分区表（PGPT + SGPT）：重名 gz→gx（`--rename`）或将 LBA 指向无效地址（默认） |
| `detect_lk_gz.py` | 分析 LK 固件，检测并修补 bl2_ext GZ 初始化管线，支持 DTB VCP 节点禁用 |

## 两种方案

| 方案 | 层面 | 条件 | 是否需要跳过签名 |
|------|------|------|-----------------|
| **GPT 重名方案** | Preloader | `halt_on_assert` 未强制置 1 且主引导循环无 gz 硬依赖 | 否 |
| **GPT 无效 LBA 方案** | Preloader | `halt_on_assert` 未被强制置 1 | 否 |
| **LK bl2_ext 方案** | LK (bl2_ext 段) | bl2_ext 中存在 GZ 初始化管线 | 是 |
| **VCP 禁用** | LK (DTB) | LK 中 DTB 存在 vcp-support 节点 | 是 |

- GPT 方案有两个子方案，均不修改代码：
  - **重名方案** (`--rename`)：将 gz 分区改名为 gx，`get_part_info("gz")` 找不到分区 → 无 I/O → 设置 NoGZ。需 preloader 主引导循环不独立依赖 gz 分区名解析（`detect_gz_bypass.py` 自动检测）
  - **无效 LBA 方案**（默认）：将 gz 分区 LBA 改为越界地址，存储 I/O 失败 → 设置 NoGZ
- LK bl2_ext 方案（MT6991 等）— GZ 逻辑在 bl2_ext 段，使用 Hafnium S-EL2 + GenieZone 架构：
  - **方案 A** (`--patch-validate`)：补丁 `gz_config_validate` 返回 0，跳过 GZ 初始化
  - **方案 B** (`--patch-init-fail`)：强制 `gz_init_main` 跳转到错误清理路径，触发 `gz_mblock_free_all` 释放内存
- VCP 禁用（MT6895 等）— 使用 GPT 方案跳过 GZ 后，VCP 子系统因 IOMMU 保护页表缺失而导致看门狗超时重启：
  - **VCP 禁用** (`--patch-vcp`)：将 LK DTB 中所有 `vcp-support=1` 修改为 0，LK 不再加载 VCP，避免 IOMMU 超时
- 脚本自动检测 LK 中的 bl2_ext GZ 初始化管线和 DTB VCP 节点
- 部分平台 GPT 方案不可用（如 MT6895 的 `halt_on_assert` 被强制置 1），此时需要 LK 方案
- 部分平台使用 GPT 方案跳过 GZ 后需配合 VCP 禁用：GZ 负责设置 IOMMU 保护页表，跳过 GZ 后 VCP 初始化 SMC 调用失败 → 60 秒看门狗超时重启。使用 `--patch-vcp` 禁用 VCP 可解决
- MT6991 等新式平台 GPT 方案不可用：preloader 不再负责加载 GZ，GZ 加载由 bl2_ext 执行。修改 GPT 后设备能进 fastboot，但无法正常启动——bl2_ext 的 `gz_init_main` 会在分区加载失败前执行不可逆的硬件配置（内存重映射、mblock 分配等），cleanup 无法完全逆转这些变更。需使用 LK bl2_ext 方案

## 快速开始

### 方案一：GPT 方案

#### 1. 检测可行性

先用 `detect_gz_bypass.py` 分析你的设备 preloader，确认 GPT 方案是否适用：

```bash
python3 detect_gz_bypass.py preloader.img
```

输出示例（GPT 可用，重名可行）：
```
============================================================
  推荐: 无效 LBA 方案 (只需修改 PGPT)
  python3 patch_gz_gpt.py <pgpt.bin>
  备选: 重名方案 (可能需同时修改 PGPT 和 SGPT)
  python3 patch_gz_gpt.py --rename <pgpt.bin> --sgpt <sgpt.bin>

  * 以上结果仅供参考, 实际可行性因固件版本和设备而异
```

输出示例（GPT 可用，重名不可行）：
```
============================================================
  推荐: 无效 LBA 方案 (只需修改 PGPT)
  python3 patch_gz_gpt.py <pgpt.bin>
  重名方案: 不可行

  * 以上结果仅供参考, 实际可行性因固件版本和设备而异
```

输出示例（GPT 不可用）：
```
============================================================
  GPT 方案不可用 → 需修改 LK 或 bl2_ext 补丁 (v6 设备)

  * 以上结果仅供参考, 实际可行性因固件版本和设备而异
```

#### 2. 修改分区表

确认 GPT 方案可用后，提取设备的 `pgpt.bin`（和可选的 `sgpt.bin`）并修改：

```bash
# 分析分区表（不修改）
python3 patch_gz_gpt.py pgpt.bin --dry-run

# 无效 LBA 方案（推荐，只需修改 PGPT）
python3 patch_gz_gpt.py pgpt.bin

# 重名方案（备选，可能需同时修改 PGPT 和 SGPT）
python3 patch_gz_gpt.py pgpt.bin --rename --sgpt sgpt.bin

# 指定输出文件名
python3 patch_gz_gpt.py pgpt.bin -o my_output.bin
```

#### 3. 刷写

```bash
# 使用底层工具刷写修补后的分区表
# mtkclient / geekflashtool / unlocktool 等均可

# 或通过 fastboot
fastboot flash pgpt pgpt_patched.bin
fastboot flash sgpt sgpt_patched.bin   # 如果同时修改了 SGPT
```

#### 4. 还原

```bash
# 使用脚本还原（同时还原 PGPT 和 SGPT）
python3 patch_gz_gpt.py pgpt.bin --sgpt sgpt.bin --restore

# 或直接刷回备份
fastboot flash pgpt pgpt_backup.bin
fastboot flash sgpt sgpt_backup.bin
```

### 方案二：LK 方案

适用于 GPT 方案不可用的平台，或 GPT 方案需配合 LK 修改的场景。

**前提条件**：修改 LK 后签名校验不通过，需要以下任一方式绕过签名：

- 使用不校验签名的 preloader（如工程版 preloader）
- 使用 [pwnage24mtk](https://github.com/jsbsbxjxh66/pwnage24mtk) 绕过签名验证

#### 1. 检测可行性

```bash
python3 detect_lk_gz.py lk.img
```

脚本自动检测 LK 类型并显示可用方案。

输出示例（bl2_ext 方案，如 MT6991）：
```
============================================================
  GZ 类型: 新式初始化管线 (bl2_ext 段)
  bl2_ext 代码: 0x1B5500  大小: 1.3 MB
  gz_init_main: 0x1CDED0
  gz_config_validate: 0x1CDEB4
  错误清理路径: 0x1CDF48 (含 gz_mblock_free_all)

  方案 A: gz_config_validate → 返回 0 (跳过 GZ 初始化)
    python3 detect_lk_gz.py lk.img --patch-validate
  方案 B: gz_init_main → 强制失败 (触发内存释放清理)
    python3 detect_lk_gz.py lk.img --patch-init-fail
  A+B:    python3 detect_lk_gz.py lk.img --patch-validate --patch-init-fail
```

#### 2. 修补 LK

bl2_ext 方案（`--patch-validate` / `--patch-init-fail`）：

```bash
# 预览补丁内容（不修改）
python3 detect_lk_gz.py lk.img --dry-run

# 方案 A: gz_config_validate 返回 0，跳过 GZ 初始化
python3 detect_lk_gz.py lk.img --patch-validate

# 方案 B: gz_init_main 强制失败，释放 GZ 内存
python3 detect_lk_gz.py lk.img --patch-init-fail

# A+B 同时应用
python3 detect_lk_gz.py lk.img --patch-validate --patch-init-fail
```

VCP 禁用（`--patch-vcp`）：

```bash
# 禁用 DTB 中的 VCP (vcp-support=1 → 0)
python3 detect_lk_gz.py lk.img --patch-vcp

# 配合 bl2_ext 方案同时使用
python3 detect_lk_gz.py lk.img --patch-validate --patch-vcp
```

通用选项：

```bash
# 指定输出文件
python3 detect_lk_gz.py lk.img --patch-validate -o my_lk.img
```

#### 3. 刷写

使用支持跳过签名验证的工具将 `lk_patched.img` 刷入设备。

#### 4. 还原

```bash
python3 detect_lk_gz.py lk.img --restore
```

---

## detect_gz_bypass.py

分析 MediaTek preloader 固件二进制文件，自动判定 GPT 修改方案是否可用。

### 检测流程

1. **GFH 头解析** — 扫描 GFH magic (`0x014D4D4D`)，提取 load_addr、BASE 地址、代码范围
2. **架构识别** — 自动区分 Thumb / Thumb PIC / AArch64
3. **GenieZone 代码检测** — 搜索 `bldr_load_gz_part`、`gz_init` 等特征字符串和 NoGZ 常量 (`0x4E6F475A`)
4. **halt_on_assert 分析** — 定位 `assert_fatal` 函数，检查 `halt_on_assert` 变量是否被无条件置 1
5. **重名可行性分析** — 双重检测：
   - 一次检测：统计 bare "gz\0" 字符串的代码引用数（PIC / literal pool / MOVW）。2+ 引用 = 主引导循环有硬依赖 → 重名不可行
   - 二次检测：定位主引导函数（通过 "Second Bootloader Load Failed" / "load images" 等标记字符串），扫描其中是否存在对 gz 分区名的引用。无引用 → 重名可行
   - 两种检测交叉验证，任一检出硬依赖即判定不可行
6. **存储类型 & LBA 风险** — 检测 UFS/eMMC 存储类型及 LBA 越界检查字符串
7. **GPT 可行性判定及子方案推荐** — 综合以上信息给出结论

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
| Thumb (非 PIC) | 直接地址引用 | MT6895, K50 |
| Thumb PIC | LDR + ADD PC 位置无关代码 | MT6833, MT6893 |
| AArch64 | ADRP + ADD 页相对寻址 | MT6983, MT6991 |

架构自动检测，无需手动指定。

### 输入文件

- 标准 preloader 固件 (`preloader.img`)
- 带 UFS_BOOT 磁盘头的固件 (`preloader_k6895v1_64.bin`)，GFH 通常在 0x2000 偏移处
- 脚本在前 64KB 范围内扫描 GFH magic，兼容各种头部格式

### GPT 判定逻辑

GPT 方案的前提是 `halt_on_assert` 未被强制置 1，否则 `assert_fatal` 会触发 WDT reset。

| halt_on_assert 状态 | GPT 结论 | 含义 |
|---------------------|---------|------|
| 未强制置 1 | **可用** | assert 非致命，I/O 失败后正常设置 NoGZ 并继续启动 |
| 无条件置 1 | **不可用** | assert 致命，I/O 失败触发 WDT reset |
| 无法检测 | **未知** | 需要手动逆向分析 |

GPT 可用时，脚本进一步推荐子方案：

| 重名可行性 | 推荐 | 命令 |
|-----------|------|------|
| 可行 | 无效 LBA (推荐) + 重名 (备选) | `patch_gz_gpt.py <pgpt.bin>` |
| 不可行 | 无效 LBA 方案 | `patch_gz_gpt.py <pgpt.bin>` |
| 未知 | 无效 LBA 方案 | `patch_gz_gpt.py <pgpt.bin>` |

无效 LBA 方案只需修改 PGPT，重名方案可能需同时修改 PGPT 和 SGPT（`--sgpt`）。

**重名方案判定**：preloader 的 `gz_init` 加载 gz 分区时，找不到分区名会正常设置 NoGZ。但部分平台（如 MT6833）的主引导循环在 gz_init **之外**还独立调用 `name_resolver("gz")`，该调用失败导致整个引导流水线中断（跳过 LK 加载 → 无限循环）。脚本通过代码引用计数 + 主引导函数扫描双重检测来判定。

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
| `重名方案` | gz 分区重名可行性：可行 / 不可行 / 未知 |
| `主引导函数` | 主引导函数代码范围及是否包含 gz 分区名引用 |
| `存储类型` | UFS / eMMC |
| `无效 LBA 欺骗` | UFS 越界风险检测 |

---

## patch_gz_gpt.py

修改 GPT 分区表中的 gz 分区，支持 PGPT（主分区表）和 SGPT（备份分区表）同时修改，两种子方案：

- **重名方案** (`--rename`)：将 gz 分区名改为 gx，preloader 的 `get_part_info("gz")` 找不到分区 → 无 I/O → 设置 NoGZ
- **无效 LBA 方案**（默认）：将 gz 分区 LBA 改为越界地址 (`total_lbas`)，存储 I/O 失败 → 设置 NoGZ

### 用法

```bash
# 分析分区表（不修改）
python3 patch_gz_gpt.py pgpt.bin --dry-run

# 无效 LBA 方案（推荐，只需修改 PGPT）
python3 patch_gz_gpt.py pgpt.bin

# 重名方案（备选，可能需同时修改 PGPT 和 SGPT）
python3 patch_gz_gpt.py pgpt.bin --rename --sgpt sgpt.bin

# 指定输出文件
python3 patch_gz_gpt.py pgpt.bin -o modified.bin

# 从备份还原（同时还原 SGPT）
python3 patch_gz_gpt.py pgpt.bin --sgpt sgpt.bin --restore
```

### 特性

- 支持同时修改 PGPT 和 SGPT（`--sgpt`），确保主备分区表一致
- 自动检测扇区大小（512 字节 eMMC / 4096 字节 UFS）
- 自动检测 SGPT 格式（GPT 头在文件末尾，分区条目在文件开头）
- 自动备份原始文件（PGPT 和 SGPT 各自独立备份）
- CRC32 校验自动更新（Header CRC + Entries CRC）
- 支持 gz/gz1/gz2/gz_a/gz_b 等所有 A/B 分区命名
- SGPT 中 gz 分区已被删除时自动跳过，不报错

### 提取 pgpt.bin / sgpt.bin

使用 mtkclient / geekflashtool / unlocktool 等工具从设备提取 `pgpt` 和 `sgpt` 分区。也可使用 `mtk-pgpt-tool/dump_pgpt.sh` 在已 root 设备上直接提取：

```bash
sh dump_pgpt.sh read         # 提取 PGPT
sh dump_pgpt.sh read-sgpt    # 提取 SGPT
```

---

## detect_lk_gz.py

分析 LK (Little Kernel) 固件，检测 bl2_ext GZ 初始化管线并提供补丁。支持 DTB VCP 节点禁用。

### 检测流程

1. **MTK 镜像头解析** — 解析 magic `0x58881688`，提取 LK 代码段及各子段（lk / bl2_ext / aee / dtb）
2. **架构识别** — 支持 AArch64 和 ARM32（通过异常向量表/首指令特征自动识别）
3. **GZ 代码检测** — 搜索 `pl_boottags_gz_*_hook`、`[GZ_INIT]` 等特征字符串
4. **bl2_ext 管线检测** — 在 bl2_ext 段搜索 `[GZ_INIT] init success/failed` 字符串，回溯 ADRP+ADD 引用定位 `gz_init_main`、`gz_config_validate`、错误清理路径
5. **DTB VCP 检测** — 扫描所有 FDT blob，解析设备树节点，定位 `vcp-support` 属性及其值

### 用法

```bash
# 分析 LK 镜像（自动检测类型）
python3 detect_lk_gz.py lk.img

# 预览所有补丁（不修改文件）
python3 detect_lk_gz.py lk.img --dry-run

# 方案 A: gz_config_validate 返回 0，跳过 GZ 初始化
python3 detect_lk_gz.py lk.img --patch-validate

# 方案 B: gz_init_main 强制失败，释放 GZ 内存
python3 detect_lk_gz.py lk.img --patch-init-fail

# 禁用 VCP (DTB vcp-support=1 → 0)
python3 detect_lk_gz.py lk.img --patch-vcp

# 从备份还原
python3 detect_lk_gz.py lk.img --restore
```

### bl2_ext GZ 初始化管线（MT6991 等）

MT6991 等新一代 SoC 使用 Hafnium S-EL2 + GenieZone 架构。GZ 初始化逻辑不再位于 lk 段，而是在 **bl2_ext** 段（独立签名）中，没有 `gz_enabled` 全局变量和 `gz_unmap_check` 函数。

#### GZ 初始化流程

```
gz_init_wrapper:
  BL   gz_config_validate     ; 检查 GZ 配置是否有效
  TBZ  W0, #0, skip           ; 返回 0 → 跳过 GZ 初始化
  BL   gz_init_main           ; 执行 GZ 初始化
skip:
  ...

gz_init_main:
  BL   gz_config_env_get      ; 获取配置环境
  ...                         ; 加载 gz.img → 配置 → 跳转
  → 成功: "[GZ_INIT] init success; gz will boot!!"
  → 失败: "[GZ_INIT] config env not valid"
           → gz_config_cleanup
           → gz_mblock_free_all   ; 释放所有 GZ 内存
           → "[GZ_INIT] init failed; gz is disabled from now on"
```

#### 方案 A：补丁 gz_config_validate (`--patch-validate`)

将 `gz_config_validate` 中计算返回值的指令（BIC W0, W9, W8）替换为 `MOV W0, #0`。效果：

- `gz_config_validate` 始终返回 0
- `gz_init_wrapper` 的 TBZ 条件跳过 `gz_init_main` 调用
- GZ 初始化完全不执行

```
原始:                          补丁后:
  PACIASP                       PACIASP
  ADRP X8, <page>               ADRP X8, <page>
  MOV  W9, #1                   MOV  W9, #1
  LDRB W8, [X8, #0x150]         LDRB W8, [X8, #0x150]
  BIC  W0, W9, W8               MOV  W0, #0     ; ← 补丁
  AUTIASP                       AUTIASP
  RET                           RET
```

#### 方案 B：强制 gz_init_main 失败 (`--patch-init-fail`)

将 `gz_init_main` 的第一条 BL（调用 `gz_config_env_get`）替换为 B（无条件跳转）到错误清理路径。效果：

- `gz_init_main` 直接跳转到 "config env not valid" 错误处理
- 执行 `gz_config_cleanup` → `gz_mblock_free_all` 释放所有 GZ 保留内存
- 打印 "init failed; gz is disabled from now on"

```
原始:                          补丁后:
  PACIASP                       PACIASP
  STP  X29, X30, [SP, #-32]!    STP  X29, X30, [SP, #-32]!
  STP  X20, X19, [SP, #16]      STP  X20, X19, [SP, #16]
  ADD  X29, SP, #0               ADD  X29, SP, #0
  BL   gz_config_env_get         B    cleanup_path  ; ← 补丁
  ...                           ...
cleanup_path:                  cleanup_path:
  → gz_config_cleanup             → gz_config_cleanup
  → gz_mblock_free_all            → gz_mblock_free_all
```

#### bl2_ext 方案选择

| 场景 | 推荐 |
|------|------|
| 仅跳过 GZ | 方案 A（最小改动，不触发任何 GZ 代码） |
| 跳过 GZ 并确保内存释放 | 方案 B（走错误清理路径，调用 `gz_mblock_free_all`） |
| 最大兼容性 | A+B 同时使用 |

> **注意**：方案 A 跳过了整个 `gz_init_main`，`gz_mblock_free_all` 可能不被调用。如果 preloader 已经为 GZ 预留了内存（通过 `gz-tee-static-shm` mblock），方案 A 不会释放这些内存。方案 B 的错误清理路径会显式调用 `gz_mblock_free_all`，因此推荐使用方案 B 或 A+B。

### VCP 禁用（MT6895 等）

部分平台（如 MT6895）使用 GPT 方案跳过 GZ 后，设备会在开机约 60 秒后看门狗超时重启。根本原因：

```
GZ 被跳过
  → ATF 中 IOMMU 保护页表 (platform_mtksmmu_protpgd) 未被创建
  → VCP 初始化时调用 vcp_smc_vcp_init SMC
  → ATF 的 mtk_iommu_init_protect_pt_mem 查询 mblock 失败
  → VCP IOVA 映射失败
  → 60 秒看门狗超时 → 强制重启
```

`--patch-vcp` 通过修改 LK 内嵌 DTB 中的 `vcp-support` 属性来解决此问题：

- 扫描 LK 镜像中所有 FDT blob（通过 FDT magic `0xD00DFEED`）
- 解析每个 DTB 的节点树，定位 `vcp@*` 节点下的 `vcp-support` 属性
- 将所有 `vcp-support = <0x01>`（已启用）修改为 `<0x00>`（已禁用）
- LK 的 `app_load_vcp()` 读取 DTB 中的 `vcp-support`：值为 0 时直接返回，不加载 VCP

```
原始 DTB:                      补丁后:
  vcp@1ec00000 {                 vcp@1ec00000 {
    compatible = "mediatek,vcp";   compatible = "mediatek,vcp";
    vcp-support = <0x01>;   ←      vcp-support = <0x00>;   ← 已禁用
    status = "okay";               status = "okay";
  };                             };
```

> **注意**：VCP 禁用后，依赖 VCP 的功能（如硬件视频编解码加速、语音处理等）可能不可用或回退到软件实现。

### 输出字段说明

**bl2_ext 方案：**

| 字段 | 含义 |
|------|------|
| `GZ 类型` | 初始化管线类型 (bl2_ext 段) |
| `bl2_ext 代码` | bl2_ext 段的文件偏移和大小 |
| `gz_init_main` | GZ 初始化主函数的文件偏移 |
| `gz_config_validate` | 配置验证函数的文件偏移 |
| `错误清理路径` | 错误处理入口的文件偏移（含 `gz_mblock_free_all`） |

**VCP 禁用：**

| 字段 | 含义 |
|------|------|
| `DTB` | FDT blob 的文件偏移和大小 |
| `VCP 节点` | vcp-support 属性的路径、值和文件偏移 |
| `状态` | 已启用 / 已禁用 / 需补丁数量 |

**通用：**

| 字段 | 含义 |
|------|------|
| `Boot Tag 钩子` | preloader 传递 GZ 配置的 boot tag 回调函数 |
| `DTB GZ 节点` | 设备树中的 GZ 相关节点（trusty-gz / nebula 等） |

---

## 原理

### 启动流程中的 GenieZone

**v5 旧式架构（MT6833/MT6893 等，preloader 初始化 gz（存在不初始化 gz 的 preloader），LK 无 GZ 代码）：**

```
BROM → preloader (签名验证) → ATF → LK → kernel
              │                          │
              ├─ gz_init(): 读取 gz 分区  ├─ LK 无 gz_unmap_check
              │   失败 → 设置 NoGZ 标志   │   无 GZ 功能代码, 仅有分区名/DTB 节点
              ├─ 分区加载循环: 加载        │   GZ 禁用完全由 preloader 阶段决定
              │   tee/gz/scp 等分区镜像    └─ DTB: trusty-gz / nebula 节点 → kernel
              └─ ATF 跳转: 根据 NoGZ
                  决定是否将 EL2 移交给 GZ
```

**v6 架构（MT6895 等，preloader 初始化 gz，LK 含 VCP）：**

```
BROM → preloader (签名验证) → ATF → LK → kernel
              │                          │
              ├─ gz_init(): 读取 gz 分区  ├─ app_load_vcp(): 读取 DTB vcp-support
              │   配置 → 设置 NoGZ 标志   │   vcp-support=1 → 加载 VCP → SMC 初始化
              ├─ 分区加载循环: 加载        │   vcp-support=0 → 跳过 VCP 加载
              │   tee/gz/scp 等分区镜像    │   (GZ 跳过时 IOMMU 保护页表缺失 →
              └─ ATF 跳转: 根据 NoGZ      │    VCP SMC 失败 → 60s WDT 超时)
                  决定是否将 EL2 移交给 GZ  └─ DTB: trusty-gz / nebula / vcp 节点 → kernel
```

**v6 新式架构带 AVF（MT6991 等，bl2_ext 初始化 gz，Hafnium S-EL2）：**

```
BROM → preloader (签名验证) → ATF → LK (bl2_ext) → LK (lk) → kernel
              │                          │
              ├─ gz-tee-static-shm       ├─ gz_config_validate()
              │   mblock 预留             │   返回 0 → 跳过 GZ 初始化
              └─ ...                     ├─ gz_init_main()
                                         │   → gz_config_env_get
                                         │   → 加载 gz.img → 配置 → 启动 GZ
                                         │   → 失败路径: gz_mblock_free_all
                                         └─ DTB: nebula / trusty-gz 节点 → kernel
```

- **GPT 方案**（MT6833/MT6893 等）：作用于 preloader 阶段，让 gz 分区 I/O 失败 → NoGZ → 跳过 GZ 加载。LK 无 GZ 代码，GPT 方案即可完全禁用
- **GPT + VCP 禁用**（MT6895 等）：GPT 方案触发 NoGZ 跳过 GZ，但 VCP 因缺少 IOMMU 保护页表导致超时重启，需配合 `--patch-vcp` 禁用 VCP
- **bl2_ext 方案 A**：补丁 gz_config_validate → 返回 0 → 跳过 bl2_ext 中的 GZ 初始化
- **bl2_ext 方案 B**：补丁 gz_init_main → 强制走失败路径 → gz_mblock_free_all 释放内存

### GPT 子方案 A: 重名方案

将 gz 分区名改为 gx（保留 LBA 不变），`get_part_info("gz1")` 找不到分区 → 返回失败 → 设置 NoGZ。

```
阶段 1: gz_init()
  read_part("gz")
    name_resolver("gz") → "gz1" → get_part_info("gz1") → 找不到（已改名为 gx1）
  read_part 返回 -1 → 设置 NoGZ = 0x4E6F475A  ✓

阶段 2: 主分区加载循环
  情况 A (MT6893 等): gz 加载完全封装在 gz_init 中，主循环不独立引用 "gz" → 安全 ✓
  情况 B (MT6833 等): 主循环独立调用 name_resolver("gz") → 找不到 → 致命错误 ✗
```

**重名方案是否可行取决于 preloader 主引导函数是否独立引用 "gz" 分区名。** `detect_gz_bypass.py` 通过双重检查（代码引用计数 + 主引导函数扫描）自动判定。

### GPT 子方案 B: 无效 LBA 欺骗

核心发现：`get_part_info()` 只做名称匹配，不验证 LBA 地址有效性。而实际的存储 I/O 由 `func_40974` 执行，它在读取失败时返回 -1。

将 gz1 分区的 LBA 改为超出设备容量的值后：

```
阶段 1: gz_init()
  read_part("gz")
    name_resolver("gz") → "gz1" → get_part_info("gz1") → 找到 ✓
    func_40974 → 读取无效 LBA → 失败 → return -1
  read_part 返回 -1 → 设置 NoGZ = 0x4E6F475A  ✓

阶段 2: 主分区加载循环
  name_resolver("gz") → "gz1" → get_part_info("gz1") → 找到 → return 0  ✓
  bldr_load_gz_part()
    is_el2_enabled() → 0 (NoGZ 已设置)
    skip load gz → return 0  ✓
```

无效 LBA 方案不依赖主引导函数的代码结构，兼容性更广，但存储控制器对越界 LBA 的处理因硬件而异。


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

### GPT 方案

**使用重名方案后黑砖**

主引导函数独立引用了 "gz" 分区名（如 MT6833），分区找不到导致致命错误。解决方案：
1. 还原 GPT (`python3 patch_gz_gpt.py pgpt.bin --restore`)
2. 改用无效 LBA 方案 (`python3 patch_gz_gpt.py pgpt.bin`)

**亮一下 logo 就重启**

Preloader 阶段成功，但 LK 或 kernel 阶段失败。可能原因：

1. **LK/kernel 阶段 UFS 崩溃** — preloader 正常返回错误，但后续阶段读取无效 LBA 时控制器崩溃

2. **当前版本preloader不适用** — halt_on_assert 被无条件置 1, assert_fatal 触发 WDT reset。尝试 LK 方案

**能进 fastboot 但无法正常启动（MT6991 等新式平台）**

GPT CRC 校验正确，preloader 和 LK 正常运行（因此 fastboot 可用），但正常启动失败。根本原因：bl2_ext 中 `gz_init_main` 在分区加载失败前已执行了不可逆的硬件配置：

```
gz_init_main 执行流程（GPT 方案下）:
  ① BL gz_config_env_get ×3     ✅ 已执行 — 配置环境初始化
  ② BL gz_remap_init             ⚠️ 可能执行 — 内存重映射/安全区域配置
  ③ BL gz_mblock_create          ✅ 已执行 — 分配 4 个 mblock 内存区域
  ④ BL gz_part_load_image        ❌ 失败 — UFS 读取无效 LBA
  ⑤ cleanup: gz_mblock_free_all  ✅ 已执行 — 释放 mblock

  问题: ②的内存重映射/安全配置变更不被 cleanup 逆转
        → 内核启动时内存布局异常 → 启动失败
```

LK 补丁方案不存在此问题：
- **方案 A** (`--patch-validate`)：`gz_init_main` 完全不执行，①~⑤ 均跳过
- **方案 B** (`--patch-init-fail`)：第一条指令直接跳到 cleanup，①~④ 均跳过

**完全无响应（黑砖）**

UFS 控制器在 preloader 阶段读取越界 LBA 时崩溃（控制器 bug）。需要通过 mtkclient 或 SP Flash Tool 底层恢复刷回备份 GPT。

### LK 方案

**签名验证失败，无法启动**

LK 方案修改了 LK 代码/数据，签名校验不通过。需要使用不校验签名的 preloader 或 [pwnage24mtk](https://github.com/jsbsbxjxh66/pwnage24mtk) 绕过签名验证。

**GPT 方案跳过 GZ 后约 60 秒看门狗重启（MT6895 等）**

GZ 被跳过后，ATF 中的 IOMMU 保护页表 (`platform_mtksmmu_protpgd`) 未被创建。VCP 初始化时调用 `vcp_smc_vcp_init` SMC → ATF 查询 mblock 失败 → VCP IOVA 映射失败 → 60 秒看门狗超时重启。使用 `--patch-vcp` 禁用 VCP 可解决。

**补丁后仍未释放 GZ 内存**

可能原因：
1. **方案 A**：`--patch-validate` 跳过了 `gz_init_main`，`gz_mblock_free_all` 未被调用。如果 preloader 已通过 `gz-tee-static-shm` 预留了内存，这部分内存不会被释放 → 使用 `--patch-init-fail`（方案 B）或 A+B
2. 内核层面的 trusty-gz / nebula 驱动仍在尝试初始化 GZ（通常会优雅失败，不影响启动）

---

## 兼容性

### 已测试设备

| 设备 | SoC | 系统 | Preloader 指令集 | LK 指令集 | GPT 重名 | GPT LBA | LK 方案 | 已验证 |
|------|-----|------|-----------------|----------|---------|---------|---------|--------|
| OPPO A55 | MT6833 | Android 13 | ARM32 Thumb PIC | ARM32 | **不可行** | **可用** | 不适用（LK 无 GZ 代码） | ✅ |
| OPPO K9 Pro | MT6893 | Android 13 | ARM32 Thumb PIC | ARM32 | 未测试 | **可用** | 不适用（LK 无 GZ 代码） | ✅ |
| Realme GT Neo 闪速版 | MT6893 | Android 13 | ARM32 Thumb PIC | ARM32 | 未测试 | **可用** | 不适用（LK 无 GZ 代码） | ✅ |
| — | MT6895 | — | ARM32 Thumb | AArch64 | 未测试 | 未测试 | 未测试 | — |
| — | MT6991 | — | AArch64 | AArch64 | — | 未测试 | 未测试 | — |

### 其他

| 项目 | 说明 |
|------|------|
| 扇区大小 | 自动检测 512 字节 (eMMC) / 4096 字节 (UFS) |
| 分区名称 | 支持 gz/gz1/gz2/gz_a/gz_b/gz1_a/gz1_b/gz2_a/gz2_b |
| Python | 3.6+，无第三方依赖 |

## 风险与注意事项

- **检测脚本不是万能的**：成功与否你都得有能够救砖的能力
- **适用平台**：同处理器有失败的不代表不行可能你只是缺少一个合适的preloader固件
- **UFS 崩溃**：部分 UFS 控制器在遇到越界 LBA 时会崩溃而非返回错误（GPT 方案）
- **OTA 更新**：系统 OTA 可能还原 GPT / LK 到原始状态，需要重新修改
- **可恢复性**：GPT 方案仅修改分区表，LK 方案自动备份原始固件，均可随时还原
- **备份 GPT**：使用 `--sgpt` 同时修改 PGPT 和 SGPT，确保主备分区表一致。部分 preloader 在主 GPT 校验失败时会回退到备份 GPT，仅修改 PGPT 可能因 SGPT 中 gz 分区仍有效而导致方案失效
- **LK 签名**：LK 方案修改了代码/数据，需要不校验签名的 preloader 或 [pwnage24mtk](https://github.com/jsbsbxjxh66/pwnage24mtk) 绕过签名
- **处理器代际差异**：
  - 天玑 v5 及以下（如 MT6833/MT6893）：GPT LBA 方案通常直接可用，LK 无 GZ 代码不需要 LK 方案
  - 天玑 v6（如 MT6895）：GPT 方案跳过 GZ 后需配合 `--patch-vcp` 禁用 VCP，否则 VCP IOMMU 超时导致 60 秒看门狗重启
  - 天玑 v6+（如 MT6991）：GPT 方案不可用（修改 GPT 后能进 fastboot 但无法正常启动，bl2_ext 中 GZ 初始化的部分执行导致不可逆硬件配置变更），需使用 bl2_ext 方案（`--patch-validate` / `--patch-init-fail`）
  - 或使用 [pwnage24mtk](https://github.com/jsbsbxjxh66/pwnage24mtk) 高级用法直接干掉 GenieZone
- **功能影响**：禁用 GenieZone 后，依赖 GZ 虚拟化服务的功能（如部分 DRM、安全容器等）可能不可用；禁用 VCP 后，硬件视频编解码加速等功能可能不可用或回退到软件实现

## License

MIT — 详见 [LICENSE](LICENSE) 文件。
