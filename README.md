# mtk-soc-disable-geniezone

禁用联发科 GenieZone (GZ) 虚拟化管理程序。支持两种方案：修改 GPT 分区表（preloader 层面）或修补 LK 固件（LK 层面）。LK 方案支持 bl2_ext GZ 初始化管线补丁和 DTB VCP 节点禁用。ATF 方案支持三层补丁：SMMU 保护跳过 + VCP handler 旁路 + DEVMPU 重置（清除 preloader 设置的所有硬件访问限制）。VCP 禁用方案需同时修补 LK DTB 和 vendor_boot DTB（内核设备树）。

> **免责声明**
>
> 本工具仅供安全研究和个人设备调试使用。使用本工具修改设备固件存在**变砖风险**，包括但不限于：设备无法启动、需要通过底层工具救砖、丢失保修资格等。作者不对因使用本工具造成的任何损失承担责任。**使用前请务必备份原始固件，风险自负。**

## 项目结构

| 工具 | 用途 |
|------|------|
| `detect_gz_bypass.py` | 分析 preloader 固件，检测 GPT 修改方案是否可用，推荐无效 LBA 或重名子方案 |
| `patch_gz_gpt.py` | 修改 GPT 分区表（PGPT）：重名 gz→gx（`--rename`）或将 LBA 指向无效地址（默认） |
| `detect_lk_gz.py` | 分析 LK 固件，检测并修补 bl2_ext GZ 初始化管线，支持 DTB VCP 节点禁用 |
| `patch_tee_vcp.py` | 补丁 ATF (tee.img)，三层补丁：跳过 SMMU 保护设置 + DEVMPU 重置，解决禁用 GZ 后 VCP 崩溃和 DEVMPU 违规问题 |
| `patch_vendor_boot.py` | 修补 vendor_boot.img 中的内核设备树，禁用 VCP 驱动 probe（配合 `--patch-vcp` 使用） |

## 两种方案

| 方案 | 层面 | 条件 | 是否需要跳过签名 |
|------|------|------|-----------------|
| **GPT 重名方案** | Preloader | `halt_on_assert` 未强制置 1 且主引导循环无 gz 硬依赖 | 否 |
| **GPT 无效 LBA 方案** | Preloader | `halt_on_assert` 未被强制置 1 | 否 |
| **LK bl2_ext 方案** | LK (bl2_ext 段) | bl2_ext 中存在 GZ 初始化管线 | 是 |
| **ATF VCP 修复** | ATF (tee.img) | ATF 中存在 vcp_smc_vcp_init 函数和 DEVMPU 初始化函数 | 是 |
| **VCP 禁用** | LK (DTB) + vendor_boot (DTB) | DTB 中存在 vcp-support 节点 | 是 |

- GPT 方案有两个子方案，均不修改代码：
  - **重名方案** (`--rename`)：将 gz 分区改名为 gx，`get_part_info("gz")` 找不到分区 → 无 I/O → 设置 NoGZ。需 preloader 主引导循环不独立依赖 gz 分区名解析（`detect_gz_bypass.py` 自动检测）
  - **无效 LBA 方案**（默认）：将 gz 分区 LBA 改为越界地址，存储 I/O 失败 → 设置 NoGZ
- LK bl2_ext 方案（MT6991 等）— GZ 逻辑在 bl2_ext 段，使用 Hafnium S-EL2 + GenieZone 架构：
  - **方案 A** (`--patch-validate`)：补丁 `gz_config_validate` 返回 0，跳过 GZ 初始化
  - **方案 B** (`--patch-init-fail`)：强制 `gz_init_main` 跳转到错误清理路径，触发 `gz_mblock_free_all` 释放内存
- VCP 修复/禁用（MT6895 等）— 使用 GPT 方案跳过 GZ 后，VCP 子系统因 SMMU 保护页表为空而导致看门狗超时重启，以及 DEVMPU 域7访问违规洪泛：
  - **ATF VCP 修复** (`patch_tee_vcp.py`，推荐）：三层补丁 ATF。Layer 1 在 SMMU 保护函数内部跳过硬件编程（覆盖所有 5 个调用点），Layer 2 在 `vcp_smc_vcp_init` 中跳过保护调用并走"零化+成功"路径，Layer 3 在 DEVMPU init 函数中注入 devmpu_reset 调用（通过 code cave 中的 trampoline），在 DEVMPU 启用前写入 reset 命令（7→1）到控制寄存器 `0x10351104`/`0x10355104`，清除 preloader 设置的所有 DEVMPU APC（Access Permission Control）限制。VCP 仅使用内核 M4U IOMMU（正常工作），无需 SMMU 保护层。视频硬件编解码不受影响
  - **VCP 禁用** (`--patch-vcp` + `patch_vendor_boot.py`，备用）：将 LK DTB 和 vendor_boot DTB 中所有主 VCP 节点的 `vcp-support=1` 改为 0，`status="okay"` 改为 `"fail"`。LK 不加载 VCP 固件，内核 VCP 驱动不 probe，避免 IOMMU 超时。需同时修改两个镜像（LK 控制固件加载，vendor_boot 控制内核驱动 probe）。视频硬件编解码不可用
- 脚本自动检测 LK 中的 bl2_ext GZ 初始化管线和 DTB VCP 节点
- 部分平台 GPT 方案不可用（如 `halt_on_assert` 被强制置 1 的平台），此时需要 LK 方案
- 部分平台使用 GPT 方案跳过 GZ 后需处理 VCP 问题：GZ 负责填充 SMMU 保护页表（protpgd）的页表项，跳过 GZ 后页表为空，VCP DMA 映射到 PA=0x0 触发 IOMMU translation fault → 60 秒看门狗超时重启。此外，DEVMPU（Device Memory Protection Unit）的域7（VCP/APU）访问限制由 preloader 设置，正常情况下 VCP 通过 GZ 代理访问受保护内存，跳过 GZ 后 VCP 直接访问被 DEVMPU 拒绝，导致 DEVMPU 违规洪泛（约启动后 33 秒触发 12000+ 次违规 → IRQ 风暴 → HWT 崩溃）。推荐使用 `patch_tee_vcp.py` 三层补丁 ATF（跳过 SMMU 保护 + DEVMPU 重置，保留 VCP 功能），或使用 `detect_lk_gz.py --patch-vcp` + `patch_vendor_boot.py` 禁用 VCP（需同时修补 LK 和 vendor_boot 两个镜像的 DTB）
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
  备选: 重名方案
  python3 patch_gz_gpt.py --rename <pgpt.bin>

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

确认 GPT 方案可用后，提取设备的 `pgpt.bin` 并修改：

```bash
# 分析分区表（不修改）
python3 patch_gz_gpt.py pgpt.bin --dry-run

# 无效 LBA 方案（推荐，只需修改 PGPT）
python3 patch_gz_gpt.py pgpt.bin

# 重名方案（备选）
python3 patch_gz_gpt.py pgpt.bin --rename

# 指定输出文件名
python3 patch_gz_gpt.py pgpt.bin -o my_output.bin
```

#### 3. 刷写

```bash
# 使用底层工具刷写修补后的分区表
# mtkclient / geekflashtool / unlocktool 等均可

# 或通过 fastboot
fastboot flash pgpt pgpt_patched.bin
fastboot flash sgpt pgpt_patched.bin   # 同步刷写到备份 GPT（可选）
```

#### 4. 还原

```bash
# 使用脚本还原
python3 patch_gz_gpt.py pgpt.bin --restore

# 或直接刷回备份
fastboot flash pgpt pgpt_backup.bin
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

VCP 禁用（`--patch-vcp` + `patch_vendor_boot.py`，仅在 ATF 补丁不可用时使用）：

```bash
# 步骤 1: 禁用 LK DTB 中的 VCP (LK 不加载 VCP 固件)
python3 detect_lk_gz.py lk.img --patch-vcp

# 步骤 2: 禁用 vendor_boot DTB 中的 VCP (内核 VCP 驱动不 probe)
python3 patch_vendor_boot.py vendor_boot.img
```

> **重要**：两步都要做。LK DTB 控制 bootloader 是否加载 VCP 固件，vendor_boot DTB 控制内核 VCP 驱动是否 probe。只改 LK 不改 vendor_boot 会导致内核仍然尝试使用 VCP。

### 方案三：ATF VCP 修复（配合 GPT 方案使用）

适用于 GPT 方案跳过 GZ 后 VCP 崩溃的平台（如 MT6895）。补丁 tee.img 跳过 SMMU 保护设置。

**前提条件**：与 LK 方案相同，需要绕过签名验证。

```bash
# 分析 tee.img（不修改）
python3 patch_tee_vcp.py tee.img --dry-run

# 应用补丁
python3 patch_tee_vcp.py tee.img -o tee_patched.img

# 检测是否已打补丁
python3 patch_tee_vcp.py tee_patched.img --dry-run
```

> **注意**：此补丁与 `--patch-protpgd` 互斥，不要同时使用。使用此补丁后 protpgd mblock 不再需要。

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

无效 LBA 方案和重名方案均修改 PGPT。部分设备可能需要将修改后的文件同时刷写到 SGPT 以确保一致性。

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

修改 GPT 分区表中的 gz 分区（PGPT 主分区表），两种子方案：

- **重名方案** (`--rename`)：将 gz 分区名改为 gx，preloader 的 `get_part_info("gz")` 找不到分区 → 无 I/O → 设置 NoGZ
- **无效 LBA 方案**（默认）：将 gz 分区 LBA 改为越界地址 (`total_lbas`)，存储 I/O 失败 → 设置 NoGZ

### 用法

```bash
# 分析分区表（不修改）
python3 patch_gz_gpt.py pgpt.bin --dry-run

# 无效 LBA 方案（推荐，只需修改 PGPT）
python3 patch_gz_gpt.py pgpt.bin

# 重名方案（备选）
python3 patch_gz_gpt.py pgpt.bin --rename

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

### 提取 pgpt.bin

使用 mtkclient / geekflashtool / unlocktool 等工具从设备提取 `pgpt` 分区。也可使用 `mtk-pgpt-tool/dump_pgpt.sh` 在已 root 设备上直接提取：

```bash
sh dump_pgpt.sh read         # 提取 PGPT
```

---

## detect_lk_gz.py

分析 LK (Little Kernel) 固件，检测 bl2_ext GZ 初始化管线并提供补丁。支持 DTB VCP 节点禁用。

### 检测流程

1. **MTK 镜像头解析** — 解析 magic `0x58881688`，提取 LK 代码段及各子段（lk / bl2_ext / aee / dtb）
2. **架构识别** — 支持 AArch64 和 ARM32（通过异常向量表/首指令特征自动识别）
3. **GZ 代码检测** — 搜索 `pl_boottags_gz_*_hook`、`[GZ_INIT]` 等特征字符串
4. **bl2_ext 管线检测** — 在 bl2_ext 段搜索 `[GZ_INIT] init success/failed` 字符串，回溯 ADRP+ADD 引用定位 `gz_init_main`、`gz_config_validate`、错误清理路径
5. **DTB VCP 检测** — 扫描所有 FDT blob，解析设备树节点，定位主 VCP 节点的 `vcp-support` 和 `status` 属性及其值

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

# 禁用 VCP (DTB vcp-support=1→0, status="okay"→"fail")
# 仅在 patch_tee_vcp.py ATF 补丁不可用时使用
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

### VCP 修复/禁用（MT6895 等）

部分平台（如 MT6895）使用 GPT 方案跳过 GZ 后，设备会在开机约 60 秒后看门狗超时重启。根本原因：

```
GZ 被跳过
  → SMMU 保护页表 (protpgd) 虽然分配了但页表项为空 (GZ 负责填充)
  → ATF 的 vcp_smc_vcp_init 配置 SMMU 寄存器指向空页表
  → VCP DMA 映射到 PA=0x0 (空页表默认映射)
  → IOMMU translation fault → 无限 WDT 重启循环

  同时:
  → DEVMPU APC 由 preloader 编程，限制域7 (VCP/APU) 访问 PROT_SHARED
  → 正常时 VCP 通过 GZ 代理访问 (GZ 有权限)
  → GZ 被跳过后 VCP 直接访问被 DEVMPU 拒绝
  → 12000+ 次 DEVMPU 违规 → IRQ 风暴 → 约 33 秒后 HWT 崩溃
```

提供两种解决方案：

#### 推荐方案：ATF VCP 补丁 (`patch_tee_vcp.py`)

三层补丁 ATF，跳过 SMMU 保护设置并重置 DEVMPU。

**背景**：禁用 GZ 后 ATF 层面有两个独立的硬件保护问题：

1. **SMMU 保护页表为空**：ATF 中有一个 SMMU 保护函数，被 5 个不同的 SMC handler 调用。该函数内部先做验证/查找，再做 SMMU 硬件编程。当 GZ 被禁用时，protpgd 页表为空，任何一个调用点触发 SMMU 编程都会导致空页表被加载到硬件。内核的 `iommu_secure.ko` 在启动早期（~1.1s）就通过 SMC 调用编程 SMMU，远早于 VCP 启动（~7.7s），因此仅补丁 VCP handler 不够。

2. **DEVMPU APC 限制**：DEVMPU（Device Memory Protection Unit，位于 0x10351000/0x10355000）是 MTK 平台的可编程内存保护单元。Preloader 在启动时编程 DEVMPU APC（Access Permission Control）寄存器，限制域7（VCP/APU）访问 PROT_SHARED 内存区域（region 10）。正常情况下 VCP 的内存请求通过 GZ 代理（GZ 有权限），但禁用 GZ 后 VCP 直接访问被 DEVMPU 拒绝——触发 12000+ 次违规中断，形成 IRQ 风暴，约 33 秒后导致 HWT（Hardware Watchdog Timeout）崩溃。ATF 初始化 DEVMPU 时只编程区域边界（start/end addresses），不触碰 APC，preloader 设置的限制原封不动保留。

**三层补丁**：

```
Layer 1 (全局): 保护函数内部
  原始:  BL smmu_programming    ; 第 2 个 BL，执行 SMMU 硬件编程
  补丁:  MOVZ W0, #0            ; 返回成功，跳过硬件编程
  效果:  所有 5 个调用点都不会编程 SMMU 硬件

Layer 2 (VCP handler): vcp_smc_vcp_init 内部
  原始:                          补丁后:
    LDR   X0, [X25, #0x650]       NOP
    LDR   X1, [X26, #0x658]       NOP
    MOVZ  W3, #1                   NOP
    MOV   W2, WZR                  NOP
    BL    protection_func           B     skip_path               ← 跳到零化+返回成功
  效果:  VCP handler 完全不处理 protpgd 指针
         skip_path 零化保护寄存器 [X24,#0] 和 [X24,#4] 后返回成功

Layer 3 (DEVMPU 重置): DEVMPU init 函数 + code cave trampoline
  在 DEVMPU init 函数中，将启用 ch0 的 STR 指令替换为 BL 跳转到
  code cave 中的 15 指令 trampoline。trampoline 执行:
    1. 保存 X8, X10 到栈
    2. 向 DEVMPU 控制寄存器写入 reset 命令:
       - 写 7 到 0x10351104 (reset ch0, 清除所有 APC)
       - 写 1 到 0x10351104 (reinit ch0)
       - 写 7 到 0x10355104 (reset ch1, 清除所有 APC)
       - 写 1 到 0x10355104 (reinit ch1)
    3. 恢复寄存器并执行原始的 enable ch0 操作
    4. RET 返回，继续正常的 enable ch1 和 boundary 编程
  效果:  preloader 设置的所有 DEVMPU APC 限制被清除
         DEVMPU 正常启用并编程区域边界，但无访问限制
         域7 (VCP/APU) 可自由访问所有 region，包括 PROT_SHARED
         共 16 条指令 (1 BL redirect + 15 trampoline)
```

Layer 1 单独即可阻止 SMMU 被空页表配置，Layer 2 进一步确保 VCP handler 不处理无效的 protpgd 数据，Layer 3 消除 DEVMPU 对域7的访问限制。

> **优势**：VCP 保持完整功能，视频硬件编解码正常工作。仅使用内核 M4U IOMMU（无 SMMU 保护层，GZ 禁用时可接受）。DEVMPU 被完全重置，消除所有 preloader APC 限制。脚本使用模式匹配定位补丁点，不依赖固定偏移，具备跨固件版本通用性。

> **注意**：此补丁与 `--patch-protpgd` 互斥。使用此补丁后 protpgd mblock 不再被访问，无需通过 bl2_ext 分配。

#### 备用方案：VCP 禁用 (`--patch-vcp` + `patch_vendor_boot.py`)

完全禁用 VCP 需要修改两个镜像中的 DTB：

1. **LK DTB**（`detect_lk_gz.py --patch-vcp`）：LK 的 `app_load_vcp()` 读取 DTB，`vcp-support=0` 时不加载 VCP 固件
2. **vendor_boot DTB**（`patch_vendor_boot.py`）：内核 VCP 驱动读取此 DTB，`status="fail"` 时不 probe

两步缺一不可：
- 只改 LK → LK 不加载 VCP 固件，但内核驱动仍 probe VCP 硬件 → 异常
- 只改 vendor_boot → 内核不 probe，但 LK 可能已加载了 VCP 固件到 SRAM → 资源浪费

每个镜像的修改内容：
- 扫描镜像中所有 FDT blob（通过 FDT magic `0xD00DFEED`）
- 定位 `vcp@*` 节点下的 `vcp-support` 和 `status` 属性
- 将 `vcp-support = <0x01>` 修改为 `<0x00>`
- 将 `status = "okay"` 修改为 `"fail"`
- `vcp_iommu_*` 子节点（`vcp-support=2~6`）无 `status` 属性，无需修改（主 VCP 禁用后子节点不被消费）

> **注意**：`"fail"` 与 `"okay"` 同为 5 字节（含 \0），不改变 FDT 结构；`"disabled"` 为 9 字节，无法原地替换。`"fail"` 是设备树规范定义的标准状态值，内核 `of_device_is_available()` 对非 `"okay"` 的值一律返回 false，效果等同 `"disabled"`。

> **注意**：VCP 禁用后，依赖 VCP 的功能（如硬件视频编解码加速、语音处理等）可能不可用或回退到软件实现。仅在 `patch_tee_vcp.py` ATF 补丁不可用时使用。

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
| `VCP 节点` | vcp-support 属性值、status 属性值、路径和文件偏移 |
| `状态` | 已启用 / 已禁用 / 需补丁数量（vcp-support + status） |

**通用：**

| 字段 | 含义 |
|------|------|
| `Boot Tag 钩子` | preloader 传递 GZ 配置的 boot tag 回调函数 |
| `DTB GZ 节点` | 设备树中的 GZ 相关节点（trusty-gz / nebula 等） |

---

## patch_tee_vcp.py

三层补丁 MTK ATF (tee.img)，跳过 SMMU 保护设置并重置 DEVMPU。适用于 GPT 方案禁用 GZ 后 VCP 因空 SMMU 保护页表崩溃以及 DEVMPU 域7违规的平台（如 MT6895）。

### 检测流程

1. **字符串定位** — 搜索 `vcp_smc_vcp_init` 字符串作为近距离参考
2. **锚点匹配** — 在函数代码范围内查找 `MOVZ Wn, #0x38` + `STR Wn, [Xm, #0xC]`（VCP MMIO 寄存器写入），提取保护寄存器基址寄存器号
3. **调用点定位** — 从锚点向前搜索 `MOVZ W3, #1; MOV W2, WZR; BL` 原始模式或 `NOP; NOP; NOP; NOP; B` 已补丁模式
4. **跳过路径定位** — 搜索 `STR WZR, [Xm, #0]; STUR XZR, [Xm, #4]` 零化+返回成功路径
5. **保护函数编程 BL 定位** — 从 VCP handler 的 BL 目标地址进入保护函数，找到第 2 个 BL（SMMU 硬件编程调用）
6. **DEVMPU init 定位** — 搜索 `MOVZ W8, #0x1118; MOVZ W10, #0x5118`（DEVMPU ch0/ch1 enable 寄存器地址），定位 `STR W9, [X8]`（enable ch0 写入），搜索 code cave（60+ 零字节区域）放置 trampoline

### 用法

```bash
# 分析（不修改）
python3 patch_tee_vcp.py tee.img --dry-run

# 应用补丁
python3 patch_tee_vcp.py tee.img -o tee_patched.img

# 原地补丁（自动备份 .bak）
python3 patch_tee_vcp.py tee.img

# 检测已补丁状态
python3 patch_tee_vcp.py tee_patched.img --dry-run
```

### 补丁内容

22 条指令（88 字节），不改变文件大小：

**Layer 1（全局 SMMU 编程旁路）— 1 条指令：**

| 原始指令 | 补丁后 | 说明 |
|---------|--------|------|
| `BL smmu_programming` | `MOVZ W0, #0` | 保护函数内第 2 个 BL → 返回成功，跳过 SMMU 硬件编程 |

**Layer 2（VCP handler 跳过）— 5 条指令：**

| 原始指令 | 补丁后 | 说明 |
|---------|--------|------|
| `LDR X0, [X25, #imm]` | `NOP` | 跳过参数加载 |
| `LDR X1, [X26, #imm]` | `NOP` | |
| `MOVZ W3, #1` | `NOP` | |
| `MOV W2, WZR` | `NOP` | |
| `BL protection_func` | `B skip_path` | 跳转到已有零化+成功路径 |

**Layer 3（DEVMPU 重置）— 16 条指令（1 redirect + 15 trampoline）：**

| 原始 | 补丁后 | 说明 |
|------|--------|------|
| `STR W9, [X8]` | `BL trampoline` | DEVMPU init 中 enable ch0 → 跳转到 code cave |

Trampoline（写入 code cave 的零字节区域）：

| 指令 | 说明 |
|------|------|
| `STP X8, X10, [SP, #-0x10]!` | 保存 ch0/ch1 enable 地址 |
| `MOVZ W8, #0x1104` | ch0 control register (low) |
| `MOVZ W11, #0x5104` | ch1 control register (low) |
| `MOVK W8, #0x1035, LSL#16` | W8 = 0x10351104 |
| `MOVZ W9, #7` | reset 命令 |
| `MOVZ W10, #1` | reinit 命令 |
| `MOVK W11, #0x1035, LSL#16` | W11 = 0x10355104 |
| `STR W9, [X8]` | reset ch0（清除所有 APC） |
| `STR W10, [X8]` | reinit ch0 |
| `STR W9, [X11]` | reset ch1（清除所有 APC） |
| `STR W10, [X11]` | reinit ch1 |
| `LDP X8, X10, [SP], #0x10` | 恢复 ch0/ch1 enable 地址 |
| `MOVZ W9, #1` | 恢复 enable value |
| `STR W9, [X8]` | 执行原始操作：enable ch0 |
| `RET` | 返回（继续 enable ch1 + boundary 编程） |

### 注意事项

- 此补丁与 `--patch-protpgd` 互斥，不要同时使用
- 补丁后 VCP 仅使用内核 M4U IOMMU，不再有 SMMU 保护层（GZ 禁用时可接受）
- Layer 3 重置 DEVMPU 硬件，清除 preloader 设置的所有 APC 限制，域7（VCP/APU）可访问所有 region
- Trampoline 指令序列来自 ATF 原始 `devmpu_reset` 函数，经过交叉验证
- 脚本使用模式匹配，不依赖固定文件偏移，具备跨固件版本通用性
- 无法自动还原（原始 BL 目标地址不可恢复），需保留原始 tee.img

---

## patch_vendor_boot.py

修补 vendor_boot.img 中的内核设备树，禁用 VCP 驱动 probe。Android GKI 设备的内核 DTB 嵌在 vendor_boot.img（VNDRBOOT v3/v4 格式）中，与 LK 中的 DTB 是独立的两份。

### 背景

MTK 平台的 VCP 禁用需要修改两个层面的设备树：

| 层面 | 镜像 | 作用 | 工具 |
|------|------|------|------|
| Bootloader (LK) | lk.img | 控制 LK 是否加载 VCP 固件 | `detect_lk_gz.py --patch-vcp` |
| 内核 | vendor_boot.img | 控制内核 VCP 驱动是否 probe | `patch_vendor_boot.py` |

只改 LK DTB 时，LK 不加载 VCP 固件，但内核的 VCP 驱动仍然看到 `status="okay"` 会 probe，导致 VCP 子系统部分初始化后因缺少固件而异常。

### 用法

```bash
# 分析 vendor_boot.img（显示 DTB 信息和 VCP 节点状态）
python3 patch_vendor_boot.py vendor_boot.img --dry-run

# 修补（自动备份原始文件）
python3 patch_vendor_boot.py vendor_boot.img

# 指定输出文件
python3 patch_vendor_boot.py vendor_boot.img -o vendor_boot_patched.img

# 从备份还原
python3 patch_vendor_boot.py vendor_boot.img --restore
```

### 修补内容

- 扫描 vendor_boot.img 中所有 FDT blob（通过 FDT magic `0xD00DFEED`）
- 定位主 VCP 节点（`vcp-support=1`），将其改为 `vcp-support=0`
- 将 `status="okay"` 改为 `"fail"`（等长替换，不改变 FDT 结构）
- `vcp_iommu_*` 子节点（`vcp-support=2~6`）无需修改，主节点禁用后子节点不被消费

### 特性

- 自动检测 VNDRBOOT 格式版本（v3/v4）
- 支持多 DTB（vendor_boot v4 可嵌多个 DTB）
- 幂等：对已禁用的镜像重复运行会提示"无需修补"
- 自动备份原始文件（`*_backup.*`）
- 支持 `--restore` 还原

### 完整 VCP 禁用流程

```bash
# 1. 禁用 LK DTB 中的 VCP
python3 detect_lk_gz.py lk.img --patch-vcp
# 输出: lk_patched.img

# 2. 禁用 vendor_boot DTB 中的 VCP
python3 patch_vendor_boot.py vendor_boot.img
# 输出: vendor_boot_patched.img

# 3. 刷入两个修补后的镜像
fastboot flash lk lk_patched.img
fastboot flash vendor_boot vendor_boot_patched.img
```

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

**v6 架构（MT6895 等，preloader 初始化 gz，LK 含 VCP，ATF 含 SMMU 保护 + DEVMPU）：**

```
BROM → preloader (签名验证) → ATF → LK → kernel
              │                  │       │       │
              ├─ gz_init():      │       │       ├─ VCP 驱动 probe:
              │  读取 gz 分区     │       │       │   读取 vendor_boot DTB
              │  配置 NoGZ 标志   │       │       │   status="okay" → probe VCP
              ├─ DEVMPU APC:     │       │       │   status="fail" → 跳过
              │  preloader 编程   │       │       │   patch_vendor_boot.py: 改 DTB
              │  域7限制          │       │       └─ DTB: trusty-gz / nebula 节点
              ├─ 分区加载循环     │       │
              └─ ATF 跳转        │       ├─ app_load_vcp(): 读取 LK DTB
                                 │       │   vcp-support=1 → 加载 VCP 固件
                                 │       │   vcp-support=0 → 跳过
                                 │       │   detect_lk_gz.py --patch-vcp: 改 LK DTB
                                 │       └─ DTB: vcp 节点 → 仅影响 LK 阶段
                                 │
                                 ├─ SMMU 保护函数 (被 5 个 SMC handler 调用):
                                 │   GZ 跳过时 protpgd 为空 → DMA PA=0x0 → fault
                                 │   patch_tee_vcp.py Layer 1: 编程 BL → MOVZ W0,#0
                                 ├─ vcp_smc_vcp_init:
                                 │   patch_tee_vcp.py Layer 2: 跳过保护调用 → 零化+成功
                                 ├─ DEVMPU init:
                                 │   只编程区域边界，不碰 APC (preloader 限制保留)
                                 │   GZ 跳过时域7被 DEVMPU 拒绝 → 12K+ 违规 → HWT
                                 │   patch_tee_vcp.py Layer 3: 注入 devmpu_reset trampoline
                                 └─ VCP 仅使用内核 M4U IOMMU (正常工作)
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
- **GPT + ATF VCP 修复**（MT6895 等）：GPT 方案触发 NoGZ 跳过 GZ，但 VCP 因 SMMU 保护页表为空和 DEVMPU APC 限制导致崩溃，需配合 `patch_tee_vcp.py` 补丁 ATF（推荐，保留 VCP 功能）或 `--patch-vcp`（禁用 VCP）
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

部分平台的 preloader 会无条件将 `halt_on_assert` 置为 1。此时 `assert_fatal` 被触发后调用 WDT reset，设备直接重启进入 BROM 模式，而不是继续执行设置 NoGZ 的代码路径。

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

### LK / bl2_ext 方案

**签名验证失败，无法启动**

LK 方案修改了 LK 代码/数据，签名校验不通过。需要使用不校验签名的 preloader 或 [pwnage24mtk](https://github.com/jsbsbxjxh66/pwnage24mtk) 绕过签名验证。ATF 补丁（`patch_tee_vcp.py`）同理，tee.img 也有签名校验。

**补丁后仍未释放 GZ 内存**

可能原因：
1. **方案 A**：`--patch-validate` 跳过了 `gz_init_main`，`gz_mblock_free_all` 未被调用。如果 preloader 已通过 `gz-tee-static-shm` 预留了内存，这部分内存不会被释放 → 使用 `--patch-init-fail`（方案 B）或 A+B
2. 内核层面的 trusty-gz / nebula 驱动仍在尝试初始化 GZ（通常会优雅失败，不影响启动）

### VCP 崩溃（GPT 禁用 GZ 后约 60 秒看门狗重启）

适用平台：MT6895 等使用 GPT 方案禁用 GZ 且 ATF 中有 VCP SMMU 保护逻辑的平台。

#### 症状

设备正常启动进入系统，但约 60 秒后突然重启。反复循环。内核日志（如能抓取）中可能看到：

```
mtk_iommu: iova 0x... pa 0x0 ...
mtk_iommu: translation fault
vcp: watchdog timeout
```

关键特征：
- PA 地址为 **0x0**（空页表默认映射）
- 故障来源为 VCP 相关的 IOMMU 端口
- 重启间隔固定约 60 秒（VCP 看门狗超时时间）
- 不禁用 GZ 时不会出现此问题

#### 根因分析

```
正常流程 (GZ 启用):
  bl2_ext 分配 protpgd mblock (2MB) → 全零
  ATF 映射 protpgd 到 VA 空间
  GZ 启动后填充 protpgd 页表项 (IOVA → PA 映射)     ← 关键步骤
  内核启动 → iommu_secure.ko → SMC 调用保护函数 (site1-4)
  ATF 用 protpgd 中的映射配置 SMMU (有效页表项)
  VCP 驱动 → SMC vcp_smc_vcp_init (site5)
  ATF 配置 VCP SMMU 保护寄存器
  VCP DMA → SMMU 查 protpgd → 正确 PA → 正常工作 ✓

异常流程 (GZ 禁用, 未打 ATF 补丁):
  bl2_ext 分配 protpgd mblock (2MB) → 全零
  ATF 映射 protpgd 到 VA 空间
  GZ 未启动 → protpgd 页表项全为 0                   ← 根因 1
  DEVMPU APC 由 preloader 编程，限制域7              ← 根因 2
  ATF DEVMPU init: 只编程区域边界，不碰 APC (preloader 限制保留)
  内核启动 (~1.1s) → iommu_secure.ko → SMC 调用保护函数 (site1-4)
  ATF 用空 protpgd 编程 SMMU → 所有映射指向 PA=0x0   ← 早于 VCP 启动
  VCP 启动 (~7.7s) → SMC vcp_smc_vcp_init (site5)
  VCP DMA → SMMU 查 protpgd → PA=0x0 → translation fault
  VCP 访问 PROT_SHARED → DEVMPU 拒绝 → 12K+ 违规 → IRQ 风暴
  ~33s HWT 崩溃 或 ~60s VCP 看门狗超时 → WDT reset ✗

修复后流程 (GZ 禁用, 已打三层 ATF 补丁):
  Layer 1: 保护函数内部 SMMU 编程 BL → MOVZ W0,#0
    → 所有 5 个调用点 (iommu_secure/cmdq/display/VCP 等) 都不编程 SMMU 硬件
  Layer 2: vcp_smc_vcp_init 跳过保护调用
    → 跳到 skip_path 零化保护寄存器并返回成功
  Layer 3: DEVMPU init 注入 devmpu_reset trampoline
    → STR W9,[X8] 替换为 BL trampoline (code cave)
    → trampoline 写 7→1 到 DEVMPU 控制寄存器 (0x10351104/0x10355104)
    → 清除 preloader 设置的所有 DEVMPU APC 限制
    → 恢复寄存器后执行原始 enable 操作
    → 域7 (VCP/APU) 不再被限制 → 无 DEVMPU 违规
  VCP 仅使用内核 M4U IOMMU → 正常工作 ✓
  DEVMPU 不再阻止域7访问 → 无违规洪泛 ✓
```

#### 解决方案

| 方案 | 工具 | 效果 | 适用场景 |
|------|------|------|---------|
| **ATF 补丁**（推荐） | `patch_tee_vcp.py tee.img` | 跳过 SMMU 保护 + DEVMPU 重置，VCP 正常工作 | 有 tee.img 且能绕过签名 |
| **VCP 禁用**（备用） | `detect_lk_gz.py --patch-vcp` + `patch_vendor_boot.py` | 完全禁用 VCP，无 IOMMU 调用 | ATF 补丁不可用时 |

#### 诊断步骤

1. **确认问题类型**：
   - 约 60 秒固定间隔重启 → 大概率是 VCP 看门狗（SMMU 空页表，Layer 1+2 解决）
   - 约 33-40 秒崩溃 → 大概率是 DEVMPU 违规洪泛（域7无权限，Layer 3 解决）
   - 随机时间重启 → 可能是其他问题
2. **抓日志**：如果能连接 adb，开机后立即运行 `adb logcat | grep -iE "iommu|vcp|translation|fault|watchdog|emi_mpu|devmpu|violation"` 捕获关键日志
3. **确认 GZ 已禁用**：`adb shell cat /proc/device-tree/chosen/atag,gz` 或搜索 dmesg 中的 `NoGZ` / `gz is disabled` 字样
4. **检查 tee.img**：用 `patch_tee_vcp.py tee.img --dry-run` 确认能找到补丁点（应显示 22 条指令替换）

#### 常见问题

**`patch_tee_vcp.py` 报 "pattern not found"**

脚本未能在 tee.img 中找到 `vcp_smc_vcp_init` 的特征模式。可能原因：
- tee.img 不是 ATF 镜像（如提取了错误的分区）
- 该平台 ATF 中没有 VCP SMMU 保护逻辑（可能不需要此补丁）
- 该平台 ATF 使用了不同的寄存器编号或指令序列（需要手动逆向分析）

验证方法：用 `strings tee.img | grep vcp_smc` 检查是否包含函数名字符串

**补丁后仍然 60 秒重启**

1. 确认使用的是最新版 `patch_tee_vcp.py`（三层补丁，22 条指令）。旧版只补丁 VCP handler（Layer 2），不够——iommu_secure.ko 在 VCP 启动前就通过其他调用点编程了 SMMU
2. 确认从原始未补丁的 tee.img 打补丁（不要在已部分补丁的文件上操作）
3. 确认 tee.img 已正确刷入（对比文件大小和 md5）
4. 确认签名验证已被绕过（否则补丁后的 tee.img 会被拒绝加载，设备可能回退到 ROM 中的原始 ATF）
5. 确认 GPT 补丁仍然有效（OTA 可能还原了 GPT）

**补丁后视频编解码异常**

正常情况下不应出现。ATF 补丁只跳过 SMMU Stage 2 保护层，内核 M4U IOMMU（Stage 1）仍正常工作。如果出现异常：
- 确认内核 IOMMU 驱动正常加载（`dmesg | grep mtk_iommu`）
- 确认 VCP 固件已被 LK 加载（`dmesg | grep -i vcp`）
- 如果是特定视频格式/分辨率失败，可能与 SMMU 保护无关

**补丁后约 33-40 秒崩溃（DEVMPU 违规洪泛）**

如果使用旧版 `patch_tee_vcp.py`（仅 Layer 1+2，无 Layer 3），设备可能在启动约 33-40 秒后因 DEVMPU 违规洪泛而崩溃。内核日志或 expdb.log 中可能看到：

```
[emi_mpu] Clear DEVMPU violation. emi: 0x0, devmpu: 0x1
emi_mpu: violation - domain 7, region 10, master 0x2C06
```

这是因为 DEVMPU 的 APC（Access Permission Control）由 preloader 编程，限制域7（VCP/APU）访问 PROT_SHARED 等 region。正常情况下 VCP 通过 GZ 代理访问（GZ 有权限），禁用 GZ 后 VCP 直接访问被 DEVMPU 拒绝，产生 12000+ 次违规中断 → IRQ 风暴 → HWT 崩溃。

解决方法：更新到最新版 `patch_tee_vcp.py`（三层补丁，22 条指令），Layer 3 在 DEVMPU init 中注入 devmpu_reset trampoline，在 DEVMPU 启用前写入 reset 命令（7→1）到控制寄存器，清除 preloader 设置的所有 APC 限制。

**误用 `--patch-protpgd` 和 `patch_tee_vcp.py` 同时打补丁**

两者互斥但同时使用不会导致崩溃。ATF 补丁跳过了 SMMU 保护设置，protpgd 是否被分配不影响结果（不会被访问）。只是 `--patch-protpgd` 变成了无用修改，浪费了 2MB 内存用于分配一个永远不会被使用的 mblock

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
- **备份 GPT**：当前工具仅修改 PGPT。部分 preloader 在主 GPT 校验失败时会回退到备份 GPT（SGPT），仅修改 PGPT 可能因 SGPT 中 gz 分区仍有效而导致方案失效
- **LK 签名**：LK 方案修改了代码/数据，需要不校验签名的 preloader 或 [pwnage24mtk](https://github.com/jsbsbxjxh66/pwnage24mtk) 绕过签名
- **处理器代际差异**：
  - 天玑 v5 及以下（如 MT6833/MT6893）：GPT LBA 方案通常直接可用，LK 无 GZ 代码不需要 LK 方案
  - 天玑 v6（如 MT6895）：GPT 方案跳过 GZ 后需配合 `patch_tee_vcp.py` 三层补丁 ATF（推荐）或 `--patch-vcp` + `patch_vendor_boot.py` 禁用 VCP，否则 VCP SMMU 保护页表为空导致 IOMMU translation fault → 60 秒看门狗重启，以及 DEVMPU 域7违规洪泛 → 约 33 秒 HWT 崩溃
  - 天玑 v6+（如 MT6991）：GPT 方案不可用（修改 GPT 后能进 fastboot 但无法正常启动，bl2_ext 中 GZ 初始化的部分执行导致不可逆硬件配置变更），需使用 bl2_ext 方案（`--patch-validate` / `--patch-init-fail`）
  - 或使用 [pwnage24mtk](https://github.com/jsbsbxjxh66/pwnage24mtk) 高级用法直接干掉 GenieZone
- **功能影响**：禁用 GenieZone 后，依赖 GZ 虚拟化服务的功能（如部分 DRM、安全容器等）可能不可用；禁用 VCP 后，硬件视频编解码加速等功能可能不可用或回退到软件实现

## License

MIT — 详见 [LICENSE](LICENSE) 文件。
