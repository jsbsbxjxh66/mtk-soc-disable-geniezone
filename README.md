# mtk-soc-disable-geniezone

通过修改 GPT 分区表禁用联发科 GenieZone (GZ) 虚拟化管理程序，不破坏 preloader 代码签名。

适用于使用 GenieZone 的联发科平台（MT6893/Dimensity 1200 已验证，理论兼容其他 MTK 平台）。

> **⚠️ 免责声明**
>
> 本工具仅供安全研究和个人设备调试使用。使用本工具修改设备分区表存在**变砖风险**，包括但不限于：设备无法启动、需要通过底层工具救砖、丢失保修资格等。作者不对因使用本工具造成的任何损失承担责任。**使用前请务必备份原始分区表，风险自负。**

## 原理简述

联发科的 preloader 在启动时加载 GenieZone 到 EL2。直接删除 gz 分区会导致 preloader 内部的分区查找函数 `func_36d68` 返回错误，触发 "Second Bootloader Load Failed" 致命错误，设备无法启动。

本工具利用 preloader 中 **分区存在性检查** 与 **数据读取** 使用不同函数的特性：保留 gz1/gz2 分区条目在 GPT 中（通过存在性检查），但将 LBA 地址指向存储设备容量之外（使数据读取失败），从而触发 preloader 内部的 `NoGZ` 标志位，安全跳过 GenieZone 的加载。

## 使用方法

### 前置条件

- Python 3.6+（无第三方依赖）
- 已解锁 bootloader 的联发科设备
- 设备的 GPT 分区表文件（`pgpt.bin`）

### 提取分区表

```bash
# 使用你能够连上设备的工具提取pgpt分区文件pgpt.bin
- mtkclent
- geekflashtool
- unlocktool

# 或通过 fastboot（部分设备支持）
# 具体分区路径视设备而定
```

### 修改分区表

```bash
# 分析分区表（不修改）
python3 patch_gz_gpt.py pgpt.bin --dry-run

# 执行修改，生成 pgpt_patched.bin
python3 patch_gz_gpt.py pgpt.bin

# 指定输出文件名
python3 patch_gz_gpt.py pgpt.bin -o my_output.bin
```

### 刷写

```bash
# 使用你能够连上设备的工具刷写修补后的pgpt_patched.bin到pgpt分区
- mtkclent
- geekflashtool
- unlocktool

# 或者通过 fastboot（部分设备支持
# 刷写修改后的分区表
fastboot flash pgpt pgpt_patched.bin

# 如果出问题，用备份还原
fastboot flash pgpt pgpt_backup.bin
```

### 还原

```bash
# 使用脚本还原
python3 patch_gz_gpt.py pgpt.bin --restore

# 或直接工具恢复
- mtkclent
- geekflashtool
- unlocktool

# 或直接用 fastboot 刷回备份
fastboot flash pgpt pgpt_backup.bin
```

## 技术细节

以下基于 MT6893 (Dimensity 1200) 平台的 preloader 逆向分析。

### 启动流程中的 GenieZone

```
BROM → preloader (签名验证) → ATF → LK → kernel
                  │
                  ├─ gz_init(): 读取 gz 分区配置 → 设置 NoGZ 标志
                  ├─ 分区加载循环: 加载 tee/gz/scp 等分区镜像
                  └─ ATF 跳转: 根据 NoGZ 决定是否将 EL2 移交给 GZ
```

### Catch-22：为什么不能直接删除 gz 分区

Preloader 中有一个核心的分区名称映射函数 `func_36d68`，它将逻辑名 `"gz"` 映射到实际分区名 `"gz1"`，并通过 `get_part_info()` 检查该分区是否存在于 GPT 中。

关键问题在于，**两个不同的代码路径**都调用了同一个函数：

| 调用者 | 目的 | 如果 gz1 不在 GPT 中 |
|--------|------|---------------------|
| `gz_init()` → `read_part()` | 读取 gz 配置数据 | `func_36d68` 返回错误 → `read_part` 返回 -1 → **设置 NoGZ** ✓ |
| `main()` 分区加载循环 | 加载 gz 镜像 | `func_36d68` 返回非零 → **进入致命错误处理** ✗ |

删除 gz1 分区后，`gz_init` 正确设置了 NoGZ，但随后主循环中同一个 `func_36d68` 也会失败，触发 `"Second Bootloader Load Failed"` 致命错误，设备无法启动。

### 为什么不能直接擦除 gz 分区数据

另一个直觉方案是保留分区条目、只擦除（清零）分区数据。这同样不可行，原因在于 `func_40974`（底层存储 I/O）不关心读到的**内容**，只要 I/O 操作本身完成就返回 `0x200`（成功）：

```
擦除 gz 分区数据后:
  gz_init()
    → read_part("gz") → func_40974 读取 0x200 字节
    → 分区地址有效，I/O 成功完成，返回 0x200
    → 0x200 == 0x200 → gz_init 认为读取成功
    → 继续解析全零数据...
```

全零数据也是"成功读到的数据"，不会触发 NoGZ。之后 `gz_init` 会尝试解析这些全零内容，行为不可预测：

- 若有 magic number 校验：校验失败后的处理方式未知（可能触发致命错误）
- 若无校验：全零被当作有效配置，后续加载并跳转到地址 0x0 → 死机
- 最好的情况也是不可预测的崩溃

**关键区别**：擦除数据让错误发生在**数据解析层**（行为不可控），而无效 LBA 让错误发生在**存储 I/O 层**（`func_40974` 返回 -1，行为确定）。

### 解决方案：无效 LBA 欺骗

核心发现：`get_part_info()` 只做**名称匹配**，不验证 LBA 地址有效性。而实际的存储 I/O 由另一个函数 `func_40974` 执行，它在读取失败时返回 -1。

```
get_part_info("gz1")       ← 仅检查 GPT 中是否存在该名称的条目
                              不关心 LBA 指向哪里

func_40974(addr, buf, sz)  ← 实际从存储设备读取数据
                              如果 LBA 超出设备容量 → 返回 -1
```

将 gz1 分区的 LBA 改为超出设备容量的值后：

```
阶段 1: gz_init()
  read_part("gz")
    func_36d68("gz") → "gz1" → get_part_info("gz1") → 找到 ✓
    func_36e9c → func_40974 → 读取无效 LBA → 失败 → return -1
  read_part 返回 -1
  -1 ≠ 0x200 → 设置 NoGZ = 0x4E6F475A ("NoGZ")  ✓

阶段 2: 主分区加载循环
  func_36d68("gz") → "gz1" → get_part_info("gz1") → 找到 → return 0  ✓
  bldr_load_gz_part()
    is_el2_enabled() → 0 (NoGZ 已设置)
    print "EL2_BOOTING_DISABLED, skip load gz"
    return 0  ✓
  继续启动...

阶段 3: ATF 跳转
  is_el2_enabled() → 0
  GZ entry = 0 → ATF 不启动 GenieZone
  正常进入内核  ✓
```

### 关键地址参考 (MT6893)

| 符号 | 文件偏移 | 内存地址 | 说明 |
|------|---------|---------|------|
| `is_el2_booting_enabled` | 0x269A8 | 0x2278B8 | 检查 NoGZ 标志 |
| `set_el2_flag` | 0x26520 | 0x227430 | 写入 NoGZ 标志 |
| `gz_init` | 0x269C4 | 0x2278D4 | GZ 初始化，读取配置 |
| `bldr_load_gz_part` | 0x273B0 | 0x2282C0 | 加载 GZ 镜像 |
| `read_part` | 0x36F44 | 0x237E54 | 通用分区读取函数 |
| `func_36d68` | 0x36D68 | 0x237C78 | 分区名称映射 (gz→gz1) |
| `get_part_info` | 0x36D34 | 0x237C44 | GPT 分区查找 (仅名称匹配) |
| `func_36e9c` | 0x36E9C | 0x237DAC | 存储读取 (含范围检查) |
| `func_40974` | 0x40974 | 0x241884 | 底层存储 I/O |
| NoGZ SRAM 地址 | — | 0x002E91E8 | NoGZ 标志位存储位置 |
| NoGZ 常量 | — | 0x4E6F475A | ASCII "NoGZ" |
| 硬编码分区表 | 0x6A900 | — | gz→gz1 映射表 (签名区域内) |
| 签名区域 | 0x0–0x745CC | — | 不可修改 |

### 为什么保留 2 个扇区

修改后的分区大小设为 2 扇区，而非 0 或 1。原因：

`func_36e9c` 在调用底层 I/O 前会做范围检查：`sector_count × sector_size ≥ offset + read_size`。gz_init 请求读取 0x200 (512) 字节。若分区扇区数为 0，范围检查本身就会失败，但 `func_36e9c` 的错误处理会调用 `func_25f18`（错误日志），我们无法确定其行为。2 扇区 × 4096 字节 = 8192 ≥ 512，安全通过范围检查，让错误发生在更可控的底层 I/O 阶段。

### 安全启动配置

该 preloader 的 GFH 头显示：

- **sig_type**: 0x05 (RSA 签名)
- **证书**: `Oplus_cert`
- **签名覆盖范围**: 文件 0x0 – 0x745CC (整个代码和数据区)
- **签名数据**: 0x745CC – 0x74C38 (1644 字节)

签名区域包含硬编码分区映射表 (文件 0x6A900)，因此无法通过修改 preloader 来更改映射关系。本方案完全不涉及 preloader 的修改。

## 风险与注意事项

- **变砖风险**：虽然概率极低，但存储控制器对越界读取的处理方式因厂商而异。eMMC/UFS 规范要求返回错误，但极个别固件可能挂起而非返回错误，导致设备卡在 preloader 阶段
- **OTA 更新**：系统 OTA 可能还原 GPT 分区表到原始状态，需要重新修改
- **可恢复性**：修改仅涉及 GPT 分区表，可随时通过 fastboot 或底层工具刷回备份恢复
- **备份 GPT**：本工具仅修改主 GPT (primary GPT)。设备末尾的备份 GPT 可能需要同步修改，大多数联发科设备优先使用主 GPT
- **功能影响**：禁用 GenieZone 后，依赖 GZ 虚拟化服务的功能（如部分 DRM、安全容器等）可能不可用

## 兼容性

| 项目 | 说明 |
|------|------|
| 已验证平台 | MT6893 (Dimensity 1200) |
| 理论兼容 | 其他使用 GenieZone 的联发科平台（MT6885/6889/6893/6983/6985 等） |
| 扇区大小 | 自动检测 512 字节 (eMMC) 和 4096 字节 (UFS) |
| 分区名称 | 支持 gz/gz1/gz2/gz_a/gz_b/gz1_a/gz1_b/gz2_a/gz2_b |

## 致谢

本项目基于对联发科 preloader 二进制文件的逆向工程分析。感谢所有为 MTK 平台安全研究做出贡献的社区成员。

## License

MIT — 详见 [LICENSE](LICENSE) 文件。
