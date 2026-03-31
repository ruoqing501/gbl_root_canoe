# Bootloader Slot Flasher

这是一个 KernelSU 模块，作用是：

- 自动识别当前活动槽位
- 将 images 目录中的所有 .img 镜像刷写到另一槽位的同名分区
- 刷写前校验模块内关键文件和所有镜像的 SHA-256
- 通过 WebUI 触发刷写
- 在页面内执行二次确认
- 在页面内展示刷写日志

## 目录约定

- 当前实现使用固定镜像列表（写死）：
  - abl.img
  - xbl.img
  - xbl_config.img
  - xbl_ac_config.img
  - xbl_ramdump.img
- 当前实现固定使用分区目录：
  - /dev/block/by-name/<partition>_<slot>

## 使用方式

1. 将当前目录打包成模块 zip
2. 在 KernelSU Manager 中安装这个 zip
3. 打开模块 WebUI
4. 查看当前槽位和目标槽位
5. 点击刷写按钮，并完成两次确认
6. 在日志面板里观察执行结果

## 哈希校验

- `hashes.sha256` 保存所有模块文件的 SHA-256 校验和（标准 sha256sum 格式）
- 模块安装时通过 `sha256sum -c` 校验，失败则终止安装
- 刷写前再次校验全部文件
- 更新模块文件后需同步重新生成 `hashes.sha256`

## 注意事项

- 这是高风险操作，错误镜像可能导致目标槽位无法启动
- 建议仅在明确知道镜像来源、分区对应关系和恢复手段的前提下使用
- 当前模块只负责刷写另一槽位，不负责切换活动槽位