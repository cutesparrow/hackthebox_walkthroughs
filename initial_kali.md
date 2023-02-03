初始化kali系统

1. 键位重绑定

   input-remapper

2. tmux配置

   ```bash
   bind c new-window -c "#{pane_current_path}"
   bind '"' split-window -c "#{pane_current_path}"
   bind % split-window -h -c "#{pane_current_path}"
   setw -g mode-keys vi
   ```

3. 安装常用工具：

   1. shellerator