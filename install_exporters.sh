#!/bin/bash

# 确保脚本在出错时退出，并且管道中的命令失败也会导致退出
set -e
set -o pipefail

# --- Node Exporter (Systemd) 配置 ---
NODE_EXPORTER_VERSION="1.9.1" # 可以根据需要更新版本
NODE_EXPORTER_BIN="/usr/local/bin/node_exporter"
NODE_EXPORTER_SERVICE_FILE="/etc/systemd/system/node_exporter.service"
NODE_EXPORTER_TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector" # Textfile collector 目录

# --- 共享/Docker 配置 ---
WORK_DIR="/root/monitoring" # 指定工作目录 (用于认证和 Docker 文件)
PASSWORD_FILE=".credentials" # 存储明文密码! (相对于 WORK_DIR)
WEB_CONFIG_FILE="web-config.yml" # Node Exporter 认证配置 (相对于 WORK_DIR)
COMPOSE_FILE="docker-compose.yml" # Docker Compose 文件 (相对于 WORK_DIR)
BLACKBOX_CONFIG_DIR="blackbox_config" # Blackbox 配置目录 (相对于 WORK_DIR)
BLACKBOX_CONFIG_FILE_REL="$BLACKBOX_CONFIG_DIR/blackbox.yml" # 相对路径
BLACKBOX_CONFIG_FILE_ABS="$WORK_DIR/$BLACKBOX_CONFIG_FILE_REL" # 绝对路径
DOCKER_INSTALL_SCRIPT="get-docker.sh" # Docker 安装脚本临时文件名

# --- Smokeping Prober 配置 ---
SMOKEPING_PROBER_CONFIG_DIR="smokeping_prober_config" # Smokeping Prober 配置目录 (相对于 WORK_DIR)
SMOKEPING_PROBER_CONFIG_FILE_REL="$SMOKEPING_PROBER_CONFIG_DIR/config.yml" # 相对路径
SMOKEPING_PROBER_CONFIG_FILE_ABS="$WORK_DIR/$SMOKEPING_PROBER_CONFIG_FILE_REL" # 绝对路径

# Smokeping Prober 默认配置内容
DEFAULT_SMOKEPING_PROBER_CONFIG=$(cat <<'EOF'
targets:
  - hosts:
      - 157.148.58.29
      - 120.233.18.250
      - 183.47.126.35
      - 240e:97c:2f:3000::44
      - 2409:8c54:871:1001::12
      - 2408:8756:f50:1001::c
    interval: 1s      # 探测间隔
    network: ip       # ip / ip4 / ip6
    protocol: icmp    # 探测协议
    size: 56          # 包大小
EOF
)

# 日志文件
LOG_FILE="/var/log/exporter_install.log" # 合并后的日志文件

# Blackbox 默认配置内容 (如果文件不存在则创建)
DEFAULT_BLACKBOX_CONFIG=$(cat <<'EOF'
modules:
  http_2xx:
    prober: http
    http:
      preferred_ip_protocol: "ip4"
  http_post_2xx:
    prober: http
    http:
      method: POST
  tcp_connect:
    prober: tcp
  pop3s_banner:
    prober: tcp
    tcp:
      query_response:
      - expect: "^+OK"
      tls: true
      tls_config:
        insecure_skip_verify: false
  grpc:
    prober: grpc
    grpc:
      tls: true
      preferred_ip_protocol: "ip4"
  grpc_plain:
    prober: grpc
    grpc:
      tls: false
      service: "service1"
  ssh_banner:
    prober: tcp
    tcp:
      query_response:
      - expect: "^SSH-2.0-"
      - send: "SSH-2.0-blackbox-ssh-check"
  ssh_banner_extract:
    prober: tcp
    timeout: 5s
    tcp:
      query_response:
      - expect: "^SSH-2.0-([^ -]+)(?: (.*))?$"
        labels:
        - name: ssh_version
          value: "${1}"
        - name: ssh_comments
          value: "${2}"
  irc_banner:
    prober: tcp
    tcp:
      query_response:
      - send: "NICK prober"
      - send: "USER prober prober prober :prober"
      - expect: "PING :([^ ]+)"
        send: "PONG ${1}"
      - expect: "^:[^ ]+ 001"
  icmp:
    prober: icmp
  icmp_ttl5:
    prober: icmp
    timeout: 5s
    icmp:
      ttl: 5
EOF
)

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 全局变量 ---
OS_DISTRIBUTION="unknown" # 存储检测到的操作系统类型 (debian, redhat, unknown)
declare -a COMPOSE_CMD_ARRAY # 存储 Docker Compose 命令 (处理 V1/V2)
# --- END 全局变量 ---

# --- 函数定义 ---

# 日志记录函数
log_info() {
  echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${GREEN}[信息]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
  echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${YELLOW}[警告]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
  echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}[错误]${NC} $1" | tee -a "$LOG_FILE"
}

log_step() { echo -e "\n${BLUE}>>> 步骤: $1${NC}"; }

# 检查命令是否存在
check_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log_error "缺少依赖命令：'$1'。请先安装它。"
    if [[ "$1" == "docker" ]]; then
        log_error "此脚本需要 Docker 来运行 Blackbox Exporter 或生成 Node Exporter 的密码哈希。请安装 Docker Engine。"
        log_error "安装指南: https://docs.docker.com/engine/install/"
    fi
    exit 1
  fi
}

# 获取操作系统发行版信息 (用于 user/group 确定)
get_os_info() {
  if command -v apt-get >/dev/null 2>&1; then
    OS_DISTRIBUTION="debian"
    log_info "检测到操作系统为 Debian/Ubuntu 系列。"
  elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
    OS_DISTRIBUTION="redhat"
    log_info "检测到操作系统为 Red Hat/CentOS/Fedora 系列。"
  else
    OS_DISTRIBUTION="unknown"
    log_warn "无法准确检测到操作系统发行版。"
  fi
}

# 检查并安装 Docker
check_install_docker() {
    log_info "检查 Docker 是否已安装..."
    if command -v docker >/dev/null 2>&1; then
        log_info "Docker 已安装。"
        # 检查 Docker 服务是否运行
        if ! docker info > /dev/null 2>&1; then
             log_warn "检测到 Docker 命令，但无法连接到 Docker 守护进程。请确保 Docker 服务正在运行 (例如: systemctl start docker)。"
             # 不退出，但后续 Docker 操作可能会失败
        else
             log_info "Docker 服务正在运行。"
        fi
        return 0
    fi

    log_warn "未检测到 Docker。将尝试使用官方脚本自动安装。"
    log_info "检查 curl 是否可用..."
    check_command curl # 如果 curl 不存在会退出

    log_info "正在从 get.docker.com 下载 Docker 安装脚本..."
    if ! curl -fsSL https://get.docker.com -o "$DOCKER_INSTALL_SCRIPT"; then
        log_error "下载 Docker 安装脚本失败。"
        rm -f "$DOCKER_INSTALL_SCRIPT" # 清理可能不完整的文件
        exit 1
    fi

    log_info "正在执行 Docker 安装脚本 (这可能需要一些时间)..."
    # 使用 sh 执行脚本，因为脚本本身会处理权限问题
    if ! sh "$DOCKER_INSTALL_SCRIPT"; then
        log_error "Docker 安装脚本执行失败。"
        rm -f "$DOCKER_INSTALL_SCRIPT"
        exit 1
    fi

    log_info "Docker 安装脚本执行完毕。正在清理..."
    rm -f "$DOCKER_INSTALL_SCRIPT"

    # 再次检查 Docker 是否安装成功
    log_info "再次检查 Docker 是否安装成功..."
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker 安装后仍然无法检测到 'docker' 命令。请检查安装日志或手动安装。"
        exit 1
    fi
    log_info "Docker 安装成功！"

    # 尝试启动 Docker 服务
    log_info "尝试启动 Docker 服务..."
    if systemctl start docker; then
        log_info "Docker 服务已启动。"
    else
        log_warn "尝试启动 Docker 服务失败，可能需要手动启动 (systemctl start docker)。"
    fi

    log_warn "Docker 已安装。如果当前用户不是 root，可能需要重新登录或将用户添加到 'docker' 组才能免 sudo 使用 Docker。"
}

# 检测 Docker Compose 命令 (V1 或 V2) 并设置 COMPOSE_CMD_ARRAY
detect_compose_command() {
  log_info "正在检测 Docker Compose 命令..."
  # 优先检测 V2
  if docker compose version >/dev/null 2>&1; then
    log_info "检测到 'docker compose' (V2)。"
    COMPOSE_CMD_ARRAY=("docker" "compose")
  elif command -v docker-compose >/dev/null 2>&1; then
    log_info "检测到 'docker-compose' (V1)。"
    COMPOSE_CMD_ARRAY=("docker-compose")
  else
    log_warn "未能检测到可用的 Docker Compose 命令 ('docker compose' 或 'docker-compose')。"
    log_warn "Docker Compose V2 通常随 Docker Engine 一起安装。如果需要 V1，请手动安装。"
    # 如果需要安装 Blackbox，这里应该报错退出
    # 如果只是生成哈希，可以不退出，但 generate_hash 会失败
    # 暂时不退出，让后续逻辑处理
    COMPOSE_CMD_ARRAY=() # 标记为未找到
    log_warn "如果计划安装 Blackbox Exporter，请确保 Docker Compose V1 或 V2 已安装。"
    # return 1 # 返回错误码，让调用者决定是否退出
  fi
  if [[ ${#COMPOSE_CMD_ARRAY[@]} -gt 0 ]]; then
      log_info "将使用命令: ${COMPOSE_CMD_ARRAY[*]}"
  fi
  return 0
}

# 提示输入密码 (带确认)
prompt_password() {
  local password_var_name="$1" # Pass the name of the variable to store the password
  local password=""
  local password_confirm=""
  while true; do
    read -sp "请输入用于 Node Exporter Basic Auth 的密码: " password
    echo
    read -sp "请再次输入密码确认: " password_confirm
    echo
    if [[ "$password" == "$password_confirm" ]]; then
      if [[ -z "$password" ]]; then
        log_warn "密码不能为空，请重新输入。"
      else
        # Assign the password to the variable name passed as argument
        printf -v "$password_var_name" '%s' "$password"
        break
      fi
    else
      log_error "两次输入的密码不匹配，请重新输入。"
    fi
  done
}

# 生成 Bcrypt 哈希 (需要 Docker)
# 参数: $1 = 用户名, $2 = 密码, $3 = 存储哈希的变量名
generate_hash() {
  local user="$1"
  local pass="$2"
  local hash_var_name="$3"
  local bcrypt_hash=""

  log_info "正在使用 Docker (httpd:2.4 镜像) 生成密码哈希..."
  # 确保 Docker 守护进程正在运行
  if ! docker info > /dev/null 2>&1; then
      log_error "无法连接到 Docker 守护进程。请确保 Docker 服务正在运行 (systemctl start docker)。"
      exit 1
  fi

  # 使用 httpd 镜像中的 htpasswd 生成 bcrypt 哈希 (-B 强制 bcrypt)
  # Muting stderr with 2>/dev/null as htpasswd might print warnings we don't need
  hash_output=$(docker run --rm httpd:2.4 htpasswd -nbB "$user" "$pass" 2>/dev/null)
  local exit_code=$?

  if [[ $exit_code -ne 0 ]] || [[ -z "$hash_output" ]]; then
    # Retry without stderr mute to capture potential errors from htpasswd itself
    hash_output_debug=$(docker run --rm httpd:2.4 htpasswd -nbB "$user" "$pass" 2>&1)
    log_error "使用 htpasswd 生成密码哈希失败！Docker/htpasswd 命令错误:"
    log_error "输出: $hash_output_debug"
    # Try to pull the image explicitly if it failed
    if [[ "$hash_output_debug" == *"Unable to find image"* ]]; then
        log_info "尝试拉取 httpd:2.4 镜像..."
        if ! docker pull httpd:2.4; then
            log_error "拉取 httpd:2.4 镜像失败。"
        else
             log_warn "镜像已拉取，请重试脚本。"
        fi
    fi
    exit 1
  fi

  # 提取哈希部分 (冒号后面的所有内容)
  bcrypt_hash=$(echo "$hash_output" | cut -d':' -f2-)
  if [[ -z "$bcrypt_hash" ]] || [[ ! "$bcrypt_hash" =~ ^\$2[aby]\$.* ]]; then
     log_error "未能从 htpasswd 输出中提取有效的 bcrypt 哈希值。"
     log_error "原始输出为: $hash_output"
     exit 1
  fi

  # Assign the hash to the variable name passed as argument
  printf -v "$hash_var_name" '%s' "$bcrypt_hash"
  log_info "密码哈希生成成功。"
}

# 创建 Node Exporter 的 web-config.yml (在 WORK_DIR)
# 参数: $1 = 用户名, $2 = 哈希
create_node_exporter_web_config() {
  local user="$1"
  local hash="$2"
  local target_file="$WORK_DIR/$WEB_CONFIG_FILE"
  log_info "正在创建 Node Exporter 认证配置文件: $target_file"
  # 确保工作目录存在
  mkdir -p "$WORK_DIR"
  chmod 700 "$WORK_DIR" # 设置目录权限

  cat <<EOF > "$target_file"
# web-config.yml
# 用于 Node Exporter 的 Basic Authentication 配置
# 由脚本自动生成

basic_auth_users:
  $user: '$hash'
EOF
  # 设置文件权限 (例如，root 可读写，其他人不可访问)
  chmod 644 "$target_file"
  log_info "$target_file 创建成功。"
}

# 创建 Node Exporter 的 systemd 服务文件
# 参数: $1 = User, $2 = Group, $3 = Web Config File Path (绝对路径)
create_node_exporter_systemd_service() {
    local service_user="$1"
    local service_group="$2"
    local web_config_abs_path="$3" # 使用传入的绝对路径

    log_info "创建并配置 Node Exporter systemd 服务 ($NODE_EXPORTER_SERVICE_FILE)..."
    cat <<EOF > "$NODE_EXPORTER_SERVICE_FILE"
[Unit]
Description=Prometheus Node Exporter (Systemd)
Wants=network-online.target
After=network-online.target

[Service]
User=$service_user
Group=$service_group
Type=simple
# 增加了一些常见的排除项 和 web 认证配置
ExecStart=$NODE_EXPORTER_BIN \\
  --collector.cpu.info \\
  --collector.diskstats.ignored-devices="^(ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\\d+n\\d+p)\\d+$" \\
  --collector.filesystem.ignored-mount-points="^/(sys|proc|dev|host|etc|run/user|run/lock|var/lib/docker/.+|snap/.+|var/snap/.+|mnt/.+)($$|/)" \\
  --collector.filesystem.ignored-fs-types="^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tmpfs|tracefs|xfs)$" \\
  --collector.netclass.ignored-devices="^(lo|veth.*|docker0|virbr.*|kube-ipvs.*)$" \\
  --collector.textfile.directory="$NODE_EXPORTER_TEXTFILE_DIR" \\
  --web.listen-address=":9100" \\
  --web.config.file="$web_config_abs_path"

Restart=on-failure
RestartSec=5s
StartLimitInterval=60s
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
EOF
    log_info "Node Exporter Systemd 服务文件创建成功。"
}

# 创建 Probers (Blackbox/Smokeping) 的 Docker Compose 文件
# 参数: $1 = "true"|"false" (是否包含 blackbox)
#      $2 = "true"|"false" (是否包含 smokeping_prober)
create_probers_compose_config() {
    local include_blackbox="$1"
    local include_smokeping="$2"
    local target_file="$WORK_DIR/$COMPOSE_FILE"
    log_info "正在生成 Docker Compose 配置文件: $target_file"

    # 文件头部
    cat <<EOF > "$target_file"
# docker-compose.yml for Prober Exporters
# 由脚本自动生成
version: '3.7'

services:
EOF

    # --- Blackbox Exporter 部分 ---
    if [[ "$include_blackbox" == "true" ]]; then
        log_info "向 docker-compose.yml 添加 blackbox_exporter..."
        cat <<EOF >> "$target_file"
  blackbox_exporter:
    image: quay.io/prometheus/blackbox-exporter:latest
    container_name: blackbox_exporter
    restart: unless-stopped
    user: nobody
    volumes:
      - ./$BLACKBOX_CONFIG_FILE_REL:/config/blackbox.yml:ro
      - ./$WEB_CONFIG_FILE:/etc/blackbox_exporter/web-config.yml:ro
    ports:
      - "9115:9115"
    command:
      - '--config.file=/config/blackbox.yml'
      - '--web.config.file=/etc/blackbox_exporter/web-config.yml'

EOF
    fi

    # --- Smokeping Prober 部分 ---
    if [[ "$include_smokeping" == "true" ]]; then
        log_info "向 docker-compose.yml 添加 smokeping_prober..."
        cat <<EOF >> "$target_file"
  smokeping_prober:
    image: quay.io/superq/smokeping-prober:latest
    container_name: smokeping_prober
    restart: unless-stopped
    volumes:
      - ./$SMOKEPING_PROBER_CONFIG_FILE_REL:/config.yml:ro
      # Smokeping Prober 也使用相同的 web-config.yml 进行认证
      - ./$WEB_CONFIG_FILE:/etc/smokeping_prober/web-config.yml:ro
    ports:
      - "9374:9374" # Smokeping Prober 默认端口
    command:
      - '--config.file=/config.yml'
      # 添加 web 认证配置，保护 /metrics 和 /probe 端点
      - '--web.config.file=/etc/smokeping_prober/web-config.yml'

EOF
    fi

    log_info "$target_file 生成成功。"
}

# 卸载 Node Exporter (Systemd)
uninstall_node_exporter_systemd() {
  log_warn "--- 开始卸载 Node Exporter (Systemd) ---"
  log_info "停止并禁用 node_exporter 服务..."
  systemctl stop node_exporter >/dev/null 2>&1 || true # 忽略停止失败
  systemctl disable node_exporter >/dev/null 2>&1 || true # 忽略禁用失败

  log_info "删除 node_exporter 二进制文件: $NODE_EXPORTER_BIN"
  rm -f "$NODE_EXPORTER_BIN"

  log_info "删除 systemd 服务文件: $NODE_EXPORTER_SERVICE_FILE"
  rm -f "$NODE_EXPORTER_SERVICE_FILE"

  log_info "删除 Node Exporter Web 配置文件: $WORK_DIR/$WEB_CONFIG_FILE"
  rm -f "$WORK_DIR/$WEB_CONFIG_FILE"

  log_info "删除凭据文件: $WORK_DIR/$PASSWORD_FILE"
  rm -f "$WORK_DIR/$PASSWORD_FILE" # 删除存储的明文密码

  # 删除 textfile collector 目录（如果为空）
  if [ -d "$NODE_EXPORTER_TEXTFILE_DIR" ]; then
      if [ -z "$(ls -A "$NODE_EXPORTER_TEXTFILE_DIR" 2>/dev/null)" ]; then
          log_info "删除空的 textfile collector 目录: $NODE_EXPORTER_TEXTFILE_DIR"
          rmdir "$NODE_EXPORTER_TEXTFILE_DIR" || log_warn "删除目录 $NODE_EXPORTER_TEXTFILE_DIR 失败 (可能已被删除或非空)"
      else
          log_warn "Textfile collector 目录 $NODE_EXPORTER_TEXTFILE_DIR 非空，将保留。"
      fi
  fi
  # 可选：删除 /var/lib/node_exporter 目录本身（如果 textfile 目录也被删了且该目录为空）
   if [ -d "/var/lib/node_exporter" ]; then
       if [ -z "$(ls -A /var/lib/node_exporter 2>/dev/null)" ]; then
           log_info "删除空的父目录: /var/lib/node_exporter"
           rmdir /var/lib/node_exporter || log_warn "删除目录 /var/lib/node_exporter 失败 (可能已被删除或非空)"
       fi
   fi

  log_info "重新加载 systemd 配置..."
  systemctl daemon-reload

  log_info "--- Node Exporter (Systemd) 卸载完成 ---"
}

# 卸载所有 Docker Probers (Blackbox 和 Smokeping)
uninstall_docker_probers() {
    log_warn "--- 开始卸载所有 Docker Probers (Blackbox, Smokeping) ---"
    local compose_file_path="$WORK_DIR/$COMPOSE_FILE"

    if [[ ! -f "$compose_file_path" ]]; then
        log_warn "未找到 Docker Compose 文件 '$compose_file_path'，跳过卸载。"
        return
    fi

    if [[ ${#COMPOSE_CMD_ARRAY[@]} -eq 0 ]]; then
        log_error "未检测到 Docker Compose 命令，无法执行卸载。请手动操作。"
        return
    fi

    log_info "正在使用 '${COMPOSE_CMD_ARRAY[*]}' 停止并移除所有 Docker Prober 服务..."
    # 使用 down -v 会停止并移除所有容器、网络和卷
    (cd "$WORK_DIR" && "${COMPOSE_CMD_ARRAY[@]}" down -v --remove-orphans) || log_warn "执行 '${COMPOSE_CMD_ARRAY[*]} down' 失败，可能服务未运行或已移除。"

    log_info "删除 Docker Compose 文件: $compose_file_path"
    rm -f "$compose_file_path"

    # 清理 Blackbox 相关文件
    log_info "删除 Blackbox 配置文件: $BLACKBOX_CONFIG_FILE_ABS"
    rm -f "$BLACKBOX_CONFIG_FILE_ABS"
    rm -rf "$WORK_DIR/$BLACKBOX_CONFIG_DIR"

    # 清理 Smokeping Prober 相关文件
    log_info "删除 Smokeping Prober 配置文件: $SMOKEPING_PROBER_CONFIG_FILE_ABS"
    rm -f "$SMOKEPING_PROBER_CONFIG_FILE_ABS"
    rm -rf "$WORK_DIR/$SMOKEPING_PROBER_CONFIG_DIR"

    # 注意：不删除共享的 web-config.yml 和凭据文件，因为 Node Exporter 可能还在使用
    log_info "--- 所有 Docker Probers 卸载完成 ---"
}

# 更换 Node Exporter 认证凭据
change_node_exporter_credentials() {
  log_warn "--- 开始更换 Node Exporter 认证凭据 ---"
  local web_config_path="$WORK_DIR/$WEB_CONFIG_FILE"
  local cred_file_path="$WORK_DIR/$PASSWORD_FILE"

  if [[ ! -f "$web_config_path" ]]; then
      log_error "未找到 Node Exporter 认证配置文件 '$web_config_path'。无法更换凭据。"
      log_error "请先确保 Node Exporter 已通过此脚本安装。"
      return 1 # 返回错误，以便调用者知道操作失败
  fi

  # 1. 获取新凭据
  local new_username=""
  local new_password=""
  local new_hash=""
  read -p "请输入新的 Node Exporter Basic Auth 用户名: " new_username
  if [[ -z "$new_username" ]]; then
    log_error "用户名不能为空。"
    return 1
  fi
  prompt_password new_password # 获取密码存入 new_password

  # 2. 生成新哈希 (需要 Docker)
  generate_hash "$new_username" "$new_password" new_hash # 哈希存入 new_hash
  if [[ -z "$new_hash" ]]; then
      log_error "生成新哈希失败，无法继续。"
      return 1
  fi

  # 3. 更新 Web 配置文件
  create_node_exporter_web_config "$new_username" "$new_hash"

  # 4. 更新存储的明文密码文件 (并警告)
  log_info "正在更新存储的明文密码文件: $cred_file_path"
  echo "$new_password" > "$cred_file_path"
  chmod 600 "$cred_file_path" # 确保权限正确
  log_warn "${RED}警告：新的明文密码已更新并存储在 $cred_file_path 文件中！${NC}"

  # 5. 重启 Node Exporter 服务以应用更改
  log_info "正在重启 node_exporter 服务以应用新的凭据..."
  if systemctl is-active --quiet node_exporter; then
      if systemctl restart node_exporter; then
        log_info "Node Exporter 服务已成功重启。"
      else
        log_error "重启 node_exporter 服务失败。请检查日志: journalctl -u node_exporter -n 50 --no-pager"
        # 即使重启失败，凭据文件也已更新
      fi
  else
      log_warn "Node Exporter 服务当前未运行，凭据将在下次启动时生效。"
  fi

  # 检查并重启 Docker Probers
  if [[ "$BLACKBOX_DOCKER_INSTALLED" == true ]] || [[ "$SMOKEPING_DOCKER_INSTALLED" == true ]]; then
      log_info "正在重启 Docker Prober 服务以应用新的凭据..."
      if (cd "$WORK_DIR" && "${COMPOSE_CMD_ARRAY[@]}" restart); then
          log_info "Docker Prober 服务已成功重启。"
      else
          log_error "重启 Docker Prober 服务失败。请手动重启。"
      fi
  fi

  log_info "--- Node Exporter 认证凭据已成功更换 ---"
  return 0
}

# 管理 Blackbox Exporter (Docker) 服务
manage_blackbox_docker() {
    local compose_file_path="$WORK_DIR/$COMPOSE_FILE"
    if [[ ! -f "$compose_file_path" ]]; then
        log_error "未找到 Docker Compose 文件 '$compose_file_path'。无法管理 Blackbox 服务。"
        return 1
    fi
    if [[ ${#COMPOSE_CMD_ARRAY[@]} -eq 0 ]]; then
        log_error "未检测到 Docker Compose 命令，无法管理 Blackbox 服务。"
        return 1
    fi

    echo "请选择 Blackbox Exporter (Docker) 服务操作:"
    echo "  a) 启动/创建 (up -d)"
    echo "  b) 停止 (stop)"
    echo "  c) 重启 (restart)"
    echo "  d) 查看日志 (logs)"
    echo "  e) 查看状态 (ps)"
    echo "  f) 停止并移除 (down)"
    echo "  *) 返回"
    read -p "请输入选项 (a/b/c/d/e/f/*): " SVC_CHOICE

    # 切换到工作目录执行 compose 命令
    (cd "$WORK_DIR" && \
        case $SVC_CHOICE in
            a) log_info "尝试启动/创建 Blackbox 服务..."; "${COMPOSE_CMD_ARRAY[@]}" up -d && log_info "命令执行成功。" || log_error "命令执行失败。";;
            b) log_info "尝试停止 Blackbox 服务..."; "${COMPOSE_CMD_ARRAY[@]}" stop blackbox_exporter && log_info "命令执行成功。" || log_error "命令执行失败。";;
            c) log_info "尝试重启 Blackbox 服务..."; "${COMPOSE_CMD_ARRAY[@]}" restart blackbox_exporter && log_info "命令执行成功。" || log_error "命令执行失败。";;
            d) log_info "查看 Blackbox 服务日志 (按 Ctrl+C 退出):"; "${COMPOSE_CMD_ARRAY[@]}" logs -f blackbox_exporter ;;
            e) log_info "查看 Blackbox 服务状态:"; "${COMPOSE_CMD_ARRAY[@]}" ps ;;
            f) log_info "尝试停止并移除 Blackbox 服务..."; "${COMPOSE_CMD_ARRAY[@]}" down && log_info "命令执行成功。" || log_error "命令执行失败。";;
            *) log_info "返回...";;
        esac
    )
    return 0
}

# 管理 Smokeping Prober (Docker) 服务
manage_smokeping_prober_docker() {
    local compose_file_path="$WORK_DIR/$COMPOSE_FILE"
    if [[ ! -f "$compose_file_path" ]]; then
        log_error "未找到 Docker Compose 文件 '$compose_file_path'。无法管理 Smokeping Prober 服务。"
        return 1
    fi
    if [[ ${#COMPOSE_CMD_ARRAY[@]} -eq 0 ]]; then
        log_error "未检测到 Docker Compose 命令，无法管理 Smokeping Prober 服务。"
        return 1
    fi

    echo "请选择 Smokeping Prober (Docker) 服务操作:"
    echo "  a) 启动/创建 (up -d)"
    echo "  b) 停止 (stop)"
    echo "  c) 重启 (restart)"
    echo "  d) 查看日志 (logs)"
    echo "  e) 查看状态 (ps)"
    echo "  f) 停止并移除 (down)"
    echo "  *) 返回"
    read -p "请输入选项 (a/b/c/d/e/f/*): " SVC_CHOICE

    # 切换到工作目录执行 compose 命令
    (cd "$WORK_DIR" && \
        case $SVC_CHOICE in
            a) log_info "尝试启动/创建 Smokeping Prober 服务..."; "${COMPOSE_CMD_ARRAY[@]}" up -d smokeping_prober && log_info "命令执行成功。" || log_error "命令执行失败。";;
            b) log_info "尝试停止 Smokeping Prober 服务..."; "${COMPOSE_CMD_ARRAY[@]}" stop smokeping_prober && log_info "命令执行成功。" || log_error "命令执行失败。";;
            c) log_info "尝试重启 Smokeping Prober 服务..."; "${COMPOSE_CMD_ARRAY[@]}" restart smokeping_prober && log_info "命令执行成功。" || log_error "命令执行失败。";;
            d) log_info "查看 Smokeping Prober 服务日志 (按 Ctrl+C 退出):"; "${COMPOSE_CMD_ARRAY[@]}" logs -f smokeping_prober ;;
            e) log_info "查看 Smokeping Prober 服务状态:"; "${COMPOSE_CMD_ARRAY[@]}" ps ;;
            f) log_info "尝试停止并移除 Smokeping Prober 服务..."; "${COMPOSE_CMD_ARRAY[@]}" down smokeping_prober && log_info "命令执行成功。" || log_error "命令执行失败。";;
            *) log_info "返回...";;
        esac
    )
    return 0
}

# --- 主逻辑 ---

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}错误：请使用 root 权限运行此脚本！${NC}"
  exit 1
fi

# 创建/清理日志文件
if [[ -f "$LOG_FILE" ]]; then
    # 保留旧日志
    mv "$LOG_FILE" "$LOG_FILE.$(date +%Y%m%d_%H%M%S).old" || log_warn "无法移动旧日志文件 $LOG_FILE"
fi
echo "--- 脚本执行开始于 $(date) ---" > "$LOG_FILE"
log_info "开始执行 Exporter 安装/管理脚本..."
log_info "工作目录设置为: $WORK_DIR"

# 准备工作目录
log_step "准备工作目录"
mkdir -p "$WORK_DIR"
if [[ $? -ne 0 ]]; then
    log_error "创建工作目录 '$WORK_DIR' 失败。"
    exit 1
fi
chmod 700 "$WORK_DIR" # 设置权限
log_info "工作目录 '$WORK_DIR' 已准备就绪。"
# 后续 Docker Compose 命令需要在 WORK_DIR 下执行，但其他命令不需要

# 检查依赖
log_step "检查依赖环境"
check_command wget
check_command tar
check_command systemctl
check_command grep
check_command date
check_command tee
check_command mktemp
check_command chmod
check_command chown
check_command mkdir
check_command rmdir # For cleanup
check_command rm
check_command mv
check_command cut
check_command getent # For user/group check
check_command docker # 需要 Docker
check_command curl # 需要 curl 下载 Docker 安装脚本 (如果需要)

# 获取操作系统信息
get_os_info

# 检查并安装 Docker (如果需要)
check_install_docker

# 检测 Docker Compose
detect_compose_command # 设置 COMPOSE_CMD_ARRAY

# 检测已安装的组件
NODE_EXPORTER_INSTALLED=false
if [[ -f "$NODE_EXPORTER_SERVICE_FILE" ]] || [[ -f "$NODE_EXPORTER_BIN" ]]; then
    NODE_EXPORTER_INSTALLED=true
    log_info "检测到 Node Exporter (Systemd) 可能已安装。"
fi

BLACKBOX_DOCKER_INSTALLED=false
if [[ -f "$WORK_DIR/$COMPOSE_FILE" ]]; then
    # 更可靠的检测是看容器是否定义或运行
    if [[ ${#COMPOSE_CMD_ARRAY[@]} -gt 0 ]]; then
        if (cd "$WORK_DIR" && "${COMPOSE_CMD_ARRAY[@]}" ps -q blackbox_exporter 2>/dev/null) >/dev/null; then
             BLACKBOX_DOCKER_INSTALLED=true
             log_info "检测到 Blackbox Exporter (Docker) 容器正在运行或已定义。"
        elif grep -q "blackbox_exporter:" "$WORK_DIR/$COMPOSE_FILE"; then
             BLACKBOX_DOCKER_INSTALLED=true
             log_info "检测到 Blackbox Exporter (Docker) 的 Compose 文件存在。"
        fi
    elif grep -q "blackbox_exporter:" "$WORK_DIR/$COMPOSE_FILE"; then
        # 如果没有 compose 命令，但文件存在，也认为它“已安装”
        BLACKBOX_DOCKER_INSTALLED=true
        log_warn "检测到 Blackbox Exporter 的 Compose 文件，但无法找到 docker-compose 命令进行验证。"
    fi
fi

SMOKEPING_DOCKER_INSTALLED=false
if [[ -f "$WORK_DIR/$COMPOSE_FILE" ]]; then
    if [[ ${#COMPOSE_CMD_ARRAY[@]} -gt 0 ]]; then
        if (cd "$WORK_DIR" && "${COMPOSE_CMD_ARRAY[@]}" ps -q smokeping_prober 2>/dev/null) >/dev/null; then
             SMOKEPING_DOCKER_INSTALLED=true
             log_info "检测到 Smokeping Prober (Docker) 容器正在运行或已定义。"
        elif grep -q "smokeping_prober:" "$WORK_DIR/$COMPOSE_FILE"; then
             SMOKEPING_DOCKER_INSTALLED=true
             log_info "检测到 Smokeping Prober (Docker) 的 Compose 文件存在。"
        fi
    elif grep -q "smokeping_prober:" "$WORK_DIR/$COMPOSE_FILE"; then
        SMOKEPING_DOCKER_INSTALLED=true
        log_warn "检测到 Smokeping Prober 的 Compose 文件，但无法找到 docker-compose 命令进行验证。"
    fi
fi

# --- 管理菜单 (如果检测到任何组件) ---
if [[ "$NODE_EXPORTER_INSTALLED" == true ]] || [[ "$BLACKBOX_DOCKER_INSTALLED" == true ]] || [[ "$SMOKEPING_DOCKER_INSTALLED" == true ]]; then
  log_warn "检测到已安装的 Exporter 组件。"
  echo "----------------------------------------"
  echo "请选择操作："
  echo "  1) 卸载所有 Exporter"
  echo "  2) 卸载 Node Exporter (Systemd)"
  echo "  3) 卸载所有 Docker Probers (Blackbox + Smokeping)"
  echo "  4) 更改认证凭据 (适用于所有Exporter)"
  echo "  5) 管理 Node Exporter 服务 (Systemd)"
  echo "  6) 管理 Blackbox Exporter 服务 (Docker)"
  echo "  6a) 管理 Smokeping Prober 服务 (Docker)"
  echo "  7) 强制重新安装所有组件"
  echo "  *) 退出脚本"
  echo "----------------------------------------"
  read -p "请输入选项: " CHOICE

  case $CHOICE in
    1)
      log_warn "--- 开始卸载所有组件 ---"
      if [[ "$NODE_EXPORTER_INSTALLED" == true ]]; then uninstall_node_exporter_systemd; fi
      # 调用统一的 Docker Prober 卸载函数
      if [[ "$BLACKBOX_DOCKER_INSTALLED" == true ]] || [[ "$SMOKEPING_DOCKER_INSTALLED" == true ]]; then
          uninstall_docker_probers
      fi
      log_info "所有检测到的 Exporter 组件卸载完成。"
      exit 0
      ;;
    2)
      if [[ "$NODE_EXPORTER_INSTALLED" == true ]]; then
          uninstall_node_exporter_systemd
      else
          log_warn "未检测到 Node Exporter (Systemd) 安装。"
      fi
      exit 0
      ;;
    3) 
      # 调用统一的 Docker Prober 卸载函数
      if [[ "$BLACKBOX_DOCKER_INSTALLED" == true ]] || [[ "$SMOKEPING_DOCKER_INSTALLED" == true ]]; then
          uninstall_docker_probers
      else
          log_warn "未检测到任何 Docker Prober 安装。"
      fi
      exit 0
      ;;
    4)
      if [[ "$NODE_EXPORTER_INSTALLED" == true ]]; then
          change_node_exporter_credentials || log_error "更换凭据失败。"
      else
          log_error "Node Exporter (Systemd) 未安装，无法更换凭据。"
      fi
      exit 0
      ;;
    5)
      if [[ "$NODE_EXPORTER_INSTALLED" == true ]]; then
          echo "请选择 Node Exporter 服务操作:"
          echo "  a) 启动 (start)"
          echo "  b) 停止 (stop)"
          echo "  c) 重启 (restart)"
          echo "  d) 查看状态 (status)"
          echo "  *) 返回"
          read -p "请输入选项 (a/b/c/d/*): " SVC_CHOICE_NE
          case $SVC_CHOICE_NE in
              a) log_info "尝试启动 node_exporter 服务..."; systemctl start node_exporter && log_info "服务已启动。" || log_error "启动失败。";;
              b) log_info "尝试停止 node_exporter 服务..."; systemctl stop node_exporter && log_info "服务已停止。" || log_error "停止失败。";;
              c) log_info "尝试重启 node_exporter 服务..."; systemctl restart node_exporter && log_info "服务已重启。" || log_error "重启失败。";;
              d) log_info "查看 node_exporter 服务状态:"; systemctl status node_exporter --no-pager;;
              *) log_info "返回...";;
          esac
      else
          log_error "Node Exporter (Systemd) 未安装，无法管理服务。"
      fi
      exit 0
      ;;
    6)
       if [[ "$BLACKBOX_DOCKER_INSTALLED" == true ]]; then
           manage_blackbox_docker || log_error "管理 Blackbox 服务时出错。"
       else
           log_error "Blackbox Exporter (Docker) 未安装，无法管理服务。"
       fi
       exit 0
       ;;
    6a)
        if [[ "$SMOKEPING_DOCKER_INSTALLED" == true ]]; then
            manage_smokeping_prober_docker || log_error "管理 Smokeping Prober 服务时出错。"
        else
            log_error "Smokeping Prober (Docker) 未安装，无法管理服务。"
        fi
        exit 0
        ;;
    7)
      log_warn "选择强制重新安装，将首先执行卸载..."
      if [[ "$NODE_EXPORTER_INSTALLED" == true ]]; then uninstall_node_exporter_systemd; fi
      if [[ "$BLACKBOX_DOCKER_INSTALLED" == true ]] || [[ "$SMOKEPING_DOCKER_INSTALLED" == true ]]; then
          uninstall_docker_probers
      fi
      log_info "卸载完成，现在开始重新安装..."
      # 继续执行下面的安装流程
      ;;
    *)
      log_info "用户选择退出脚本。"
      exit 0
      ;;
  esac
fi

# --- 执行安装流程 ---
log_step "开始安装 Exporter"

# 选择要安装的组件
install_node=false
install_blackbox=false
install_smokeping=false # 新增
echo "请选择要安装的 Exporter (可多选, 例如输入 '13' 安装 Node 和 Smokeping):"
echo "  1) Node Exporter (Systemd, 带 Basic Auth)"
echo "  2) Blackbox Exporter (Docker Compose)"
echo "  3) Smokeping Prober (Docker Compose)"
read -p "请输入选项 (例如 1, 2, 3, 12, 13, 23, 123): " install_choice

if [[ "$install_choice" =~ "1" ]]; then install_node=true; fi
if [[ "$install_choice" =~ "2" ]]; then install_blackbox=true; fi
if [[ "$install_choice" =~ "3" ]]; then install_smokeping=true; fi # 新增

if [[ "$install_node" == false ]] && [[ "$install_blackbox" == false ]] && [[ "$install_smokeping" == false ]]; then
    log_error "未选择任何组件进行安装。"
    exit 1
fi

# --- Node Exporter 安装 (如果选择) ---
if [[ "$install_node" == true ]]; then
    log_step "安装 Node Exporter (Systemd) v$NODE_EXPORTER_VERSION"

    # 1. 获取认证凭据
    log_info "获取 Node Exporter Basic Auth 凭据"
    AUTH_USERNAME=""
    AUTH_PASSWORD=""
    AUTH_HASH=""
    read -p "请输入用于 Node Exporter Basic Auth 的用户名: " AUTH_USERNAME
    if [[ -z "$AUTH_USERNAME" ]]; then
      log_error "用户名不能为空。"
      exit 1
    fi
    prompt_password AUTH_PASSWORD # 获取密码存入 AUTH_PASSWORD

    # 2. 生成哈希
    log_info "生成密码哈希"
    generate_hash "$AUTH_USERNAME" "$AUTH_PASSWORD" AUTH_HASH # 哈希存入 AUTH_HASH
    if [[ -z "$AUTH_HASH" ]]; then
        log_error "生成哈希失败，无法继续安装 Node Exporter。"
        exit 1
    fi

    # 3. 创建 Web 配置文件 (在 WORK_DIR)
    log_info "创建 Node Exporter Web 认证配置文件"
    create_node_exporter_web_config "$AUTH_USERNAME" "$AUTH_HASH"
    NODE_EXPORTER_WEB_CONFIG_ABS_PATH="$WORK_DIR/$WEB_CONFIG_FILE" # 获取绝对路径

    # 4. 存储明文密码 (并警告)
    log_info "存储明文密码 (用于凭据管理)"
    NODE_CRED_FILE_PATH="$WORK_DIR/$PASSWORD_FILE"
    echo "$AUTH_PASSWORD" > "$NODE_CRED_FILE_PATH"
    chmod 600 "$NODE_CRED_FILE_PATH" # 仅限 root 读写
    log_warn "${RED}警告：Node Exporter 的明文密码已存储在 $NODE_CRED_FILE_PATH 文件中！${NC}"
    log_warn "${YELLOW}这是为了方便 '更换认证凭据' 功能。请确保此文件安全，或在安装后手动删除此文件（这将禁用 '更换认证凭据' 功能）。${NC}"

    # 5. 下载 Node Exporter
    log_info "下载 Node Exporter"
    ARCH=$(uname -m)
    case $ARCH in
      x86_64) ARCH="amd64" ;;
      aarch64) ARCH="arm64" ;;
      armv7l) ARCH="armv7" ;;
      *) log_error "不支持的系统架构: $ARCH"; exit 1 ;;
    esac
    log_info "系统架构检测为: $ARCH"

    log_info "正在下载 Node Exporter v$NODE_EXPORTER_VERSION for linux-$ARCH..."
    DOWNLOAD_URL="https://github.com/prometheus/node_exporter/releases/download/v$NODE_EXPORTER_VERSION/node_exporter-$NODE_EXPORTER_VERSION.linux-$ARCH.tar.gz"
    TMP_DIR=$(mktemp -d -t node_exporter_install-XXXXXX) # 创建临时目录

    log_info "下载地址: $DOWNLOAD_URL"
    if ! wget --timeout=60 --tries=3 -q -O "$TMP_DIR/node_exporter.tar.gz" "$DOWNLOAD_URL"; then
        log_error "下载 Node Exporter 失败，请检查网络、URL 或版本/架构是否存在: $DOWNLOAD_URL"
        rm -rf "$TMP_DIR"
        exit 1
    fi

    # 6. 解压并安装
    log_info "解压并安装 Node Exporter"
    mkdir "$TMP_DIR/extracted"
    if ! tar xzf "$TMP_DIR/node_exporter.tar.gz" -C "$TMP_DIR/extracted/" --strip-components=1; then
        log_error "解压 Node Exporter 失败。"
        rm -rf "$TMP_DIR"
        exit 1
    fi

    NODE_EXPORTER_EXTRACTED_BIN="$TMP_DIR/extracted/node_exporter"
    if [[ ! -f "$NODE_EXPORTER_EXTRACTED_BIN" ]]; then
        log_error "在解压文件中未找到 node_exporter 二进制文件。"
        rm -rf "$TMP_DIR"
        exit 1
    fi

    log_info "安装 node_exporter 到 $NODE_EXPORTER_BIN..."
    if ! mv "$NODE_EXPORTER_EXTRACTED_BIN" "$NODE_EXPORTER_BIN"; then
        log_error "移动 node_exporter 二进制文件失败。请检查权限或目标路径。"
        rm -rf "$TMP_DIR"
        exit 1
    fi
    chmod +x "$NODE_EXPORTER_BIN"

    # 清理临时文件
    rm -rf "$TMP_DIR"
    log_info "临时文件已清理。"

    # 7. 确定服务运行用户/组
    NOGROUP_USER="root"
    NOGROUP_GROUP="root"
    log_info "将使用用户 '$NOGROUP_USER' 和组 '$NOGROUP_GROUP' 运行 Node Exporter 服务。"
    log_info "使用 root 用户可以确保收集所有系统指标。"

    # 8. 创建 systemd 服务文件 (传入 web config 绝对路径)
    log_info "创建 Node Exporter systemd 服务文件"
    create_node_exporter_systemd_service "$NOGROUP_USER" "$NOGROUP_GROUP" "$NODE_EXPORTER_WEB_CONFIG_ABS_PATH"

    # 9. 创建 textfile collector 目录
    log_info "设置 Textfile Collector 目录"
    mkdir -p "$NODE_EXPORTER_TEXTFILE_DIR"
    chown $NOGROUP_USER:$NOGROUP_GROUP "$NODE_EXPORTER_TEXTFILE_DIR"
    log_info "Textfile collector 目录 '$NODE_EXPORTER_TEXTFILE_DIR' 已创建并设置权限。"

    # 10. 启用并启动服务
    log_info "启用并启动 Node Exporter 服务"
    systemctl daemon-reload
    systemctl enable node_exporter
    systemctl start node_exporter

    # 短暂等待服务启动
    log_info "等待几秒钟让服务启动..."
    sleep 3

    # 检查服务状态
    if ! systemctl is-active --quiet node_exporter; then
      log_error "Node Exporter 服务启动失败！请检查日志。"
      log_error "运行 'journalctl -u node_exporter -n 50 --no-pager' 查看详细日志。"
      journalctl -u node_exporter -n 20 --no-pager >> "$LOG_FILE" 2>&1
      # 尝试清理失败的安装
      uninstall_node_exporter_systemd
      exit 1
    else
      log_info "Node Exporter (Systemd) 服务已成功启动。"
    fi
fi # End Node Exporter Install

# --- Docker Probers (Blackbox/Smokeping) 安装 (如果选择) ---
if [[ "$install_blackbox" == true ]] || [[ "$install_smokeping" == true ]]; then
    log_step "安装 Docker Probers (Blackbox/Smokeping)"

    if [[ ${#COMPOSE_CMD_ARRAY[@]} -eq 0 ]]; then
        log_error "未找到 Docker Compose 命令。无法安装 Docker Probers。"
        exit 1
    fi

    # --- 1. 处理 Blackbox (如果选择) ---
    if [[ "$install_blackbox" == true ]]; then
        log_info "配置 Blackbox Exporter..."
        mkdir -p "$WORK_DIR/$BLACKBOX_CONFIG_DIR"
        if [[ ! -f "$BLACKBOX_CONFIG_FILE_ABS" ]]; then
            log_warn "创建默认 Blackbox 配置文件: $BLACKBOX_CONFIG_FILE_ABS"
            echo "$DEFAULT_BLACKBOX_CONFIG" > "$BLACKBOX_CONFIG_FILE_ABS"
        fi
        chmod 644 "$BLACKBOX_CONFIG_FILE_ABS"
    fi
    
    # --- 2. 处理 Smokeping Prober (如果选择) ---
    if [[ "$install_smokeping" == true ]]; then
        log_info "配置 Smokeping Prober..."
        mkdir -p "$WORK_DIR/$SMOKEPING_PROBER_CONFIG_DIR"
        if [[ ! -f "$SMOKEPING_PROBER_CONFIG_FILE_ABS" ]]; then
            log_warn "创建默认 Smokeping Prober 配置文件: $SMOKEPING_PROBER_CONFIG_FILE_ABS"
            echo "$DEFAULT_SMOKEPING_PROBER_CONFIG" > "$SMOKEPING_PROBER_CONFIG_FILE_ABS"
        fi
        chmod 644 "$SMOKEPING_PROBER_CONFIG_FILE_ABS"
    fi

    # --- 3. 处理共享的 web-config.yml ---
    if [[ ! -f "$WORK_DIR/$WEB_CONFIG_FILE" ]]; then
        log_warn "未找到 '$WORK_DIR/$WEB_CONFIG_FILE' 文件。将为 Docker Probers 创建认证。"
        # 提示输入用户名密码并生成 web-config.yml
        local prober_user=""
        local prober_pass=""
        local prober_hash=""
        read -p "请输入用于 Docker Probers /metrics 的用户名: " prober_user
        if [[ -z "$prober_user" ]]; then log_error "用户名不能为空。"; exit 1; fi
        local temp_prober_pass_var="prober_pass_val"
        prompt_password "$temp_prober_pass_var"
        prober_pass="${!temp_prober_pass_var}"

        generate_hash "$prober_user" "$prober_pass" prober_hash
        if [[ -z "$prober_hash" ]]; then log_error "生成哈希失败。"; exit 1; fi
        create_node_exporter_web_config "$prober_user" "$prober_hash"
        log_info "已为 Docker Probers 创建认证配置文件。"
        local prober_cred_file="$WORK_DIR/.prober_credentials"
        echo "$prober_pass" > "$prober_cred_file"
        chmod 600 "$prober_cred_file"
        log_warn "${RED}警告：Docker Probers 的明文密码已存储在 $prober_cred_file 文件中！${NC}"
    else
        log_info "将使用现有的 '$WORK_DIR/$WEB_CONFIG_FILE' 文件来保护 Docker Probers /metrics 端点。"
    fi

    # --- 4. 创建 Docker Compose 文件 (调用新函数) ---
    create_probers_compose_config "$install_blackbox" "$install_smokeping"

    # --- 5. 启动 Docker Compose 服务 ---
    log_info "正在使用 '${COMPOSE_CMD_ARRAY[*]} up -d' 启动 Prober 服务..."
    if (cd "$WORK_DIR" && "${COMPOSE_CMD_ARRAY[@]}" up -d); then
      log_info "Docker Probers 服务启动成功！"
    else
      log_error "Docker Probers 服务启动失败！请检查日志。"
      exit 1
    fi
fi # End Docker Probers Install

# --- 完成提示 ---
log_step "安装完成"
echo -e "${GREEN}安装过程已完成。配置文件位于 $WORK_DIR 目录中。${NC}"
HOST_IP=$(hostname -I | awk '{print $1}')

if [[ "$install_node" == true ]]; then
    echo "- Node Exporter (Systemd) 正在监听端口 9100。"
    echo "  访问需要 Basic Auth (用户: $AUTH_USERNAME)。"
    echo "  测试命令: curl -u '$AUTH_USERNAME':'<你的密码>' http://127.0.0.1:9100/metrics"
    if [[ -n "$HOST_IP" ]] && [[ "$HOST_IP" != "127.0.0.1" ]]; then
        echo "             curl -u '$AUTH_USERNAME':'<你的密码>' http://$HOST_IP:9100/metrics"
    fi
    log_warn "${RED}- Node Exporter 明文密码存储在: $WORK_DIR/$PASSWORD_FILE (请妥善保管或删除！)${NC}"
fi

if [[ "$install_smokeping" == true ]]; then
    echo "- Smokeping Prober (Docker) 正在监听端口 9374。"
    log_warn "${YELLOW}- 重要: 您需要手动编辑配置文件来添加探测目标: $SMOKEPING_PROBER_CONFIG_FILE_ABS${NC}"
    echo "  访问 /metrics 端点需要 Basic Auth。"
    echo "  测试命令 (查看所有目标的指标): curl -u '<用户名>':'<密码>' http://127.0.0.1:9374/metrics"
    if [[ -n "$HOST_IP" ]] && [[ "$HOST_IP" != "127.0.0.1" ]]; then
        echo "                                curl -u '<用户名>':'<密码>' http://$HOST_IP:9374/metrics"
    fi
fi

if [[ "$install_blackbox" == true ]]; then
    echo "- Blackbox Exporter (Docker) 正在监听端口 9115。"
    echo "  访问 /metrics 端点需要 Basic Auth (使用上面配置的用户名/密码)。"
    echo "  Blackbox 配置文件: $BLACKBOX_CONFIG_FILE_ABS"
    echo "  测试命令 (探测本机 http): curl 'http://127.0.0.1:9115/probe?module=http_2xx&target=http://127.0.0.1:80'"
    echo "  测试命令 (访问受保护的 /metrics): curl -u '<用户名>':'<密码>' http://127.0.0.1:9115/metrics"
    if [[ -f "$WORK_DIR/.prober_credentials" ]]; then
         log_warn "${RED}- Blackbox 明文密码存储在: $WORK_DIR/.prober_credentials (请妥善保管或删除！)${NC}"
    fi
fi

echo "- 安装日志保存在: $LOG_FILE"

exit 0
