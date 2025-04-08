#!/bin/bash

# 脚本：在 /root/monitoring 目录下使用 Docker Compose 安装 Node/Blackbox Exporter
# 功能：自动检测并安装 Docker (如果未安装)，自动检测并使用 docker-compose (V1) 或 docker compose (V2)，
#       自动生成 bcrypt 哈希，配置实验性 Basic Auth，动态生成 compose 文件，
#       自动创建默认 blackbox.yml。Node/Blackbox 均使用 Bridge 网络。
# 警告：此脚本会将明文密码存储在本地文件 (.exporter_credentials.txt) 中！

# --- 配置 ---
WORK_DIR="/root/monitoring" # 指定工作目录
PASSWORD_FILE=".exporter_credentials.txt"
WEB_CONFIG_FILE="web-config.yml"
COMPOSE_FILE="docker-compose.yml"
BLACKBOX_CONFIG_DIR="blackbox_config" # 相对于 WORK_DIR
BLACKBOX_CONFIG_FILE_REL="$BLACKBOX_CONFIG_DIR/blackbox.yml" # 相对路径
BLACKBOX_CONFIG_FILE_ABS="$WORK_DIR/$BLACKBOX_CONFIG_FILE_REL" # 绝对路径
DOCKER_INSTALL_SCRIPT="get-docker.sh"

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
# 使用数组存储命令，以正确处理 "docker compose" 中的空格
declare -a COMPOSE_CMD_ARRAY

# --- 函数定义 ---
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${BLUE}>>> Step: $1${NC}"; }

# 检查命令是否存在 (如果不存在则返回 1)
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# 检查并安装 Docker
check_install_docker() {
    log_info "检查 Docker 是否已安装..."
    if command_exists docker; then
        log_info "Docker 已安装。"
        return 0
    fi

    log_warn "未检测到 Docker。将尝试使用官方脚本自动安装。"
    log_info "检查 curl 是否可用..."
    if ! command_exists curl; then
        log_error "命令 'curl' 未找到。无法下载 Docker 安装脚本。请先安装 curl。"
        exit 1
    fi

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
    if ! command_exists docker; then
        log_error "Docker 安装后仍然无法检测到 'docker' 命令。请检查安装日志或手动安装。"
        exit 1
    fi
    log_info "Docker 安装成功！"

    # 提示：新安装的 Docker 可能需要重新登录或启动新 Shell 才能让非 root 用户免 sudo 使用
    log_warn "Docker 已安装。如果当前用户不是 root，可能需要重新登录或将用户添加到 'docker' 组才能免 sudo 使用 Docker。"
}


# 检测 Docker Compose 命令 (V1 或 V2) 并设置 COMPOSE_CMD_ARRAY
detect_compose_command() {
  log_info "正在检测 Docker Compose 命令..."
  if command -v docker-compose >/dev/null 2>&1; then
    log_info "检测到 'docker-compose' (V1)。"
    COMPOSE_CMD_ARRAY=("docker-compose")
  elif docker compose version >/dev/null 2>&1; then
    log_info "检测到 'docker compose' (V2)。"
    COMPOSE_CMD_ARRAY=("docker" "compose")
  else
    log_warn "未能检测到可用的 Docker Compose 命令 ('docker-compose' 或 'docker compose')。"
    log_warn "Docker Compose V2 通常随 Docker Engine 一起安装。如果需要 V1，请手动安装。"
    # 脚本可以继续，但用户可能需要手动运行 compose 命令
    # 或者在这里报错退出，取决于你的需求
    log_error "请确保 Docker Compose V1 或 V2 已正确安装并可在当前环境执行。"
    exit 1
  fi
  log_info "将使用命令: ${COMPOSE_CMD_ARRAY[*]}"
}


# 提示输入密码 (带确认)
prompt_password() {
  while true; do
    read -sp "请输入用于 Basic Auth 的密码: " password
    echo
    read -sp "请再次输入密码确认: " password_confirm
    echo
    if [[ "$password" == "$password_confirm" ]]; then
      if [[ -z "$password" ]]; then
        log_warn "密码不能为空，请重新输入。"
      else
        break
      fi
    else
      log_error "两次输入的密码不匹配，请重新输入。"
    fi
  done
}

# 生成 Bcrypt 哈希
generate_hash() {
  local user="$1"
  local pass="$2"
  log_info "正在使用 Docker 生成密码哈希..."
  # 确保 Docker 守护进程正在运行
  if ! docker info > /dev/null 2>&1; then
      log_error "无法连接到 Docker 守护进程。请确保 Docker 服务正在运行。"
      exit 1
  fi
  hash_output=$(docker run --rm httpd:latest htpasswd -nbB "$user" "$pass" 2>&1)
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    log_error "生成密码哈希失败！Docker 命令错误:"
    log_error "$hash_output"
    exit 1
  fi
  # 提取哈希部分 (冒号后面的所有内容)
  bcrypt_hash=$(echo "$hash_output" | cut -d':' -f2-)
  if [[ -z "$bcrypt_hash" ]] || [[ ! "$bcrypt_hash" =~ ^\$2[aby]\$.* ]]; then
     log_error "未能从 htpasswd 输出中提取有效的 bcrypt 哈希值。"
     log_error "输出为: $hash_output"
     exit 1
  fi
  log_info "密码哈希生成成功。"
}

# 创建 web-config.yml
create_web_config() {
  local user="$1"
  local hash="$2"
  log_info "正在创建认证配置文件: $WORK_DIR/$WEB_CONFIG_FILE"
  cat <<EOF > "$WORK_DIR/$WEB_CONFIG_FILE"
# web-config.yml
# 用于 Exporter 的 Basic Authentication 配置
# 由 install_exporters.sh 脚本自动生成

basic_auth_users:
  $user: '$hash'
EOF
  log_info "$WEB_CONFIG_FILE 创建成功。"
}

# 创建 docker-compose.yml
create_compose_file() {
  local install_node="$1"
  local install_blackbox="$2"
  local node_exporter_user="$3" # 用于 Node Exporter 的 user: root

  log_info "正在生成 $WORK_DIR/$COMPOSE_FILE 文件..."

  # 文件头部
  cat <<EOF > "$WORK_DIR/$COMPOSE_FILE"
# docker-compose.yml
# 由 install_exporters.sh 脚本自动生成
version: '3.7'

services:
EOF

  # Node Exporter 服务块 (如果选择安装)
  if [[ "$install_node" == true ]]; then
    log_info "添加 Node Exporter 配置..."
    cat <<EOF >> "$WORK_DIR/$COMPOSE_FILE"
  # --- Node Exporter 配置 ---
  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    user: $node_exporter_user # 需要权限读取宿主机 /proc, /sys 等

    pid: host # 共享宿主机 PID 命名空间

    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
      - ./$WEB_CONFIG_FILE:/etc/node-exporter/web-config.yml:ro # 挂载 Web 配置文件 (相对路径)

    ports:
      - "9100:9100" # 映射 Node Exporter 默认端口

    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--path.rootfs=/rootfs'
      - '--web.config.file=/etc/node-exporter/web-config.yml' # 启用 Basic Auth

EOF
  fi

  # Blackbox Exporter 服务块 (如果选择安装)
  if [[ "$install_blackbox" == true ]]; then
    log_info "添加 Blackbox Exporter 配置 (Bridge 网络模式)..."
    cat <<EOF >> "$WORK_DIR/$COMPOSE_FILE"
  # --- Blackbox Exporter 配置 (Bridge 网络模式 + Basic Auth) ---
  blackbox_exporter:
    image: quay.io/prometheus/blackbox-exporter:latest
    container_name: blackbox_exporter
    restart: unless-stopped
    user: nobody # Blackbox 通常不需要 root

    volumes:
      - ./$BLACKBOX_CONFIG_FILE_REL:/config/blackbox.yml:ro # 挂载 Blackbox 配置文件 (相对路径)
      - ./$WEB_CONFIG_FILE:/etc/blackbox_exporter/web-config.yml:ro # 挂载 Web 配置文件 (相对路径)

    ports:
      - "9115:9115" # 映射 Blackbox Exporter 默认端口

    # 合并原始命令和 Web 配置命令
    command:
      - '--config.file=/config/blackbox.yml'
      - '--web.config.file=/etc/blackbox_exporter/web-config.yml' # 启用 Basic Auth

    # logging: # 如果需要禁用日志，取消注释
    #   driver: "none"

EOF
  fi

  log_info "$COMPOSE_FILE 生成成功。"
}

# --- 主逻辑 ---

# 检查是否以 root 身份运行 (因为要在 /root 下创建目录并可能安装 Docker)
if [[ $EUID -ne 0 ]]; then
  log_error "此脚本需要在 root 权限下运行，因为它将在 /root 目录下创建文件并可能需要安装 Docker。"
  exit 1
fi

log_step "准备工作目录: $WORK_DIR"
mkdir -p "$WORK_DIR"
if [[ $? -ne 0 ]]; then
    log_error "创建工作目录 '$WORK_DIR' 失败。"
    exit 1
fi
cd "$WORK_DIR"
if [[ $? -ne 0 ]]; then
    log_error "切换到工作目录 '$WORK_DIR' 失败。"
    exit 1
fi
log_info "当前工作目录: $(pwd)"


log_step "检查依赖环境"
check_install_docker # 检查并按需安装 Docker
detect_compose_command # 检测 Docker Compose V1 或 V2


log_step "获取用户信息和密码"
read -p "请输入用于 Basic Auth 的用户名: " username
if [[ -z "$username" ]]; then
  log_error "用户名不能为空。"
  exit 1
fi
prompt_password # 获取密码并存入 $password 变量

log_step "存储明文密码"
echo "$password" > "$PASSWORD_FILE"
chmod 600 "$PASSWORD_FILE" # 仅限当前用户读写
log_warn "警告：明文密码已存储在当前目录 ($WORK_DIR) 的 $PASSWORD_FILE 文件中！"
log_warn "请妥善保管此文件，并在不再需要时删除它。"

log_step "生成密码哈希"
generate_hash "$username" "$password" # 哈希存入 $bcrypt_hash 变量

log_step "创建 Web 认证配置文件"
create_web_config "$username" "$bcrypt_hash"

log_step "选择要安装的 Exporter"
echo "请选择要安装的 Exporter:"
echo "  1) Node Exporter"
echo "  2) Blackbox Exporter"
echo "  3) 两者都安装"
read -p "请输入选项 (1/2/3): " install_choice

install_node=false
install_blackbox=false
node_user="root" # Node Exporter 需要 root 权限访问宿主机资源

case $install_choice in
  1) install_node=true ;;
  2) install_blackbox=true ;;
  3) install_node=true; install_blackbox=true ;;
  *) log_error "无效的选项。"; exit 1 ;;
esac

if [[ "$install_node" == false ]] && [[ "$install_blackbox" == false ]]; then
    log_error "未选择任何组件进行安装。"
    exit 1
fi

# 如果安装 Blackbox，检查/创建配置文件
if [[ "$install_blackbox" == true ]]; then
    log_info "检查/创建 Blackbox 配置文件..."
    mkdir -p "$BLACKBOX_CONFIG_DIR" # 确保目录存在
    if [[ ! -f "$BLACKBOX_CONFIG_FILE_ABS" ]]; then
        log_warn "Blackbox 配置文件 '$BLACKBOX_CONFIG_FILE_ABS' 不存在，将使用默认配置创建。"
        echo "$DEFAULT_BLACKBOX_CONFIG" > "$BLACKBOX_CONFIG_FILE_ABS"
        if [[ $? -ne 0 ]]; then
            log_error "创建默认 Blackbox 配置文件失败。"
            exit 1
        fi
        log_info "已创建默认的 $BLACKBOX_CONFIG_FILE_ABS 文件。"
    else
        log_info "找到现有的 Blackbox 配置文件: $BLACKBOX_CONFIG_FILE_ABS"
    fi
fi

log_step "生成 Docker Compose 配置文件"
create_compose_file "$install_node" "$install_blackbox" "$node_user"

log_step "启动 Docker Compose 服务"
# 使用数组展开来正确处理 "docker compose" 中的空格
log_info "正在使用 '${COMPOSE_CMD_ARRAY[*]} up -d' 启动服务..."
if "${COMPOSE_CMD_ARRAY[@]}" up -d; then
  log_info "服务启动成功！"
else
  log_error "服务启动失败！请检查上面的错误信息和容器日志。"
  # 使用数组展开
  log_error "你可以使用 '${COMPOSE_CMD_ARRAY[*]} logs' 查看日志。"
  exit 1
fi

log_step "安装完成"
echo -e "${GREEN}安装过程已完成。所有文件均位于 $WORK_DIR 目录中。${NC}"
if [[ "$install_node" == true ]]; then
    echo "- Node Exporter 应该在端口 9100 上运行 (需要 Basic Auth)。"
fi
if [[ "$install_blackbox" == true ]]; then
    echo "- Blackbox Exporter 应该在端口 9115 上运行 (需要 Basic Auth 访问 /metrics)。"
    echo "- Blackbox 配置文件: $BLACKBOX_CONFIG_FILE_ABS"
fi
echo "- Basic Auth 用户名: $username"
echo -e "- ${RED}明文密码存储在: $WORK_DIR/$PASSWORD_FILE (请妥善保管或删除！)${NC}"

exit 0