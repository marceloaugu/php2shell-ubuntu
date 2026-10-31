#!/usr/bin/env bash
#
# php2shell-ubuntu.sh - Analisa e corrige CVE-2026-109618 e CVE-2026-109619 ("php2shell").
#
# Fontes das versões corrigidas (dados de 31/10/2026):
#   Ubuntu: USN-8948-1 e USN-8948-2. O Ubuntu faz backport: 8.3.6-0ubuntu0.24.04.13
#           está corrigido mesmo com número upstream "antigo".
#   PHP:    8.5.12, 8.4.27, 8.3.36, 8.2.35 (também usado para o PPA ondrej/php).
#
# Uso:
#   sudo ./php2shell-ubuntu.sh               analisa e atualiza o que estiver vulnerável
#   ./php2shell-ubuntu.sh --check            apenas analisa, sem alterar nada
#   sudo ./php2shell-ubuntu.sh --mitigate    também desativa session.upload_progress
#   sudo ./php2shell-ubuntu.sh --no-restart  não reinicia PHP-FPM/Apache
#   sudo ./php2shell-ubuntu.sh --migrate     migra PHP 8.1 ou anterior para o 8.4 (pode quebrar apps)
#   sudo ./php2shell-ubuntu.sh --migrate --target=8.5   escolhe o ramo de destino
#   sudo ./php2shell-ubuntu.sh --fix-perms   só padroniza permissões do site, sem mexer no PHP
#        opções: --web-root=/var/www/html --web-owner=ubuntu --writable=site/uploads (repetível);
#        com --check apenas mostra o plano
#
# Códigos de saída: 0 = sem problema encontrado, 1 = requer ação, 2 = erro de execução.

set -uo pipefail
export LC_ALL=C

CHECK_ONLY=0
MITIGATE=0
RESTART=1
LOG_FILE="${LOG_FILE:-/var/log/php2shell-fix.log}"
FIX_PERMS=0
WEB_ROOT="/var/www/html"
WEB_OWNER=""
WEB_GROUP="www-data"
WRITABLE_DIRS=()
OS_RELEASE="${OS_RELEASE:-/etc/os-release}"
PHP_ETC="${PHP_ETC:-/etc}"
MITIGATION_FILE="99-php2shell-mitigation.ini"
MIGRATE=0
TARGET="8.4"
BACKUP_DIR="${BACKUP_DIR:-/root}"

for arg in "$@"; do
    case "$arg" in
        --check)      CHECK_ONLY=1 ;;
        --mitigate)   MITIGATE=1 ;;
        --no-restart) RESTART=0 ;;
        --migrate)    MIGRATE=1 ;;
        --target=*)   TARGET="${arg#--target=}" ;;
        --fix-perms)  FIX_PERMS=1 ;;
        --web-root=*) WEB_ROOT="${arg#--web-root=}" ;;
        --web-owner=*) WEB_OWNER="${arg#--web-owner=}" ;;
        --writable=*) WRITABLE_DIRS+=("${arg#--writable=}") ;;
        -h|--help)    sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            echo "Opção desconhecida: $arg (use --help)" >&2; exit 2 ;;
    esac
done

if [ "$CHECK_ONLY" -eq 1 ] && [ "$MITIGATE" -eq 1 ]; then
    echo "--check e --mitigate não podem ser usados juntos." >&2
    exit 2
fi
if [ "$MIGRATE" -eq 1 ] && [ "$RESTART" -eq 0 ]; then
    echo "--migrate e --no-restart não podem ser usados juntos." >&2
    exit 2
fi
case "$TARGET" in
    8.2|8.3|8.4|8.5) ;;
    *) echo "--target deve ser 8.2, 8.3, 8.4 ou 8.5." >&2; exit 2 ;;
esac

info() { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
vuln() { printf '[VULN] %s\n' "$*"; }
die()  { printf '[ERRO] %s\n' "$*" >&2; exit 2; }

ubuntu_fixed_version() {
    case "$1:$2" in
        stonking:php8.5) echo "8.5.9-0ubuntu2.1" ;;
        resolute:php8.5) echo "8.5.4-0ubuntu1.5" ;;
        noble:php8.3)    echo "8.3.6-0ubuntu0.24.04.13" ;;
        jammy:php8.1)    echo "8.1.2-1ubuntu2.28" ;;
        focal:php7.4)    echo "7.4.3-4ubuntu2.29+esm5" ;;
        bionic:php7.2)   echo "7.2.24-0ubuntu0.18.04.17+esm14" ;;
        xenial:php7.0)   echo "7.0.33-0ubuntu0.16.04.16+esm22" ;;
        trusty:php5)     echo "5.5.9+dfsg-1ubuntu4.29+esm18" ;;
    esac
}

upstream_fixed_version() {
    case "$1" in
        8.5) echo "8.5.12" ;;
        8.4) echo "8.4.27" ;;
        8.3) echo "8.3.36" ;;
        8.2) echo "8.2.35" ;;
    esac
}

# Devolve OK, VULN ou UNKNOWN para um pacote. Na dúvida nunca devolve OK.
classify_package() {
    local source_pkg="$1" version="$2" fixed branch upstream
    branch="${source_pkg#php}"
    upstream="${version#*:}"
    upstream="${upstream%%-*}"

    case "$version" in
        *deb.sury.org*) ;;
        *ubuntu*)
            fixed="$(ubuntu_fixed_version "$CODENAME" "$source_pkg")"
            if [ -z "$fixed" ]; then
                echo UNKNOWN
            elif dpkg --compare-versions "$version" ge "$fixed"; then
                echo OK
            else
                echo VULN
            fi
            return
            ;;
    esac

    fixed="$(upstream_fixed_version "$branch")"
    if [ -z "$fixed" ]; then
        echo UNKNOWN
    elif dpkg --compare-versions "$upstream" ge "$fixed~"; then
        echo OK
    else
        case "$version" in
            *deb.sury.org*) echo VULN ;;
            *)              echo UNKNOWN ;;
        esac
    fi
}

# Considera só binários do código-fonte do PHP: php-common e php-xdebug, por exemplo, ficam de fora.
list_php_packages() {
    dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}|${source:Package}\n' 2>/dev/null |
        awk -F'|' '$1 ~ /^.i/ && $4 ~ /^php(5|[0-9]+\.[0-9]+)$/ { print $2 "|" $3 "|" $4 }'
}

candidate_version() {
    apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/ { print $2; exit }'
}

VULNERABLE=()
UNKNOWN=()

analyze_packages() {
    local pkg version source_pkg status total=0
    VULNERABLE=()
    UNKNOWN=()
    while IFS='|' read -r pkg version source_pkg; do
        [ -n "$pkg" ] || continue
        total=$((total + 1))
        status="$(classify_package "$source_pkg" "$version")"
        case "$status" in
            OK)   ok "$pkg $version" ;;
            VULN) vuln "$pkg $version"; VULNERABLE+=("$pkg|$source_pkg") ;;
            *)    warn "$pkg $version: correção não verificável"; UNKNOWN+=("$pkg") ;;
        esac
    done < <(list_php_packages)
    [ "$total" -gt 0 ] || info "Nenhum pacote PHP instalado via apt."
}

# PHP compilado ou de painel não é atualizado por apt: aqui só reportamos.
OTHER_PROBLEMS=0
scan_other_installs() {
    local bin version branch fixed found=0
    local candidates=(/usr/local/bin/php /usr/local/sbin/php-fpm /usr/local/php*/bin/php
        /opt/*/bin/php /opt/plesk/php/*/bin/php /opt/cpanel/ea-php*/root/usr/bin/php
        /usr/local/lsws/lsphp*/bin/php /www/server/php/*/bin/php /snap/bin/php)
    for bin in "${candidates[@]}"; do
        [ -x "$bin" ] && [ -f "$bin" ] || continue
        dpkg -S "$(readlink -f "$bin")" >/dev/null 2>&1 && continue
        found=1
        version="$("$bin" -n -v 2>/dev/null | awk 'NR==1 { print $2 }')"
        version="${version%%-*}"
        branch="$(printf '%s' "$version" | cut -d. -f1,2)"
        fixed="$(upstream_fixed_version "$branch")"
        if [ -n "$fixed" ] && dpkg --compare-versions "$version" ge "$fixed"; then
            ok "$bin ${version:-?} (fora do apt)"
        else
            warn "$bin ${version:-?} (fora do apt): atualize manualmente ou confirme backport com o fornecedor"
            OTHER_PROBLEMS=$((OTHER_PROBLEMS + 1))
        fi
    done
    [ "$found" -eq 1 ] || info "Nenhuma instalação de PHP fora do apt nos caminhos conhecidos."

    if command -v docker >/dev/null 2>&1; then
        local containers
        containers="$(docker ps --format '{{.Names}} ({{.Image}})' 2>/dev/null | grep -i 'php\|wordpress\|nextcloud\|drupal\|joomla' || true)"
        if [ -n "$containers" ]; then
            warn "Contêineres que provavelmente têm PHP próprio (este script não os atualiza):"
            printf '       %s\n' "$containers"
            OTHER_PROBLEMS=$((OTHER_PROBLEMS + 1))
        fi
    fi
}

# Valor efetivo aproximado: pools do FPM e configs do Apache ainda podem sobrescrever.
upload_progress_value() {
    local dir="$1"
    cat "$dir/php.ini" "$dir"/conf.d/*.ini 2>/dev/null |
        awk -F= 'tolower($1) ~ /^[ \t]*session\.upload_progress\.enabled[ \t]*$/ { v=$2 }
                 END { gsub(/[ \t\r"]/, "", v); print (v == "" ? "1" : tolower(v)) }'
}

sapi_dirs() {
    local dir
    local installed source_pkg
    installed="$(list_php_packages | cut -d'|' -f3 | sort -u)"
    for dir in "$PHP_ETC"/php/*/fpm "$PHP_ETC"/php/*/apache2 "$PHP_ETC"/php/*/cgi \
               "$PHP_ETC"/php5/fpm "$PHP_ETC"/php5/apache2 "$PHP_ETC"/php5/cgi; do
        [ -d "$dir" ] || continue
        # Pacote removido deixa /etc/php para trás, mas não há mais PHP para proteger.
        case "$dir" in
            "$PHP_ETC"/php5/*) source_pkg="php5" ;;
            *) source_pkg="${dir#"$PHP_ETC"/php/}"; source_pkg="php${source_pkg%%/*}" ;;
        esac
        printf '%s\n' "$installed" | grep -qxF "$source_pkg" && echo "$dir"
    done
}

eol_branches() {
    list_php_packages | cut -d'|' -f3 | sort -u | grep -E '^php(5|7\.[0-9]+|8\.[01])$'
}

# Inclui extensões de outras origens (php8.1-redis vem de php-redis), que também precisam migrar.
list_branch_packages() {
    local escaped="${1//./\\.}"
    dpkg-query -W -f='${db:Status-Abbrev}|${Package}|\n' 2>/dev/null |
        awk -F'|' '$1 ~ /^.i/ { print $2 }' |
        grep -E "^(${escaped}(-.*)?|libapache2-mod-${escaped}|lib${escaped}-embed)\$"
}

copy_php_settings() {
    local old_dir="$1" new_dir="$2" key value
    [ -f "$old_dir/php.ini" ] && [ -d "$new_dir" ] || return 0
    mkdir -p "$new_dir/conf.d"
    : > "$new_dir/conf.d/90-php2shell-migrated.ini"
    # Só limites e fuso: copiar o php.ini inteiro traria diretivas que não existem no ramo novo.
    for key in memory_limit upload_max_filesize post_max_size max_execution_time max_input_time max_input_vars date.timezone; do
        value="$(awk -F= -v k="$key" '{ n=$1; gsub(/[ \t]/, "", n) } n == k { v=$0 } END { print v }' "$old_dir/php.ini")"
        [ -z "$value" ] || printf '%s\n' "$value" >> "$new_dir/conf.d/90-php2shell-migrated.ini"
    done
}

update_web_configs() {
    local source_pkg="$1" branch="${1#php}" file
    grep -rlE "${source_pkg//./\\.}-fpm|/php/${branch//./\\.}/" "$PHP_ETC/nginx" "$PHP_ETC/apache2" 2>/dev/null |
    while read -r file; do
        sed -i -e "s#/var/run/php5-fpm\.sock#/run/php/php$TARGET-fpm.sock#g" \
               -e "s#${source_pkg//./\\.}-fpm#php$TARGET-fpm#g" \
               -e "s#/php/${branch//./\\.}/#/php/$TARGET/#g" "$file"
        info "Configuração ajustada: $file"
    done
}

test_web_configs() {
    if systemctl is-active --quiet nginx && ! nginx -t >/dev/null 2>&1; then
        warn "nginx -t falhou."
        return 1
    fi
    if systemctl is-active --quiet apache2 && ! apache2ctl configtest >/dev/null 2>&1; then
        warn "apache2ctl configtest falhou."
        return 1
    fi
    return 0
}

ensure_target_available() {
    local candidate
    candidate="$(candidate_version "php$TARGET-cli")"
    if [ -n "$candidate" ] && [ "$candidate" != "(none)" ] &&
       [ "$(classify_package "php$TARGET" "$candidate")" = "OK" ]; then
        return 0
    fi
    info "PHP $TARGET corrigido não está no apt. Adicionando o PPA de terceiros ondrej/php..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=120 software-properties-common ||
        warn "Falha ao instalar software-properties-common."
    # add-apt-repository falha com nomes não ASCII se o locale for C.
    LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php || warn "Falha ao adicionar o PPA ondrej/php."
    apt-get update -qq -o DPkg::Lock::Timeout=120 || warn "apt-get update teve erros."
    candidate="$(candidate_version "php$TARGET-cli")"
    [ -n "$candidate" ] && [ "$candidate" != "(none)" ] &&
        [ "$(classify_package "php$TARGET" "$candidate")" = "OK" ]
}

# Pacotes genéricos do PPA (php-xmlrpc, por exemplo) puxam o ramo mais novo. O pin evita isso
# só durante a migração: é removido ao final, mesmo em caso de erro.
PIN_FILE="$PHP_ETC/apt/preferences.d/php2shell-pin"
PIN_CREATED=0
pin_newer_branches() {
    local minor="${TARGET#8.}" next
    next=$((minor + 1))
    # Com pin, um ramo mais novo já instalado deixaria de receber atualizações de segurança.
    if list_php_packages | cut -d'|' -f3 | grep -qE "^php(8\.[$next-9]|9\.)"; then
        warn "Há PHP mais novo que $TARGET instalado: pin não criado."
        return 0
    fi
    mkdir -p "${PIN_FILE%/*}"
    trap remove_pin EXIT
    printf 'Package: /^(php|libapache2-mod-php|libphp)(8\\.[%s-9]|9\\.)/\nPin: version *\nPin-Priority: -1\n' "$next" > "$PIN_FILE" ||
        die "Falha ao gravar $PIN_FILE"
    PIN_CREATED=1
    info "Ramos mais novos que PHP $TARGET não serão instalados nesta migração."
}

remove_pin() {
    [ "$PIN_CREATED" -eq 0 ] || rm -f "$PIN_FILE"
    PIN_CREATED=0
}

# Padrão: dono $WEB_OWNER (quem sobe os arquivos), grupo www-data só para leitura, pastas 755
# e arquivos 644, com estas exceções:
#   .env 640 (tem senhas); scripts com shebang 755 (artisan, bin/console);
#   pastas de --writable 2775 e seu conteúdo 664: únicos lugares em que a aplicação grava,
#   com regra do Apache que impede executar PHP nelas (block_php_in_writable).
# Cada WordPress tem padrão próprio, pois precisa gravar para atualizar pelo painel:
#   pastas 2775, arquivos 664 e wp-config.php 640.
fix_permissions() {
    local root owner tmp file snapshot dir resolved wp_dirs writable=() not_wp=() blocked=() result=0
    root="$(readlink -f "$WEB_ROOT")"
    [ -d "$root" ] || die "Pasta não encontrada: $WEB_ROOT"
    case "$root" in
        /|/var|/var/www|/home|/etc|/usr|/root|/opt|/srv) die "Pasta ampla demais para alterar: $root" ;;
    esac
    owner="$WEB_OWNER"
    if [ -z "$owner" ]; then
        owner="${SUDO_USER:-ubuntu}"
        [ "$owner" != "root" ] || owner="ubuntu"
    fi
    id "$owner" >/dev/null 2>&1 || die "Usuário '$owner' não existe. Informe com --web-owner=USUARIO."
    getent group "$WEB_GROUP" >/dev/null 2>&1 || die "Grupo $WEB_GROUP não existe. O Apache está instalado?"

    # wp-settings.php fica sempre na raiz de uma instalação do WordPress.
    wp_dirs="$(find "$root" -type f -name wp-settings.php -printf '%h\n' | sort -u)"
    while read -r dir; do
        [ -n "$dir" ] || continue
        not_wp+=(-not -path "$dir/*")
    done <<< "$wp_dirs"

    for dir in ${WRITABLE_DIRS[@]+"${WRITABLE_DIRS[@]}"}; do
        case "$dir" in
            /*) resolved="$(readlink -f "$dir")" ;;
            *)  resolved="$(readlink -f "$root/$dir")" ;;
        esac
        [ -d "$resolved" ] || die "--writable: pasta não encontrada: $dir"
        case "$resolved" in
            *\"*|*$'\n'*) die "--writable: caminho com caractere não suportado: $dir" ;;
            "$root"/*) writable+=("$resolved") ;;
            *) die "--writable: a pasta precisa estar dentro de $root, e não ser ela própria: $dir" ;;
        esac
    done
    blocked=(${writable[@]+"${writable[@]}"})

    tmp="$(mktemp -d)" || die "Falha ao criar pasta temporária."
    trap 'rm -rf "$tmp"' RETURN

    # Listas feitas antes do chown e do chmod, que apagam essas informações.
    # Fora do WordPress: em 755, o www-data não conseguiria sobrescrever o arquivo ao atualizar um plugin.
    find "$root" -type f -perm /111 ${not_wp[@]+"${not_wp[@]}"} -print0 | while IFS= read -r -d '' file; do
        [ "$(head -c2 "$file" 2>/dev/null)" = "#!" ] && printf '%s\0' "$file"
    done > "$tmp/scripts"
    find "$root" -type f \( -name .env -o -name '.env.*' -o -name wp-config.php \) -print0 > "$tmp/secrets"

    info "Pasta: $root | dono: $owner | grupo: $WEB_GROUP"
    info "WordPress (pastas 2775, arquivos 664):"
    printf '%s\n' "${wp_dirs:-nenhum}" | sed 's/^/       /'
    info "Pastas de --writable (2775, PHP bloqueado no Apache): ${#writable[@]}"
    for dir in ${writable[@]+"${writable[@]}"}; do
        printf '       %s\n' "$dir"
    done
    # O que o Apache criou até hoje é o melhor indício de onde a aplicação grava.
    info "Pastas com arquivos do www-data, que perdem a escrita se não estiverem em --writable (até 20):"
    find "$root" -type f -user "$WEB_GROUP" ${not_wp[@]+"${not_wp[@]}"} -printf '%h\n' | sort -u | head -n 20 | sed 's/^/       /'
    info "Scripts executáveis (755): $(tr -cd '\0' < "$tmp/scripts" | wc -c)"
    info "Arquivos .env e wp-config.php (640): $(tr -cd '\0' < "$tmp/secrets" | wc -c)"

    if [ "$CHECK_ONLY" -eq 1 ]; then
        info "--check: nada foi alterado."
        return 0
    fi

    snapshot="$BACKUP_DIR/permissoes-$(date +%Y%m%d%H%M%S).txt"
    find "$root" -printf '%m %u %g %p\n' > "$snapshot" || die "Falha ao gravar $snapshot. Nada foi alterado."
    ok "Permissões anteriores guardadas em $snapshot"

    [ "$owner" = "$WEB_GROUP" ] || usermod -aG "$WEB_GROUP" "$owner" || die "Falha ao adicionar $owner ao grupo $WEB_GROUP."
    chown -R "$owner:$WEB_GROUP" "$root" || die "Falha no chown."
    # 00755, e não 755: com 755 o chmod preserva o setgid de quem já estava em 2775.
    find "$root" -type d -exec chmod 00755 {} + || die "Falha ao ajustar pastas."
    find "$root" -type f -exec chmod 644 {} + || die "Falha ao ajustar arquivos."
    while read -r dir; do
        [ -n "$dir" ] || continue
        writable+=("$dir")
    done <<< "$wp_dirs"
    for dir in ${writable[@]+"${writable[@]}"}; do
        find "$dir" -type d -exec chmod 2775 {} +
        find "$dir" -type f -exec chmod 664 {} +
    done
    xargs -0 -r chmod 755 < "$tmp/scripts"
    xargs -0 -r chmod 640 < "$tmp/secrets"
    ok "Permissões aplicadas. Saia e entre de novo no SSH para o grupo de $owner valer."

    # O WordPress compara o dono dos arquivos com quem o executa e, sem isto, pede FTP para atualizar.
    while read -r dir; do
        [ -n "$dir" ] || continue
        grep -qs "FS_METHOD" "$dir/wp-config.php" "${dir%/*}/wp-config.php" ||
            warn "$dir: adicione ao wp-config.php: define('FS_METHOD','direct'); define('FS_CHMOD_DIR',02775); define('FS_CHMOD_FILE',0664);"
    done <<< "$wp_dirs"

    if [ "${#blocked[@]}" -gt 0 ]; then
        block_php_in_writable "${blocked[@]}" || result=1
    fi
    return "$result"
}

# Mantém as pastas de execuções anteriores, para rodar com outro --writable não desproteger as antigas.
# AllowOverride None: quem envia arquivos para a pasta não pode desfazer a regra com um .htaccess.
block_php_in_writable() {
    local conf="$PHP_ETC/apache2/conf-available/php2shell-writable.conf"
    local name="php2shell-writable" tmp_conf dir was_enabled=0 previous=""
    if ! command -v apache2ctl >/dev/null 2>&1 || ! command -v a2enconf >/dev/null 2>&1; then
        warn "Apache não encontrado: a regra que bloqueia PHP nas pastas de --writable NÃO foi criada."
        return 1
    fi
    [ -e "$PHP_ETC/apache2/conf-enabled/$name.conf" ] && was_enabled=1
    tmp_conf="$(mktemp)" || { warn "Falha ao criar arquivo temporário: regra do Apache NÃO criada."; return 1; }
    if [ -f "$conf" ]; then
        previous="$(cat "$conf")"
    fi
    {
        echo "# Gerado por php2shell-ubuntu.sh --writable. Impede executar ou baixar PHP nestas pastas."
        { printf '%s\n' "$@"; printf '%s\n' "$previous" | sed -n 's/^<Directory "\(.*\)">$/\1/p'; } | sort -u |
        while IFS= read -r dir; do
            [ -d "$dir" ] || continue
            printf '<Directory "%s">\n' "$dir"
            printf '    AllowOverride None\n    Options -ExecCGI -Includes\n'
            printf '    <FilesMatch "(?i)\\.(php[0-9]*|phtml|phar|phps|pht)$">\n'
            printf '        Require all denied\n    </FilesMatch>\n</Directory>\n'
        done
    } > "$tmp_conf"
    mkdir -p "${conf%/*}"
    cp "$tmp_conf" "$conf"; rm -f "$tmp_conf"
    chmod 644 "$conf"

    if ! a2enconf -q "$name" >/dev/null 2>&1 || ! apache2ctl configtest >/dev/null 2>&1; then
        if [ -n "$previous" ]; then
            printf '%s\n' "$previous" > "$conf"
        else
            rm -f "$conf"
        fi
        [ "$was_enabled" -eq 1 ] || a2disconf -q "$name" >/dev/null 2>&1
        warn "Configuração do Apache inválida: regra de $name revertida, PHP NÃO bloqueado nas pastas de --writable."
        return 1
    fi
    if systemctl is-active --quiet apache2; then
        if ! systemctl reload apache2; then
            warn "Falha ao recarregar o Apache: a regra $conf ainda não vale."
            return 1
        fi
    fi
    ok "PHP bloqueado no Apache para as pastas de --writable: $conf"
    return 0
}

rollback_apache() {
    local backup="$1" branches="$2" source_pkg
    a2dismod -q "php$TARGET" >/dev/null 2>&1 || true
    a2disconf -q "php$TARGET-fpm" >/dev/null 2>&1 || true
    tar -xzPf "$backup" $(for d in nginx apache2; do [ -d "$PHP_ETC/$d" ] && echo "$PHP_ETC/$d"; done)
    for source_pkg in $branches; do
        if [ -n "$(list_branch_packages "$source_pkg" | grep libapache2-mod)" ]; then
            a2enmod -q "$source_pkg" >/dev/null 2>&1 || true
        fi
        if [ -n "$(list_branch_packages "$source_pkg" | grep -- '-fpm$')" ]; then
            systemctl enable --now "$source_pkg-fpm" >/dev/null 2>&1 || true
            a2enconf -q "$source_pkg-fpm" >/dev/null 2>&1 || true
        fi
    done
    if systemctl restart apache2 && systemctl is-active --quiet apache2; then
        ok "Apache restaurado com o ramo antigo."
    else
        warn "Apache não voltou. Veja: systemctl status apache2 e journalctl -xeu apache2"
    fi
}

MIGRATION_FAILED=0
migrate_eol() {
    local branches source_pkg pkg new_pkg candidate branch backup removal blockers
    local new_packages=("php$TARGET-cli") old_packages=() required_failed=0
    branches="$(eol_branches)"
    if [ -z "$branches" ]; then
        info "Nenhum PHP sem suporte (8.1 ou anterior) instalado via apt: nada a migrar."
        return 0
    fi

    if [ "$CHECK_ONLY" -eq 1 ]; then
        for source_pkg in $branches; do
            info "Com --migrate: $source_pkg seria substituído por php$TARGET, e seus pacotes removidos:"
            list_branch_packages "$source_pkg" | sed 's/^/       /'
        done
        return 0
    fi

    ensure_target_available || {
        vuln "PHP $TARGET corrigido indisponível para $CODENAME. Migração cancelada; nada foi trocado."
        MIGRATION_FAILED=1
        return 1
    }
    pin_newer_branches

    for source_pkg in $branches; do
        while read -r pkg; do
            [ -n "$pkg" ] || continue
            old_packages+=("$pkg")
            new_pkg="${pkg/$source_pkg/php$TARGET}"
            candidate="$(candidate_version "$new_pkg")"
            if [ -z "$candidate" ] || [ "$candidate" = "(none)" ]; then
                warn "$pkg não tem equivalente no PHP $TARGET: a extensão ficará ausente."
            elif apt-get -s install "$new_pkg" >/dev/null 2>&1; then
                new_packages+=("$new_pkg")
            else
                # Com o pin, a instalação falha se o pacote exigir um ramo mais novo.
                warn "$new_pkg não pode ser instalado sem um PHP mais novo: a extensão ficará ausente."
                case "$new_pkg" in
                    *-cli|*-fpm|libapache2-mod-*) required_failed=1 ;;
                esac
            fi
        done < <(list_branch_packages "$source_pkg")
    done
    if [ "$required_failed" -eq 1 ]; then
        vuln "Pacote essencial do PHP $TARGET não pode ser instalado. Migração cancelada; nada foi trocado."
        remove_pin
        MIGRATION_FAILED=1
        return 1
    fi

    backup="$BACKUP_DIR/php2shell-config-$(date +%Y%m%d%H%M%S).tar.gz"
    tar -czPf "$backup" $(for d in php php5 nginx apache2; do [ -d "$PHP_ETC/$d" ] && echo "$PHP_ETC/$d"; done) ||
        { vuln "Falha no backup de configurações. Migração cancelada."; remove_pin; MIGRATION_FAILED=1; return 1; }
    ok "Backup das configurações: $backup"

    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=120 \
        -o Dpkg::Options::=--force-confold "${new_packages[@]}"; then
        vuln "Falha ao instalar PHP $TARGET. O ramo antigo foi mantido."
        remove_pin
        MIGRATION_FAILED=1
        return 1
    fi
    PACKAGES_CHANGED=1

    for source_pkg in $branches; do
        branch="${source_pkg#php}"
        for sapi in fpm apache2 cgi cli; do
            if [ "$source_pkg" = "php5" ]; then
                copy_php_settings "$PHP_ETC/php5/$sapi" "$PHP_ETC/php/$TARGET/$sapi"
            else
                copy_php_settings "$PHP_ETC/php/$branch/$sapi" "$PHP_ETC/php/$TARGET/$sapi"
            fi
        done
        if [ -d "$PHP_ETC/php/$branch/fpm/pool.d" ] && [ -d "$PHP_ETC/php/$TARGET/fpm/pool.d" ]; then
            for pkg in "$PHP_ETC/php/$branch/fpm/pool.d"/*.conf; do
                [ -f "$pkg" ] || continue
                sed -e "s#php${branch//./\\.}-fpm#php$TARGET-fpm#g" \
                    "$pkg" > "$PHP_ETC/php/$TARGET/fpm/pool.d/${pkg##*/}"
            done
        fi
        update_web_configs "$source_pkg"
    done

    if command -v "php-fpm$TARGET" >/dev/null 2>&1 && ! "php-fpm$TARGET" -t >/dev/null 2>&1; then
        vuln "php-fpm$TARGET -t falhou. O ramo antigo foi mantido; o backup está em $backup."
        tar -xzPf "$backup" $(for d in nginx apache2; do [ -d "$PHP_ETC/$d" ] && echo "$PHP_ETC/$d"; done)
        MIGRATION_FAILED=1
        return 1
    fi
    if ! test_web_configs; then
        vuln "Configuração do servidor web inválida: restaurada do backup e ramo antigo mantido."
        tar -xzPf "$backup" $(for d in nginx apache2; do [ -d "$PHP_ETC/$d" ] && echo "$PHP_ETC/$d"; done)
        MIGRATION_FAILED=1
        return 1
    fi

    local apache_was_active=0
    systemctl is-active --quiet apache2 && apache_was_active=1

    for source_pkg in $branches; do
        branch="${source_pkg#php}"
        systemctl disable --now "php$branch-fpm" "$source_pkg-fpm" >/dev/null 2>&1 || true
        if command -v a2dismod >/dev/null 2>&1; then
            a2dismod -q "$source_pkg" >/dev/null 2>&1 || true
            a2disconf -q "$source_pkg-fpm" >/dev/null 2>&1 || true
        fi
    done
    if command -v a2enmod >/dev/null 2>&1; then
        [ -n "$(list_branch_packages "php$TARGET" | grep libapache2-mod)" ] && a2enmod -q "php$TARGET" >/dev/null 2>&1
        [ -n "$(list_branch_packages "php$TARGET" | grep -- '-fpm$')" ] && a2enconf -q "php$TARGET-fpm" >/dev/null 2>&1
    fi
    systemctl restart "php$TARGET-fpm" >/dev/null 2>&1 || true
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx || warn "Falha ao recarregar o nginx."
    fi
    # A troca de módulo só pode ser validada aqui; antes de remover o ramo antigo o Apache precisa subir.
    if [ "$apache_was_active" -eq 1 ]; then
        if ! apache2ctl configtest >/dev/null 2>&1 || ! systemctl restart apache2 ||
           ! systemctl is-active --quiet apache2; then
            vuln "Apache não subiu com PHP $TARGET. Revertendo para o ramo antigo; o backup está em $backup."
            rollback_apache "$backup" "$branches"
            MIGRATION_FAILED=1
            return 1
        fi
        ok "Apache ativo com PHP $TARGET."
    fi

    update-alternatives --set php "/usr/bin/php$TARGET" >/dev/null 2>&1 || true
    update-alternatives --set php-fpm.sock "/run/php/php$TARGET-fpm.sock" >/dev/null 2>&1 || true

    # remove, e não purge: mantém /etc/php antigo como referência para ajustar as apps.
    removal="$(apt-get -s remove "${old_packages[@]}" 2>/dev/null | awk '/^Remv / { print $2 }')"
    blockers="$(printf '%s\n' "$removal" | grep -vE '^(php|libapache2-mod-php|libphp|$)' || true)"
    if [ -n "$blockers" ]; then
        warn "Ramo antigo desativado, mas NÃO removido: a remoção levaria outros pacotes junto:"
        printf '       %s\n' $blockers
        warn "Avalie esses pacotes e remova manualmente: apt-get remove ${old_packages[*]}"
    elif DEBIAN_FRONTEND=noninteractive apt-get remove -y -o DPkg::Lock::Timeout=120 "${old_packages[@]}"; then
        ok "Ramo antigo removido; as configurações continuam em $PHP_ETC/php."
    else
        warn "Falha ao remover o ramo antigo."
    fi

    # Agendamentos com caminho fixo continuariam chamando o binário antigo, se ele não foi removido.
    for source_pkg in $branches; do
        grep -rl "/$source_pkg\b" "$PHP_ETC"/cron* "$PHP_ETC/supervisor" 2>/dev/null | sed "s#^#[WARN] Referência a $source_pkg: #"
    done
    ok "Migração para PHP $TARGET concluída. Teste as aplicações."
}

MITIGATION_CHANGED=0
check_upload_progress() {
    local dir value
    while read -r dir; do
        [ -n "$dir" ] || continue
        value="$(upload_progress_value "$dir")"
        case "$value" in
            0|off|no|false|none)
                ok "$dir: session.upload_progress desativado"
                ;;
            *)
                if [ "$MITIGATE" -eq 1 ]; then
                    mkdir -p "$dir/conf.d"
                    printf '; CVE-2026-115560: remover após o próximo bugfix release do PHP\nsession.upload_progress.enabled = 0\n' \
                        > "$dir/conf.d/$MITIGATION_FILE" || die "Falha ao gravar mitigação em $dir"
                    ok "$dir: session.upload_progress desativado agora"
                    MITIGATION_CHANGED=1
                else
                    warn "$dir: session.upload_progress ativo (use --mitigate; relevante para CVE-2026-115560)"
                fi
                ;;
        esac
    done < <(sapi_dirs)
}

# Processos antigos continuam vulneráveis mesmo com o pacote novo em disco.
find_stale_processes() {
    local proc exe pid
    for proc in /proc/[0-9]*; do
        pid="${proc#/proc/}"
        exe="$(readlink "$proc/exe" 2>/dev/null || true)"
        case "$exe" in
            *php*"(deleted)") echo "$pid $exe"; continue ;;
        esac
        if grep -q 'libphp.*(deleted)' "$proc/maps" 2>/dev/null; then
            echo "$pid $exe (libphp antiga)"
        fi
    done
}

restart_services() {
    local unit
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemd não encontrado: reinicie PHP-FPM e Apache manualmente."
        return
    fi
    while read -r unit; do
        [ -n "$unit" ] || continue
        if systemctl restart "$unit"; then
            ok "Reiniciado: $unit"
        else
            warn "Falha ao reiniciar $unit"
        fi
    done < <(systemctl list-units --type=service --state=running --no-legend --plain 'php*-fpm*' 2>/dev/null | awk '{ print $1 }')

    if systemctl is-active --quiet apache2 && dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | grep -q '^.i.* libapache2-mod-php'; then
        if ! apache2ctl configtest >/dev/null 2>&1; then
            warn "apache2ctl configtest falhou: Apache NÃO reiniciado. Corrija a configuração e reinicie."
        elif systemctl restart apache2; then
            ok "Reiniciado: apache2"
        else
            warn "Falha ao reiniciar apache2"
        fi
    fi
}

print_no_fix_hint() {
    case "$CODENAME" in
        focal|bionic|xenial|trusty)
            warn "No Ubuntu $CODENAME a correção vem do Ubuntu Pro (ESM). Verifique: pro status"
            warn "Sem assinatura ativa: sudo pro attach <token>"
            ;;
        *)
            warn "A correção não está no apt. Verifique sources.list, repositórios desativados e pacotes retidos (apt-mark showhold)."
            ;;
    esac
}

# ---------- Início ----------

command -v dpkg-query >/dev/null 2>&1 || die "Este script requer Ubuntu (dpkg não encontrado)."
[ -r "$OS_RELEASE" ] || die "Não foi possível ler $OS_RELEASE."
CODENAME="$(. "$OS_RELEASE"; echo "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}")"
DISTRO="$(. "$OS_RELEASE"; echo "${ID:-}")"
DISTRO_NAME="$(. "$OS_RELEASE"; echo "${PRETTY_NAME:-}")"
[ "$DISTRO" = "ubuntu" ] || die "Sistema não suportado: ${DISTRO_NAME:-desconhecido}."
[ -n "$CODENAME" ] || die "Não foi possível identificar a versão do Ubuntu."

if [ "$(id -u)" -ne 0 ]; then
    [ "$CHECK_ONLY" -eq 1 ] || die "Execute com sudo, ou use --check para apenas analisar."
    warn "Sem root: a busca por processos antigos pode ficar incompleta."
elif [ "$CHECK_ONLY" -eq 0 ] && : >> "$LOG_FILE" 2>/dev/null; then
    exec > >(tee -a "$LOG_FILE") 2>&1
    info "Registro em $LOG_FILE - $(date '+%F %T')"
fi

info "Sistema: $DISTRO_NAME ($CODENAME)"
if [ "$FIX_PERMS" -eq 1 ]; then
    fix_permissions
    exit $?
fi
if [ "$CHECK_ONLY" -eq 0 ]; then
    info "Atualizando índices do apt..."
    apt-get update -qq -o DPkg::Lock::Timeout=120 || warn "apt-get update teve erros: os candidatos podem estar defasados."
fi

echo
info "=== Pacotes PHP ==="
analyze_packages
echo
info "=== Outras instalações ==="
scan_other_installs

PACKAGES_CHANGED=0
NOT_FIXABLE=()
if [ "${#VULNERABLE[@]}" -gt 0 ]; then
    echo
    info "=== Atualização ==="
    TO_UPGRADE=()
    for entry in "${VULNERABLE[@]}"; do
        pkg="${entry%%|*}"
        source_pkg="${entry##*|}"
        candidate="$(candidate_version "$pkg")"
        if [ -n "$candidate" ] && [ "$candidate" != "(none)" ] &&
           [ "$(classify_package "$source_pkg" "$candidate")" = "OK" ]; then
            TO_UPGRADE+=("$pkg")
            info "$pkg -> $candidate"
        else
            vuln "$pkg: sem versão corrigida disponível (candidato: ${candidate:-nenhum})"
            NOT_FIXABLE+=("$pkg")
        fi
    done

    if [ "${#NOT_FIXABLE[@]}" -gt 0 ]; then
        print_no_fix_hint
    fi

    if [ "${#TO_UPGRADE[@]}" -gt 0 ] && [ "$CHECK_ONLY" -eq 0 ]; then
        # --force-confold preserva php.ini e demais configurações alteradas.
        if DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade \
            -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confold "${TO_UPGRADE[@]}"; then
            PACKAGES_CHANGED=1
        else
            warn "apt-get retornou erro na atualização."
        fi
        echo
        info "=== Verificação após atualizar ==="
        analyze_packages
    fi
fi

# Vem depois da atualização: se a migração falhar, o 8.1 do Ubuntu já está com o patch.
if [ "$MIGRATE" -eq 1 ]; then
    echo
    info "=== Migração de ramo para PHP $TARGET ==="
    migrate_eol
    remove_pin
    if [ "$CHECK_ONLY" -eq 0 ]; then
        echo
        info "=== Verificação após migrar ==="
        analyze_packages
    fi
fi

echo
info "=== CVE-2026-115560 (sem versão corrigida publicada) ==="
info "Afeta apps que trocam session.serialize_handler em tempo de execução com ini_set()."
check_upload_progress

echo
info "=== Processos em execução ==="
STALE="$(find_stale_processes)"
if [ "$CHECK_ONLY" -eq 0 ] && [ "$RESTART" -eq 1 ] &&
   { [ "$PACKAGES_CHANGED" -eq 1 ] || [ "$MITIGATION_CHANGED" -eq 1 ] || [ -n "$STALE" ]; }; then
    restart_services
    STALE="$(find_stale_processes)"
elif [ "$RESTART" -eq 0 ] && { [ "$PACKAGES_CHANGED" -eq 1 ] || [ "$MITIGATION_CHANGED" -eq 1 ]; }; then
    warn "--no-restart: a correção só vale depois de reiniciar PHP-FPM e Apache."
fi
if [ -n "$STALE" ]; then
    warn "Processos ainda usando PHP antigo (reinicie-os):"
    printf '       %s\n' "$STALE"
else
    ok "Nenhum processo usando binário PHP antigo."
fi

echo
info "=== Resultado ==="
RESULT=0
if [ "${#VULNERABLE[@]}" -gt 0 ]; then
    if [ "$CHECK_ONLY" -eq 1 ]; then
        vuln "${#VULNERABLE[@]} pacote(s) vulnerável(is). Execute sem --check para corrigir."
    else
        vuln "${#VULNERABLE[@]} pacote(s) continuam vulneráveis."
    fi
    RESULT=1
fi
if [ "${#UNKNOWN[@]}" -gt 0 ]; then
    warn "${#UNKNOWN[@]} pacote(s) sem correção verificável: migre para um PHP suportado ou confirme com o fornecedor."
    RESULT=1
fi
if [ "$OTHER_PROBLEMS" -gt 0 ]; then
    warn "$OTHER_PROBLEMS item(ns) fora do apt requerem verificação manual."
    RESULT=1
fi
if [ -n "$STALE" ] || [ "$MIGRATION_FAILED" -eq 1 ]; then
    RESULT=1
fi
if [ "$RESULT" -eq 0 ]; then
    ok "Nenhuma pendência para CVE-2026-109618 e CVE-2026-109619 nos itens verificados."
fi
exit "$RESULT"
