# php2shell-ubuntu.sh

Script para Ubuntu que analisa e corrige as vulnerabilidades **php2shell** do PHP (CVE-2026-109618 e CVE-2026-109619), migra versões sem suporte e padroniza as permissões dos sites.

> [!WARNING]
> Este script roda como root e altera pacotes, serviços e permissões. Ele é fornecido **sem garantia**, e o uso é por sua conta e risco.
> Tire um snapshot do servidor e rode `--check` antes. `--migrate` e `--fix-perms` podem derrubar aplicações: leia os [riscos de mudar a versão do PHP](#riscos-de-mudar-a-versão-do-php).

As versões corrigidas usadas pelo script são de **31/10/2026** e não são atualizadas sozinhas. Consulte as [fontes](#fontes) antes de usá-lo em uma data muito posterior.

## Início rápido

Copie o script para o servidor (fora de pastas públicas) e analise sem alterar nada:

```bash
sudo bash php2shell-ubuntu.sh --check
```

Aplique a correção:

```bash
sudo bash php2shell-ubuntu.sh
```

Se o PHP for 8.1 ou anterior, veja o plano de migração e depois execute:

```bash
sudo bash php2shell-ubuntu.sh --check --migrate
```

```bash
sudo bash php2shell-ubuntu.sh --migrate
```

Tire um snapshot do servidor antes de usar `--migrate` ou `--fix-perms`. O backup do script guarda só as configurações e a lista de permissões.

## Opções

| Opção | O que faz |
|---|---|
| *(sem opção)* | Analisa e atualiza pacotes vulneráveis no mesmo ramo, depois reinicia PHP-FPM e Apache |
| `--check` | Só analisa e mostra o plano, sem alterar nada |
| `--mitigate` | Também desativa `session.upload_progress` (CVE-2026-115560) |
| `--no-restart` | Não reinicia os serviços; a correção só vale depois de reiniciá-los |
| `--migrate` | Troca o PHP 8.1 ou anterior por um ramo com suporte e remove o antigo |
| `--target=8.5` | Define o ramo de destino do `--migrate`: 8.2, 8.3, 8.4 (padrão) ou 8.5 |
| `--fix-perms` | Só padroniza permissões, sem mexer no PHP |
| `--web-root=CAMINHO` | Pasta do `--fix-perms` (padrão: `/var/www/html`) |
| `--web-owner=USUARIO` | Dono dos arquivos (padrão: quem chamou o `sudo`, ou `ubuntu` se for root) |
| `--writable=PASTA` | Libera a escrita do Apache em uma pasta, relativa a `--web-root` ou absoluta, e bloqueia PHP nela; pode ser repetida |
| `--help` | Mostra a ajuda |

`--check` não pode ser combinado com `--mitigate`, nem `--migrate` com `--no-restart`.

## Correção do PHP

O Ubuntu aplica a correção mantendo o número antigo da versão. Por isso, `php -v` não confirma a correção nos pacotes padrão: o script compara a versão do pacote.

| Ubuntu | Pacote | Versão corrigida | Ubuntu Pro |
|---|---|---|---|
| 26.10 | `php8.5` | `8.5.9-0ubuntu2.1` | Não |
| 26.04 | `php8.5` | `8.5.4-0ubuntu1.5` | Não |
| 24.04 | `php8.3` | `8.3.6-0ubuntu0.24.04.13` | Não |
| 22.04 | `php8.1` | `8.1.2-1ubuntu2.28` | Não |
| 20.04 | `php7.4` | `7.4.3-4ubuntu2.29+esm5` | Sim |
| 18.04 | `php7.2` | `7.2.24-0ubuntu0.18.04.17+esm14` | Sim |
| 16.04 | `php7.0` | `7.0.33-0ubuntu0.16.04.16+esm22` | Sim, com Legacy Support |
| 14.04 | `php5` | `5.5.9+dfsg-1ubuntu4.29+esm18` | Sim, com Legacy Support |

Para o PPA `ondrej/php`, valem as versões oficiais: **8.5.12, 8.4.27, 8.3.36 e 8.2.35**.

O PHP compilado ou de painel (aaPanel, cPanel, Plesk) e os contêineres Docker só geram aviso: o script não os atualiza.

## Migração de versão (`--migrate`)

1. Aplica o patch no ramo atual, quando houver.
2. Adiciona o PPA de terceiros `ondrej/php`, se o apt não tiver o destino corrigido.
3. Salva as configurações em `/root/php2shell-config-<data>.tar.gz`.
4. Instala o novo ramo com as extensões equivalentes, evitando instalar ramos mais novos durante a migração.
5. Leva pools do FPM, limites do `php.ini` e referências ao socket no Apache e no Nginx.
6. Testa o servidor web e, se ele subir, remove o ramo antigo. Os arquivos de `/etc/php/<versão>` são mantidos.

Se o PPA ou a instalação falhar, se a configuração for inválida ou se o Apache não subir, o script mantém ou restaura o ramo antigo e termina com código `1`. Se a remoção levar pacotes que não são PHP, ele só desativa o ramo antigo e lista esses pacotes.

### Riscos de mudar a versão do PHP

> [!CAUTION]
> **Trocar de versão pode quebrar suas aplicações, e o script não detecta isso.** A reversão automática só cobre falhas de instalação e de subida do servidor web. Se o Apache subir, o script remove o ramo antigo mesmo que o site passe a mostrar erros, e ele não testa nenhuma aplicação.

O que costuma falhar ao sair de versões antigas:

- **Código removido ou mais rígido:** funções e sintaxes antigas deixam de existir, e chamadas que antes só geravam aviso podem virar erro fatal, deixando o site fora do ar ou com tela em branco. Quanto mais antiga a versão de origem, maior o risco; sair do PHP 5 ou 7 é bem mais arriscado que sair do 8.1.
- **Frameworks, CMS, temas, plugins e bibliotecas:** versões antigas podem não ser compatíveis com o ramo novo e precisar de atualização, o que às vezes exige mudar o próprio código.
- **Extensões ausentes:** algumas não existem no ramo novo. No PHP 8.4, por exemplo, `imap`, `pspell` e `oci8` saíram do núcleo do PHP. O script avisa e segue sem elas, e as funções da aplicação que dependem delas falham.
- **Componentes de terceiros:** carregadores como o ionCube e código criptografado ou compilado para uma versão específica podem não funcionar até haver uma versão compatível.
- **Avisos expostos:** novas mensagens de descontinuação podem aparecer nas páginas e revelar caminhos do servidor, se `display_errors` estiver ativo.
- **Tarefas fora do navegador:** cron, filas e scripts de linha de comando podem falhar sem que ninguém perceba.

**Antes de migrar em produção:**

1. Tire um snapshot do servidor e um backup do banco de dados.
2. Rode a aplicação no ramo de destino em uma cópia, se puder, e teste login, formulários, uploads, pagamentos e tarefas agendadas.
3. Atualize frameworks, plugins e dependências para versões compatíveis com o destino.
4. Escolha um horário de baixo movimento.

**Se a aplicação quebrar:** restaurar o snapshot é o caminho mais seguro. Reinstalar o ramo antigo só faz sentido como medida temporária e, se ele não tiver a correção das CVEs, deixa o servidor **vulnerável de novo**. Quando não for possível migrar logo, considere manter o pacote do Ubuntu com a correção, sem `--migrate`, nas versões em que ele existe (veja a [tabela](#correção-do-php)). Essa decisão troca o risco de quebrar agora pelo de continuar em um ramo sem suporte do projeto PHP.

**Depois de migrar:**

- Teste as aplicações e veja `/var/log/apache2/error.log`.
- Compare as extensões com `php -m`.
- Ajuste tarefas agendadas e o crontab dos usuários que chamem `/usr/bin/php8.1`.
- Ajuste referências ao socket antigo em `.htaccess`.
- Instale pacotes sempre com a versão no nome, como `php8.4-xmlrpc`. Pacotes genéricos, como `php-xmlrpc`, podem trazer um ramo mais novo.

## Permissões (`--fix-perms`)

O dono é o usuário que sobe os arquivos (normalmente `ubuntu`), e o grupo é `www-data`.

| Item | WordPress | Demais sites |
|---|---|---|
| Pastas | `2775` | `755` |
| Arquivos | `664` | `644` |
| `wp-config.php` / `.env` | `640` | `640` |
| Scripts com `#!` já executáveis | `664` | `755` |
| Pastas de `--writable` | `2775` / `664` | `2775` / `664` |

Cada WordPress é reconhecido pelo arquivo `wp-settings.php`, e todas as subpastas dele seguem o padrão do WordPress. O script recusa pastas amplas como `/` e `/var/www`, e salva as permissões anteriores em `/root/permissoes-<data>.txt`.

Veja o plano, que lista as instalações do WordPress e as pastas que perderiam a escrita:

```bash
sudo bash php2shell-ubuntu.sh --fix-perms --check
```

Aplique, indicando as exceções, se houver:

```bash
sudo bash php2shell-ubuntu.sh --fix-perms --writable=meusite/uploads
```

Depois de aplicar, saia e entre de novo no SSH para o grupo valer.

### WordPress

O script não edita o `wp-config.php`. Sem as linhas abaixo, o WordPress pede dados de FTP ao atualizar. Adicione-as antes de `require_once ABSPATH . 'wp-settings.php';`:

```php
define( 'FS_METHOD', 'direct' );
define( 'FS_CHMOD_DIR', 02775 );
define( 'FS_CHMOD_FILE', 0664 );
```

O script avisa se faltar o `FS_METHOD`, mas não confere as outras duas constantes.

### Verificações manuais

- **Senhas em outros arquivos:** só `.env` e `wp-config.php` são reconhecidos. Ajuste arquivos como `config.php` para `640`.
- **Cópias antigas do WordPress:** uma cópia com `wp-settings.php` também é tratada como instalação ativa e fica gravável. Remova as que não forem usadas.
- **Site dentro de um WordPress:** segue o padrão do WordPress; ajuste essa pasta manualmente.
- **Grava fora de `--writable`:** teste uploads e cadastros. Falhas aparecem como `Permission denied` no log do Apache.

### Bloqueio de PHP nas pastas de `--writable`

Cada pasta passada em `--writable` recebe automaticamente esta regra, em `/etc/apache2/conf-available/php2shell-writable.conf`:

```apache
<Directory "/var/www/html/meusite/uploads">
    AllowOverride None
    Options -ExecCGI -Includes
    <FilesMatch "(?i)\.(php[0-9]*|phtml|phar|phps|pht)$">
        Require all denied
    </FilesMatch>
</Directory>
```

O script ativa o arquivo com `a2enconf`, valida com `apache2ctl configtest` e recarrega o Apache. Se a validação falhar, ele desfaz a regra, avisa e termina com código `1`; as permissões já aplicadas permanecem, então a pasta fica gravável sem o bloqueio até você resolver. Sem Apache instalado (Nginx, por exemplo), a regra não é criada e o script também termina com código `1`.

- **O que a regra faz:** impede que um `.php` nessa pasta seja executado ou baixado pelo Apache. Ela não impede o envio do arquivo, que é feito pela aplicação; continue validando os tipos de arquivo aceitos.
- **`.htaccess`:** o `AllowOverride None` faz o Apache ignorar `.htaccess` nessa pasta e nas subpastas, para um arquivo enviado não desfazer o bloqueio. Regras legítimas em `.htaccess` ali deixam de valer.
- **PHP executado por `include`:** a regra vale para acessos pela web. Um `include` em código PHP de outra pasta continua carregando o arquivo.
- **WordPress:** a regra não é automática para `wp-content/uploads`. Para aplicá-la, informe a pasta; as permissões dela continuam iguais às do resto do WordPress:

```bash
sudo bash php2shell-ubuntu.sh --fix-perms --writable=meusite/wp-content/uploads
```

- **Execuções seguintes:** as pastas de execuções anteriores são mantidas no arquivo; só saem as que deixaram de existir. Para retirar uma pasta, apague o bloco dela e recarregue o Apache.

Para confirmar, crie um arquivo de teste na pasta e abra no navegador. O resultado certo é erro **403**; depois, apague o arquivo.

```bash
echo '<?php echo "EXECUTOU";' | sudo tee /var/www/html/meusite/uploads/teste-bloqueio.php > /dev/null
```

```bash
sudo rm /var/www/html/meusite/uploads/teste-bloqueio.php
```

Se o site for acessado por um caminho com link simbólico, a regra pode não coincidir com o caminho real; por isso, faça esse teste em cada site.

## CVE-2026-115560

Esta falha ainda não tinha correção publicada na data de referência. Ela afeta aplicações que trocam `session.serialize_handler` com `ini_set()` antes de `session_start()`, com `session.upload_progress` ativo.

O `--mitigate` desativa esse recurso para FPM, Apache e CGI, criando `99-php2shell-mitigation.ini` no `conf.d` de cada um. As barras de progresso de upload baseadas nele param de funcionar. Quando o PHP publicar a correção, atualize e apague esse arquivo, se precisar do recurso.

## Códigos de saída

| Código | Significado |
|---|---|
| `0` | Nenhuma pendência nos itens verificados |
| `1` | Requer ação: pacote vulnerável, correção não verificável, migração com falha ou item manual |
| `2` | Erro de execução ou opção inválida |

## Limitações

- **Possível invasão:** o script não detecta invasões, e atualizar não remove um invasor. Revise logs, arquivos PHP alterados, usuários, chaves SSH e crontabs.
- **Fora de alcance:** não atualiza PHP compilado, de painel ou em contêineres, e a busca fora do apt só cobre caminhos conhecidos.
- **Extensões fora do pacote principal:** extensões como `redis`, `imagick` e `xmlrpc` não aparecem na lista de pacotes; confira com `php -m`.
- **`--check`:** não roda `apt-get update`, então a versão disponível pode estar defasada.
- **Testes:** a análise e o `--migrate` foram testados com apt, serviços e `/etc` simulados no WSL. O `--fix-perms` foi testado com permissões reais em uma pasta temporária, e a geração da regra do `--writable`, com comandos do Apache simulados. Uma migração para o 8.4 em Ubuntu 22.04 com Apache também rodou em um servidor real, em uma versão anterior do script, antes do bloqueio temporário de ramos mais novos e do `--fix-perms`.

O log de cada execução com alterações fica em `/var/log/php2shell-fix.log`.

## Fontes

- [PHP: anúncios de 2026](https://www.php.net/archive/2026.php)
- [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1)
- [Ubuntu USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2)
- [NCSC-NL: php2shell](https://github.com/NCSC-NL/php2shell)

## Licença

[MIT](LICENSE)
