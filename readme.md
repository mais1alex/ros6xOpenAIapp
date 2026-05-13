# MikroTik AI MCP — MVP Docker

Primeira versao simples para conectar ChatGPT ao MikroTik/RouterOS via MCP.

## O que sobe

- Painel web local: `http://dockerhost:8282`
- Servidor MCP/OAuth: `https://url-gerada-pelo.ngrok-free.dev/mcp`
- Configuracao persistente em volume Docker
- Teste de conexao RouterOS API
- OAuth para ChatGPT Developer Mode
- ngrok opcional pelo painel

## Instalacao rapida com Docker Compose

```bash
docker compose up -d --build
```

Acesse:

```text
http://dockerhost:8282
```

Senha padrao do compose:

```text
troque-esta-senha
```

Altere no `docker-compose.yml` antes de usar em ambiente real.

## Instalacao com docker run

```bash
docker run -d \
  --name mikrotik-ai-mcp \
  --restart unless-stopped \
  -p 8282:8080 \
  -v mikrotik-ai-data:/data \
  -e ADMIN_PASSWORD='troque-esta-senha' \
  mikrotik-ai-mcp:latest
```

## Fluxo de configuracao

1. Acesse `http://dockerhost:8282`
2. Configure host, usuario e senha do MikroTik
3. Clique em **Testar MikroTik**
4. Configure URL publica manual ou informe ngrok token
5. Copie a URL final `/mcp`
6. Cole no ChatGPT Developer Mode

## Portas

| Porta | Uso |
|---|---|
| 8282 | Painel web local |

Nao exponha a porta 8080 publicamente.

## ChatGPT

Use a URL publica do MCP:

```text
https://url-gerada-pelo.ngrok-free.dev/mcp
```

Durante o OAuth, use o usuario e senha OAuth exibidos no painel.

## Segurança

- O painel exige `ADMIN_PASSWORD`.
- As configuracoes ficam no volume `/data`.
- O endpoint MCP exige OAuth.
- A senha do MikroTik nao e exibida no formulario depois de salva.
