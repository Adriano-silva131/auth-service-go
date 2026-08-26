# auth-service-go

Serviço de autenticação do [OrderHub](https://github.com/Adriano-silva131/order-hub-application), em Go com Clean Architecture — substitui o Keycloak. Cobre registro, login, refresh token e emissão de JWT (RS256 + JWKS) pro `api-gateway` validar, sem depender de um Identity Provider de terceiros.

## Por que existe

O `api-gateway` do OrderHub validava tokens emitidos pelo Keycloak. Trocamos o Keycloak por este serviço próprio — mesma responsabilidade (autenticar usuários, emitir tokens verificáveis), mas escrito do zero, e mais uma peça de portfólio consistente com o [`payment-service-go`](../payment-service-go) (mesma stack, mesmos padrões de Clean Architecture).

**Login por senha só, por enquanto.** "Sign in with Google" está planejado pra quando o frontend for estruturado (login social exige uma superfície de navegador pro consentimento — não dá pra fazer só via terminal). A coluna `password_hash` já é opcional no schema (`users.password_hash NULLABLE`) pra esse dia não exigir uma migration disruptiva — um usuário criado via Google simplesmente não teria hash de senha.

## Arquitetura

Mesmo layout de Clean Architecture do `payment-service-go`:

```
cmd/auth-service            composition root
internal/domain              User, RefreshToken — zero imports externos
internal/usecase              Register, Login, RefreshAccessToken, Logout, CreateUsersBulk, AddRole + portas
internal/adapter/
  http                       chi router, handlers, middleware (AdminAPIKey, RequireAuth)
  postgres                   repositórios via pgx
  jwt                        geração/carga de chave RSA, emissor RS256, verificador, encoder JWKS
  hash                       bcrypt
migrations/                  golang-migrate
```

## Chave RSA

`internal/adapter/jwt/keys.go` carrega o par de chaves dos caminhos configurados (`JWT_PRIVATE_KEY_PATH`/`JWT_PUBLIC_KEY_PATH`) ou **gera e persiste um novo** se os arquivos não existirem — zero configuração manual pra rodar localmente ou num `kubectl apply` limpo.

**Trade-off explícito**: como a chave é persistida em disco (não num KMS/Vault), rodar múltiplas réplicas exigiria compartilhar essa chave entre elas — o que não é trivial com um volume `ReadWriteOnce`. Por isso este serviço roda com **1 réplica só**, de propósito, tanto no Docker Compose (volume nomeado) quanto no Kubernetes (`PersistentVolumeClaim`, sem HPA). Escalar horizontalmente exigiria injetar uma chave pré-gerada via Secret/Vault em vez de gerar no boot — fora do escopo atual.

## Endpoints

| Método | Rota | Auth | Descrição |
|---|---|---|---|
| POST | `/auth/register` | — | `{email, password, name}` → cria usuário |
| POST | `/auth/login` | — | `{email, password}` → `{access_token, refresh_token, ...}` |
| POST | `/auth/refresh` | — | `{refresh_token}` → novo par (o antigo é revogado — rotação) |
| POST | `/auth/logout` | — | `{refresh_token}` → revoga (idempotente) |
| GET | `/.well-known/jwks.json` | — | chave pública em formato JWK, pro `api-gateway` validar assinatura |
| POST | `/admin/users/bulk` | header `X-Admin-Api-Key` | criação em lote — usado pelo `k6/create-users.sh` |
| POST | `/users/me/roles` | Bearer JWT | `{role}` → adiciona uma role à conta autenticada (hoje só `SELLER`; idempotente) |
| GET | `/healthz`, `/readyz`, `/metrics` | — | infra padrão |

Claims do access token: `sub` (uuid do usuário), `email`, `name`, `roles`, `iat`, `exp`, `iss`; header `kid`. `sub`, `email` e `roles` são as claims de que o resto do sistema depende (`RateLimiterConfig` e `UserContextPropagationFilter` do `api-gateway`).

Todo usuário nasce só com a role `CUSTOMER`. Roles são aditivas, não um enum exclusivo: a mesma conta pode acumular `SELLER` via `POST /users/me/roles` sem precisar de um segundo cadastro — um comprador que também vende continua com uma única identidade. `/users/me/roles` é a única rota deste serviço que valida o próprio JWT (via `internal/adapter/jwt.Verifier`, mesma chave RSA usada pra assinar); toda outra rota autenticada é validada rio abaixo, no `api-gateway`.

Refresh token é **opaco** (não é JWT) — só o hash SHA-256 fica no banco, permitindo revogação real (logout de verdade, sem precisar reinventar uma denylist).

## Rodando localmente

### Opção A — standalone (`docker-compose.yml` deste repo)

Sobe um Postgres próprio (`auth-service-postgres`, porta `5434`, volume dedicado), isolado da instância compartilhada do `order-hub-application`. Não depende de nenhum outro repositório:

```bash
cp .env.example .env
docker compose up -d --build
```

O serviço fica disponível em `http://localhost:8090`. Migrations rodam automaticamente no boot do container (`docker-entrypoint.sh`).

### Opção B — binário local, contra o Postgres da stack principal

Requer o Postgres de `order-hub-application/infra` rodando — este serviço usa um banco `authdb` separado na mesma instância.

```bash
cp .env.example .env
set -a; source .env; set +a
make migrate-up
make run
```

### Opção C — via `order-hub-application/infra`

`docker compose up -d --build` a partir de `order-hub-application/infra` sobe a stack inteira (gateway, demais serviços etc). Este repositório é esperado como diretório **irmão** de `order-hub-application` — o `build.context` do compose aponta pra `../../auth-service-go` por padrão.

**Atenção:** as opções A e C sobem um container próprio chamado `auth-service`/`orderhub-auth-service` na porta `8090` — não rode as duas ao mesmo tempo, elas vão brigar pela porta.

## Testes

```bash
make test              # unitários (fakes, sem dependências externas)
make test-integration  # testcontainers-go: Postgres real, roda as migrations deste repo
```
