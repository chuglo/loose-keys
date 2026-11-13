"""A backend and cloud developer: cloud CLIs, Kubernetes, Terraform, Docker,
SSH keys for several hosts, a dozen repositories, and the local tooling and
dependency caches that come with them."""

import base64

from .lib import DEBATABLE, HIDDEN, STORED, WORTH

REPOS = [
    "payments-api", "orders-service", "user-service", "notification-svc", "data-pipeline",
    "legacy-monolith", "infra", "admin-dashboard", "go-gateway", "ml-experiments",
    "sre-runbooks", "k8s-operators",
]


def build(h):
    cloud(h)
    ssh(h)
    repositories(h)
    shell(h)
    local_tooling(h)
    dependency_caches(h)
    bulk(h)


def cloud(h):
    h.plant(
        ".aws/credentials",
        f"[default]\naws_access_key_id = {h.token('aws-id')}\naws_secret_access_key = {h.chars(40)}\n\n"
        f"[prod-deploy]\naws_access_key_id = {h.token('aws-id')}\naws_secret_access_key = {h.chars(40)}\n",
        "long-lived AWS keys, profile default", WORTH, "static keys that work from anywhere", mode=0o600,
    )
    h.expect(".aws/credentials", "long-lived AWS keys, profile prod-deploy", WORTH, "static keys that work from anywhere")
    h.plant(
        ".aws/config",
        "[profile dev]\nsso_start_url = https://corp.example.invalid/start\nsso_region = us-east-1\n"
        "sso_account_id = 123456789012\nsso_role_name = Developer\n\n"
        "[profile vault]\ncredential_process = aws-vault exec vault --json\n",
        "AWS config with SSO and a credential helper", HIDDEN, "names no secret",
    )
    cached = ".aws/cli/cache/" + h.chars(40, "0123456789abcdef") + ".json"
    h.json(cached, {
        "Credentials": {"AccessKeyId": "AS" + "IA" + h.chars(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
                        "SecretAccessKey": h.chars(40), "SessionToken": h.chars(400),
                        "Expiration": "2026-11-11T20:00:00Z"}}, mode=0o600)
    h.expect(cached, "temporary role credentials the AWS CLI cached", STORED, "short-lived, kept by the CLI")

    key = h.pem("", 26).replace("\n", "\\n")
    for rel, why in (("src/payments-api/gcp-sa-staging.json", "a service account key inside a repository"),
                     ("keys/analytics-reader-sa.json", "a service account key kept in a folder of keys")):
        h.plant(rel, '{\n  "type": "service_account",\n  "project_id": "corp-staging",\n'
                f'  "private_key_id": "{h.chars(40, "0123456789abcdef")}",\n  "private_key": "{key}",\n'
                '  "client_email": "deploy@corp-staging.iam.gserviceaccount.com"\n}\n',
                "Google service account key", WORTH, why)
    h.json(".config/gcloud/legacy_credentials/dev@corp.example.invalid/adc.json", {
        "type": "authorized_user", "client_id": "32555940559.apps.googleusercontent.com",
        "client_secret": h.chars(24), "refresh_token": "1//" + h.chars(60)}, mode=0o600)
    h.expect(".config/gcloud/legacy_credentials/dev@corp.example.invalid/adc.json",
             "gcloud's stored sign-in", STORED, "the sign-in gcloud keeps for itself")

    kubernetes(h)
    terraform(h)
    docker_and_databases(h)


def kubernetes(h):
    token = h.chars(48)
    kube = (
        "apiVersion: v1\nkind: Config\nclusters:\n- name: prod\n  cluster:\n    server: https://k8s.example.invalid\n"
        "users:\n- name: ci-deployer\n  user:\n    token: {token}\n"
        "- name: eks-dev\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n"
        "      command: aws\n      args: [eks, get-token, --cluster-name, dev]\n"
        "- name: admin-cert\n  user:\n    client-certificate-data: {cert}\n    client-key-data: {key}\n"
    )
    cert = base64.b64encode(h.certificate().encode()).decode()
    keydata = base64.b64encode(h.pem().encode()).decode()
    h.plant(".kube/config", kube.format(token=token, cert=cert, key=keydata),
            "Kubernetes token for user ci-deployer", WORTH, "a bearer token in plain text", group="kube-ci-token", mode=0o600)
    h.expect(".kube/config", "Kubernetes client key for user admin-cert", WORTH, "an admin client key in plain text")
    h.expect(".kube/config", "Kubernetes user that runs 'aws eks get-token'", HIDDEN, "stores no credential")
    h.plant(".kube/config.bak", kube.format(token=token, cert=cert, key=keydata),
            "old copy of the kubeconfig, same token", WORTH, "the same token in a second file", group="kube-ci-token")
    h.plant(".kube/kubeconfig-staging.yaml",
            f"apiVersion: v1\nkind: Config\nusers:\n- name: staging\n  user:\n    token: {h.chars(48)}\n",
            "Kubernetes token for a second cluster", WORTH, "a bearer token in plain text")
    h.plant("src/infra/k8s/kubeconfig.dev",
            f"apiVersion: v1\nkind: Config\nclusters:\n- name: dev\n  cluster:\n    server: https://dev.example.invalid\n"
            f"users:\n- name: dev\n  user:\n    client-key-data: {keydata}\n",
            "kubeconfig saved inside a repository", WORTH, "a client key outside ~/.kube")
    h.tree(".kube/cache/discovery", 300, (".json",), 3, 6)


def terraform(h):
    db_password = h.password(24)
    state = {"version": 4, "terraform_version": "1.9.0", "resources": [
        {"type": "aws_db_instance", "name": "main", "instances": [
            {"attributes": {"username": "app", "password": db_password, "endpoint": "db.example.invalid:5432"}}]},
        {"type": "random_password", "name": "redis", "instances": [{"attributes": {"result": h.password(32)}}]}]}
    h.json("src/infra/terraform/prod/terraform.tfstate", state)
    h.expect("src/infra/terraform/prod/terraform.tfstate", "database password in Terraform state", WORTH,
             "state keeps secrets in plain text", group="tfstate-prod")
    h.json("src/infra/terraform/prod/terraform.tfstate.backup", state)
    h.expect("src/infra/terraform/prod/terraform.tfstate.backup", "Terraform's backup of the same state", WORTH,
             "the same secrets in the backup file", group="tfstate-prod")
    h.json("src/infra/terraform/prod/.terraform/terraform.tfstate",
           {"version": 3, "backend": {"type": "s3", "config": {"bucket": "corp-tfstate", "profile": "prod-deploy"}}})
    h.expect("src/infra/terraform/prod/.terraform/terraform.tfstate", "Terraform backend settings", HIDDEN, "names a profile, no secret")
    h.plant("src/infra/terraform/prod/prod.tfvars",
            f'region = "us-east-1"\ndb_password = "{db_password}"\ndatadog_api_key = "{h.token("hex32")}"\n',
            "production secrets in a .tfvars file", WORTH, "real values in plain text")
    h.plant("src/infra/terraform/prod/example.tfvars",
            'region = "us-east-1"\ndb_password = "changeme"\ndatadog_api_key = "<your key>"\n',
            "example .tfvars with placeholders", HIDDEN, "placeholders only")
    h.blobs("src/infra/terraform/prod/.terraform/providers", 40, 4000)


def docker_and_databases(h):
    h.json(".docker/config.json", {
        "auths": {"ghcr.io": {"auth": base64.b64encode(f"dev:{h.token('github')}".encode()).decode()},
                  "123456789012.dkr.ecr.us-east-1.amazonaws.com": {}},
        "credHelpers": {"gcr.io": "gcloud"}}, mode=0o600)
    h.expect(".docker/config.json", "registry token for ghcr.io written into Docker's config", WORTH, "a token in plain text")
    h.expect(".docker/config.json", "registries that use a credential helper", HIDDEN, "stores no credential")

    h.plant(".my.cnf", f"[client]\nuser = app\npassword = {h.password()}\nhost = db.example.invalid\n",
            "MySQL password in .my.cnf", WORTH, "a database password in plain text", mode=0o600)


def ssh(h):
    for name, passphrase, expect, why in (
        ("id_ed25519", "", WORTH, "an everyday key with no passphrase"),
        ("id_ed25519_github", "synthetic passphrase", STORED, "the key has a passphrase"),
        ("google_compute_engine", "", WORTH, "gcloud's SSH key, no passphrase"),
    ):
        h.ssh_key(f".ssh/{name}", passphrase)
        h.expect(f".ssh/{name}", "SSH private key", expect, why)
        h.expect(f".ssh/{name}.pub", "SSH public key", HIDDEN, "public by design")
    h.plant(".ssh/id_rsa_prod_bastion", h.pem("RSA"), "SSH key for the production bastion, no passphrase",
            WORTH, "an unprotected key for a production host", mode=0o600)
    h.plant(".ssh/deploy_staging.pem", h.pem("RSA"), "EC2 key pair file", WORTH, "an unprotected key for servers", mode=0o600)
    h.plant(".ssh/old/id_rsa.bak", h.pem("RSA"), "backup of an old SSH key in a subfolder", WORTH,
            "an unprotected key, forgotten", mode=0o600)
    h.put(".ssh/config", "Host bastion\n  HostName bastion.example.invalid\n  IdentityFile ~/.ssh/id_rsa_prod_bastion\n")
    h.put(".ssh/known_hosts", "".join(f"host{n}.example.invalid ssh-ed25519 AAAA{h.chars(64)}\n" for n in range(40)))
    h.put(".ssh/authorized_keys", f"ssh-ed25519 AAAA{h.chars(64)} dev@example.invalid\n")


def repositories(h):
    for name in REPOS:
        h.repo(f"src/{name}", f"git@github.com:corp/{name}.git")
        h.tree(f"src/{name}/src", 220, (".go", ".py", ".ts"), 4)
        h.tree(f"src/{name}/build", 120, (".o", ".map"), 2, 4)

    env_files(h)
    other_project_files(h)
    encrypted_and_test_files(h)


def env_files(h):
    """Each repository's settings: real secrets, local defaults and examples."""
    aws_id, aws_secret = h.token("aws-id"), h.chars(40)
    h.plant("src/payments-api/.env",
            f"PORT=8080\nSTRIPE_SECRET_KEY={h.token('stripe')}\n"
            f"DATABASE_URL=postgres://payments:{h.password()}@db.internal.example.invalid:5432/payments\n"
            f"JWT_SECRET={h.chars(48)}\nAWS_ACCESS_KEY_ID={aws_id}\nAWS_SECRET_ACCESS_KEY={aws_secret}\n"
            "SENTRY_DSN=https://abc123@o1.ingest.example.invalid/2\n",
            "live Stripe key", WORTH, "a live payment key")
    h.expect("src/payments-api/.env", "database URL with the production password", WORTH, "a password for a remote database")
    h.expect("src/payments-api/.env", "JWT signing secret", WORTH, "signs sessions")
    h.expect("src/payments-api/.env", "AWS key pair (ID and secret are one credential)", WORTH,
             "static AWS keys; one item for the pair would be right", group="payments-aws")
    h.plant("src/payments-api/.env.example",
            "PORT=8080\nSTRIPE_SECRET_KEY=sk_live_your-key-here\nDATABASE_URL=postgres://user:password@localhost:5432/payments\n"
            "JWT_SECRET=changeme\nAWS_ACCESS_KEY_ID=\nAWS_SECRET_ACCESS_KEY=\n",
            ".env.example with placeholders", HIDDEN, "placeholders only")

    h.plant("src/orders-service/.env",
            "POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=postgres\nREDIS_PASSWORD=redis123\n"
            "DATABASE_URL=postgres://postgres:postgres@localhost:5432/orders\n",
            "default passwords for local containers", HIDDEN, "well-known defaults for a database on localhost")
    h.plant("src/orders-service/.env.docker", "MYSQL_ROOT_PASSWORD=rootpass123\nMYSQL_DATABASE=orders\n",
            "root password of a local MySQL container", HIDDEN, "a throwaway local value")
    h.plant("src/orders-service/docker-compose.yml",
            "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: postgres\n",
            "compose file with a local default password", HIDDEN, "a well-known default on localhost")

    pat = h.token("github")
    h.plant("src/user-service/.env.local",
            f"GITHUB_TOKEN={pat}\nSLACK_BOT_TOKEN={h.token('slack')}\nSENDGRID_API_KEY={h.token('sendgrid')}\n",
            "GitHub personal access token", WORTH, "a real token", group="github-pat")
    h.expect("src/user-service/.env.local", "Slack bot token", WORTH, "a real token")
    h.expect("src/user-service/.env.local", "SendGrid API key", WORTH, "a real key")
    h.plant("src/admin-dashboard/.env", f"GITHUB_TOKEN={pat}\nPORT=3000\n",
            "the same GitHub token in a second project", WORTH, "one credential, two files", group="github-pat")
    h.plant("src/user-service/.env.test",
            "JWT_SECRET=test-secret-do-not-use\nAPI_KEY=test_api_key_123456\nDB_PASSWORD=testpassword\n",
            "values for the test suite", HIDDEN, "named as test values")

    h.plant("src/notification-svc/.env",
            f"TWILIO_ACCOUNT_SID=AC{h.chars(32, '0123456789abcdef')}\nTWILIO_AUTH_TOKEN={h.token('hex32')}\n"
            f"SLACK_WEBHOOK_URL={h.token('slack-hook')}\n",
            "Twilio auth token", WORTH, "a real token")
    h.expect("src/notification-svc/.env", "Slack webhook URL", WORTH, "anyone with the URL can post")
    h.plant("src/data-pipeline/.env",
            f"SNOWFLAKE_USER=etl\nSNOWFLAKE_PASSWORD={h.password()}\nDATABRICKS_TOKEN={h.token('databricks')}\n"
            f"OPENAI_API_KEY={h.token('openai')}\n",
            "Snowflake password", WORTH, "a warehouse password")
    h.expect("src/data-pipeline/.env", "Databricks token", WORTH, "a real token")
    h.expect("src/data-pipeline/.env", "OpenAI API key", WORTH, "a real key")
    h.plant("src/legacy-monolith/.env.production",
            f"SECRET_KEY_BASE={h.chars(96, '0123456789abcdef')}\nSMTP_PASSWORD={h.password()}\n"
            f"RAILS_MASTER_KEY={h.token('hex32')}\n",
            "Rails secret key base and SMTP password, production", WORTH, "production secrets copied to a laptop")
    h.expect("src/legacy-monolith/.env.production", "Rails master key", WORTH, "decrypts the app's credentials file")
    h.plant("src/legacy-monolith/config/database.yml",
            f"production:\n  adapter: postgresql\n  host: db.example.invalid\n  username: app\n  password: {h.password()}\n",
            "production database password in a YAML config", WORTH, "a real password, though not in a .env file")
    h.plant("src/infra/.envrc",
            f'export AWS_PROFILE=prod-deploy\nexport TF_VAR_db_password="{h.password()}"\n'
            "export VAULT_ADDR=https://vault.example.invalid\nexport VAULT_TOKEN=$(cat ~/.vault-token)\n",
            "database password exported from .envrc", WORTH, "a real password")
    h.expect("src/infra/.envrc", "Vault token read from a command", HIDDEN, "a reference, not a value")
    h.plant("src/go-gateway/.env", f"SESSION_SECRET={h.chars(40)}\nAPI_KEY=${{API_KEY}}\nLOG_LEVEL=debug\n",
            "session secret", WORTH, "signs sessions")
    h.expect("src/go-gateway/.env", "API key taken from the environment", HIDDEN, "a reference, not a value")
    h.plant("src/ml-experiments/.env", f"HF_TOKEN={h.token('huggingface')}\nWANDB_API_KEY={h.token('hex40')}\n",
            "Hugging Face token", WORTH, "a real token")
    h.expect("src/ml-experiments/.env", "Weights & Biases API key", WORTH, "a real key")


def other_project_files(h):
    """Secrets in a repository outside its .env files."""
    h.plant("src/infra/helm/values-prod.yaml",
            f"postgresql:\n  auth:\n    username: app\n    password: {h.password()}\nreplicaCount: 3\n",
            "production password in Helm values", WORTH, "a real password in a plain YAML file")

    h.plant("src/infra/scripts/deploy.sh",
            f'#!/bin/sh\ncurl -s -H "Authorization: Bearer {h.token("github")}" https://api.github.example.invalid/repos\n',
            "token written into a deploy script", WORTH, "a real token in a script")
    h.plant("src/data-pipeline/scripts/backfill.py",
            h.source(90).replace("export function", "def") + f'\nTOKEN = "{h.token("gitlab")}"\n',
            "token on line 92 of a Python script", WORTH, "a real token, wherever it sits in the file")
    h.put("src/k8s-operators/.git/config",
          "[core]\n\tbare = false\n[remote \"origin\"]\n"
          f"\turl = https://oauth2:{h.token('gitlab')}@gitlab.example.invalid/corp/k8s-operators.git\n")
    h.expect("src/k8s-operators/.git/config", "GitLab token inside a remote URL", WORTH, "a token in plain text")

    h.plant("src/sre-runbooks/notes/oncall.txt",
            f"Grafana\nadmin password: {h.password(14)}\n\nPagerDuty\nsee 1Password\n",
            "password in a text note", WORTH, "a real password in a note")


def encrypted_and_test_files(h):
    h.plant("src/sre-runbooks/ansible/group_vars/prod/vault.yml",
            "$ANSIBLE_VAULT;1.1;AES256\n" + "\n".join(h.chars(80, "0123456789abcdef") for _ in range(12)) + "\n",
            "Ansible Vault file", HIDDEN, "encrypted")
    h.plant("src/infra/secrets/prod.enc.yaml",
            f"db_password: ENC[AES256_GCM,data:{h.chars(32)},iv:{h.chars(16)},tag:{h.chars(22)},type:str]\n"
            "sops:\n  age:\n  - recipient: age1" + h.chars(58, "abcdefghijklmnopqrstuvwxyz0123456789") + "\n",
            "sops-encrypted secrets", HIDDEN, "encrypted")

    h.plant("src/user-service/tests/fixtures/test_rsa.pem", h.pem("RSA"),
            "private key among a repository's test fixtures", DEBATABLE, "looks real, sits in tests/")
    h.plant("src/payments-api/testdata/fake-service-account.json",
            '{\n  "type": "service_account",\n  "project_id": "test-project",\n  "private_key": "'
            + h.pem("", 6).replace("\n", "\\n") + '",\n  "client_email": "test@test-project.iam.gserviceaccount.com"\n}\n',
            "service account file among test data", DEBATABLE, "looks real, sits in testdata/")
    h.plant("src/go-gateway/docs/setup.md",
            "# Setup\n\nCreate a token and export it:\n\n    export GITHUB_TOKEN=gh" + "p_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
            "placeholder token in documentation", HIDDEN, "a placeholder")


def shell(h):
    h.plant(".zsh_history",
            ": 1790000000:0;cd src/payments-api\n"
            f": 1790000100:0;export AWS_SECRET_ACCESS_KEY={h.chars(40)}\n"
            f": 1790000200:0;PGPASSWORD={h.password()} psql -h db.example.invalid -U app payments\n"
            f": 1790000300:0;curl -H 'Authorization: Bearer {h.token('github')}' https://api.github.example.invalid/user\n"
            f": 1790000400:0;docker login -u deploy -p {h.password()} registry.example.invalid\n"
            f": 1790000500:0;mysql -u root -p{h.password()} -h db.example.invalid\n"
            ": 1790000600:0;terraform plan -var-file=prod.tfvars\n: 1790000700:0;kubectl get pods -n prod\n",
            "AWS secret key exported in the shell", WORTH, "a real key typed into the shell", mode=0o600)
    h.expect(".zsh_history", "database password given to psql", WORTH, "a real password typed into the shell")
    h.expect(".zsh_history", "GitHub token in a curl command", WORTH, "a real token typed into the shell")
    h.expect(".zsh_history", "registry password given to 'docker login -p'", WORTH, "a real password typed into the shell")
    h.expect(".zsh_history", "database password given to 'mysql -p'", WORTH, "a real password typed into the shell")
    h.plant(".zshrc",
            'export PATH="$HOME/go/bin:$PATH"\nexport GITHUB_TOKEN=$(gh auth token)\n'
            f"export HOMEBREW_GITHUB_API_TOKEN={h.token('github')}\n",
            "GitHub token exported from .zshrc", WORTH, "a real token in a startup file")
    h.expect(".zshrc", "token read from 'gh auth token'", HIDDEN, "a reference, not a value")


def local_tooling(h):
    """Keys that tools make for this Mac alone, or publish on purpose."""
    for rel in (".minikube/ca.key", ".minikube/proxy-client-ca.key", ".minikube/profiles/minikube/client.key",
                ".minikube/profiles/minikube/apiserver.key", ".minikube/profiles/minikube/proxy-client.key",
                ".minikube/machines/minikube/id_rsa"):
        h.plant(rel, h.pem("RSA"), "key minikube made for its local cluster", HIDDEN,
                "works only against a cluster on this Mac", mode=0o600)
    h.ssh_key(".lima/_config/user")
    h.expect(".lima/_config/user", "key Lima made to reach its local VMs", HIDDEN, "works only against VMs on this Mac")
    h.ssh_key(".colima/_lima/_config/user")
    h.expect(".colima/_lima/_config/user", "key Colima made to reach its local VM", HIDDEN, "works only against a VM on this Mac")
    h.plant(".vagrant.d/insecure_private_key", h.pem("RSA"), "Vagrant's published insecure key", HIDDEN,
            "public by design: every Vagrant install has it")
    h.plant(".vagrant.d/insecure_private_keys/vagrant.key.rsa", h.pem("RSA"), "Vagrant's published insecure key", HIDDEN,
            "public by design: every Vagrant install has it")
    h.plant("Library/Application Support/mkcert/rootCA-key.pem", h.pem("RSA"), "mkcert's local certificate authority key",
            DEBATABLE, "local only, but this Mac trusts what it signs", mode=0o400)


def dependency_caches(h):
    """Test keys that packages ship, outside the folders discovery skips."""
    go = "go/pkg/mod"
    shipped = [
        f"{go}/github.com/golang-jwt/jwt/v5@v5.2.1/test/sample_key",
        f"{go}/github.com/golang-jwt/jwt/v5@v5.2.1/test/ec256-private.pem",
        f"{go}/github.com/golang-jwt/jwt/v5@v5.2.1/test/ed25519-private.pem",
        f"{go}/google.golang.org/grpc@v1.64.0/testdata/x509/server1_key.pem",
        f"{go}/google.golang.org/grpc@v1.64.0/testdata/x509/client1_key.pem",
        f"{go}/google.golang.org/grpc@v1.64.0/testdata/x509/server_ca_key.pem",
        f"{go}/google.golang.org/grpc@v1.64.0/examples/data/x509/server_key.pem",
        f"{go}/google.golang.org/grpc@v1.64.0/examples/data/x509/client_key.pem",
        f"{go}/github.com/docker/go-connections@v0.5.0/tlsconfig/fixtures/key.pem",
        f"{go}/k8s.io/client-go@v0.30.1/util/cert/testdata/dontUseThisKey.pem",
        f"{go}/golang.org/toolchain@v0.0.1-go1.22.4.darwin-arm64/src/crypto/tls/testdata/example-key.pem",
        ".pyenv/versions/3.12.4/lib/python3.12/test/certdata/keycert.pem",
        ".pyenv/versions/3.12.4/lib/python3.12/test/certdata/ssl_key.pem",
        ".pyenv/versions/3.12.4/lib/python3.12/test/certdata/keycert2.pem",
        ".pyenv/versions/3.12.4/lib/python3.12/test/certdata/keycertecc.pem",
        ".pyenv/versions/3.12.4/lib/python3.12/test/certdata/idnsans.pem",
        ".pyenv/versions/3.12.4/lib/python3.12/site-packages/tornado/test/test.key",
        ".pyenv/versions/3.12.4/lib/python3.12/site-packages/twisted/test/server.pem",
        ".pyenv/versions/3.12.4/lib/python3.12/site-packages/gevent/tests/test_server.key",
    ]
    for rel in shipped:
        h.plant(rel, h.pem("" if rel.endswith("_key.pem") else "RSA"), "test key shipped inside a downloaded package",
                HIDDEN, "published with the package; the developer never made or used it", mode=0o444)
    h.plant(".pyenv/versions/3.12.4/lib/python3.12/test/certdata/ssl_key.passwd.pem", h.pem("", encrypted=True),
            "encrypted test key shipped with Python", HIDDEN, "published with Python", mode=0o444)
    h.tree(f"{go}/github.com", 3500, (".go", ".mod", ".sum"), 5)
    h.tree(f"{go}/golang.org/toolchain@v0.0.1-go1.22.4.darwin-arm64/src", 2500, (".go",), 4)
    h.tree(".pyenv/versions/3.12.4/lib/python3.12/site-packages", 4500, (".py", ".pyi"), 4)
    h.tree(".pyenv/versions/3.12.4/lib/python3.12/test", 900, (".py",), 2)


def bulk(h):
    h.tree("src/data-pipeline/.venv/lib/python3.12/site-packages", 1500, (".py",), 4)
    h.tree("src/go-gateway/vendor", 1200, (".go",), 4)
    h.tree("src/payments-api/target/debug", 800, (".d", ".rlib"), 3, 3)
    h.tree("Library/Caches/go-build", 2500, ("-a", "-d"), 2, 3)
    h.tree("Library/Application Support/Code/User/workspaceStorage", 600, (".json",), 2, 5)
    h.tree(".vscode/extensions/golang.go-0.42.0/dist", 700, (".js",), 3)
    h.tree(".gradle/caches/modules-2/files-2.1", 1500, (".pom", ".jar"), 4, 3)
    h.tree(".m2/repository", 1500, (".pom", ".sha1"), 5, 3)
    h.tree(".terraform.d/plugin-cache", 60, (".zip",), 3, 40)
