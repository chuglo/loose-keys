"""A JavaScript developer: many projects with large dependency trees, registry
settings, framework build output, test fixtures and a package store."""

from .lib import DEBATABLE, HIDDEN, STORED, WORTH

PROJECTS = [
    "web-storefront", "admin-panel", "mobile-app", "api-server", "component-library", "monorepo",
    "landing-site", "chrome-extension", "electron-app", "docs-site", "legacy-jquery", "design-tokens",
    "cli-tool", "realtime-chat", "blog",
]


def build(h):
    registries(h)
    storefront(h)
    client_apps(h)
    servers_and_tools(h)
    fixtures(h)
    sign_ins(h)
    shell(h)
    bulk(h)


def registries(h):
    h.plant(".npmrc",
            f"//registry.npmjs.org/:_authToken={h.token('npm')}\n"
            f"//npm.pkg.github.com/:_authToken={h.token('github')}\n@corp:registry=https://npm.pkg.github.com\n",
            "npm publish token in ~/.npmrc", WORTH, "a real token", mode=0o600)
    h.expect(".npmrc", "GitHub Packages token in ~/.npmrc", WORTH, "a real token")
    h.plant("code/component-library/.npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
            "project .npmrc that reads the token from the environment", HIDDEN, "a reference, not a value")
    h.plant("code/component-library/.yarnrc.yml",
            f'npmRegistryServer: "https://registry.npmjs.org"\nnpmAuthToken: "{h.token("npm")}"\n',
            "npm token in a project's Yarn settings", WORTH, "a real token")
    h.plant("code/monorepo/.npmrc", f"@corp:registry=https://npm.corp.example.invalid/\n"
            f"//npm.corp.example.invalid/:_authToken={h.chars(44)}\n",
            "private registry token in a project .npmrc", WORTH, "a real token")


def storefront(h):
    stripe = h.token("stripe")
    env = (
        "NEXT_PUBLIC_SUPABASE_URL=https://abcdefgh.supabase.example.invalid\n"
        f"NEXT_PUBLIC_SUPABASE_ANON_KEY={h.token('jwt')}\n"
        f"SUPABASE_SERVICE_ROLE_KEY={h.token('jwt')}\n"
        f"NEXT_PUBLIC_FIREBASE_API_KEY={h.token('google')}\n"
        f"NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_{h.chars(40)}\n"
        f"STRIPE_SECRET_KEY={stripe}\n"
        f"NEXTAUTH_SECRET={h.chars(44)}\n"
        f"DATABASE_URL=postgresql://store:{h.password()}@db.example.invalid:5432/store\n"
    )
    project = "code/web-storefront"
    h.plant(f"{project}/.env.local", env, "live Stripe key", WORTH, "a live payment key", group="store-stripe")
    h.expect(f"{project}/.env.local", "Supabase service role key", WORTH, "bypasses the database's access rules")
    h.expect(f"{project}/.env.local", "NextAuth secret", WORTH, "signs sessions")
    h.expect(f"{project}/.env.local", "database URL with a password", WORTH, "a password for a remote database")
    h.expect(f"{project}/.env.local", "Firebase web API key (NEXT_PUBLIC_)", HIDDEN,
             "the framework ships NEXT_PUBLIC_ values to every browser")
    h.expect(f"{project}/.env.local", "Supabase anon key and Stripe publishable key", HIDDEN, "public by design")
    h.plant(f"{project}/.next/standalone/.env.local", env, "copy of .env.local in the framework's build output",
            WORTH, "the same secrets in a second file; one item each would be right", group="store-stripe")
    h.plant(f"{project}/.next/server/app/api/checkout/route.js",
            h.source(80) + f'const stripe = new Stripe("{stripe}");\n' + h.source(20),
            "the Stripe key compiled into a server bundle", WORTH, "the same key in build output", group="store-stripe")
    h.plant(f"{project}/.env.example",
            "NEXT_PUBLIC_SUPABASE_URL=\nSUPABASE_SERVICE_ROLE_KEY=your-service-role-key\nSTRIPE_SECRET_KEY=sk_live_...\n"
            "NEXTAUTH_SECRET=changeme\nDATABASE_URL=postgresql://user:password@localhost:5432/store\n",
            ".env.example with placeholders", HIDDEN, "placeholders only")
    h.plant(f"{project}/certificates/localhost-key.pem", h.pem(""),
            "key for the dev server's localhost certificate", HIDDEN, "made by the dev server for localhost only")
    h.put(f"{project}/certificates/localhost.pem", h.certificate())
    h.put(f"{project}/.git/config",
          "[core]\n\tbare = false\n[remote \"origin\"]\n"
          f"\turl = https://x-access-token:{h.token('github-app')}@github.example.invalid/corp/web-storefront.git\n")
    h.expect(f"{project}/.git/config", "GitHub token inside a remote URL", WORTH, "a token in plain text")


def client_apps(h):
    h.plant("code/admin-panel/.env",
            f"VITE_API_URL=https://api.example.invalid\nVITE_GOOGLE_MAPS_API_KEY={h.token('google')}\n"
            "VITE_SENTRY_DSN=https://abc@o1.ingest.example.invalid/3\n",
            "Google Maps key in a Vite app (VITE_)", HIDDEN, "the bundler ships VITE_ values to every browser")
    h.plant("code/admin-panel/.env.production", f"VITE_API_KEY={h.chars(32)}\nVITE_APP_TITLE=Admin\n",
            "API key a Vite app sends from the browser (VITE_)", HIDDEN, "the bundler ships VITE_ values to every browser")
    h.plant("code/admin-panel/.cert/key.pem", h.pem("RSA"), "key for the dev server's localhost certificate", HIDDEN,
            "made for localhost only")
    h.plant("code/mobile-app/.env", f"EXPO_PUBLIC_API_KEY={h.chars(32)}\nEXPO_PUBLIC_API_URL=https://api.example.invalid\n",
            "API key an Expo app ships (EXPO_PUBLIC_)", HIDDEN, "Expo ships EXPO_PUBLIC_ values inside the app")
    h.plant("code/mobile-app/AuthKey_7XK2P9QRST.p8", h.pem(""), "Apple API key file (.p8)", WORTH,
            "signs requests to Apple as the developer account")
    h.json("code/mobile-app/google-services.json",
           {"project_info": {"project_id": "shop-mobile"}, "client": [{"api_key": [{"current_key": h.token("google")}]}]})
    h.expect("code/mobile-app/google-services.json", "Firebase config for an Android app", HIDDEN, "shipped inside the app")
    h.plant("code/landing-site/.env",
            f"PUBLIC_POSTHOG_KEY=phc_{h.chars(43)}\nCONTENTFUL_ACCESS_TOKEN={h.chars(43)}\n",
            "Contentful access token", WORTH, "a real token")
    h.expect("code/landing-site/.env", "PostHog project key (PUBLIC_)", HIDDEN, "public by design")
    h.plant("code/chrome-extension/key.pem", h.pem(""), "signing key of a browser extension", WORTH,
            "whoever has it can publish as this extension")
    h.plant("code/electron-app/.env",
            f"APPLE_ID=dev@example.invalid\nAPPLE_APP_SPECIFIC_PASSWORD={h.chars(4)}-{h.chars(4)}-{h.chars(4)}-{h.chars(4)}\n"
            f"GH_TOKEN={h.token('github')}\n",
            "Apple app-specific password", WORTH, "a real password")
    h.expect("code/electron-app/.env", "GitHub token used to publish releases", WORTH, "a real token")
    h.plant("code/docs-site/examples/.env", f"STRIPE_KEY={h.token('stripe-test')}\n",
            "Stripe test-mode key in an example", DEBATABLE, "a key its issuer marks as test-only")


def servers_and_tools(h):
    h.plant("code/api-server/.env",
            f"JWT_SECRET={h.chars(48)}\n"
            f"MONGODB_URI=mongodb+srv://api:{h.password()}@cluster0.example.invalid/prod\n"
            f"SENDGRID_API_KEY={h.token('sendgrid')}\nPORT=4000\n",
            "JWT signing secret", WORTH, "signs sessions")
    h.expect("code/api-server/.env", "MongoDB URL with a password", WORTH, "a password for a remote database")
    h.expect("code/api-server/.env", "SendGrid API key", WORTH, "a real key")
    key = h.pem("", 26).replace("\n", "\\n")
    h.plant("code/api-server/serviceAccountKey.json",
            '{\n  "type": "service_account",\n  "project_id": "shop-prod",\n'
            f'  "private_key": "{key}",\n  "client_email": "firebase-adminsdk@shop-prod.iam.gserviceaccount.com"\n}}\n',
            "Firebase admin service account key", WORTH, "full access to the Firebase project")
    h.plant("code/realtime-chat/.env",
            "REDIS_URL=redis://localhost:6379\nSESSION_SECRET=keyboard cat\nPUSHER_APP_KEY=a1b2c3d4e5f6a7b8c9d0\n",
            "sample values from a tutorial", HIDDEN, "a tutorial's default and a public app key")
    h.plant("code/cli-tool/.env.test", "API_TOKEN=test-token-for-unit-tests\nAPI_URL=http://localhost:9999\n",
            "token for unit tests against localhost", HIDDEN, "named as a test value")


def fixtures(h):
    h.plant("code/api-server/test/fixtures/jwt-private.pem", h.pem("RSA"),
            "private key among a project's test fixtures", DEBATABLE, "looks real, sits in test/fixtures")
    h.json("code/api-server/test/fixtures/tokens.json",
           {"valid": h.token("github"), "expired": h.token("github"), "revoked": h.token("github")})
    h.expect("code/api-server/test/fixtures/tokens.json", "three token-shaped strings in a test fixture", DEBATABLE,
             "shaped like real tokens, sits in test/fixtures")
    h.plant("code/api-server/__tests__/__snapshots__/auth.test.js.snap",
            "// Jest Snapshot v1\n\nexports[`auth header 1`] = `\n{\n  \"authorization\": \"Bearer "
            + h.token("github") + "\",\n}\n`;\n",
            "token-shaped string in a Jest snapshot", DEBATABLE, "shaped like a real token, sits in a snapshot")
    h.json("code/admin-panel/cypress.env.json", {"username": "qa@example.invalid", "password": h.password()})
    h.expect("code/admin-panel/cypress.env.json", "password of a QA account for end-to-end tests", DEBATABLE,
             "a working password for a test account")
    h.json("code/web-storefront/playwright/.auth/user.json",
           {"cookies": [{"name": "session", "value": h.chars(64), "domain": "staging.example.invalid"}]})
    h.expect("code/web-storefront/playwright/.auth/user.json", "signed-in browser session saved for tests", DEBATABLE,
             "a working session for a staging site")


def sign_ins(h):
    h.json("Library/Preferences/netlify/config.json",
           {"userId": "u1", "users": {"u1": {"auth": {"token": h.chars(43), "github": {}}}}}, mode=0o600)
    h.expect("Library/Preferences/netlify/config.json", "Netlify CLI's stored sign-in", STORED, "kept by the CLI for itself")
    h.json(".config/configstore/firebase-tools.json",
           {"tokens": {"refresh_token": "1//" + h.chars(60), "access_token": h.chars(120)}, "user": {"email": "dev@example.invalid"}}, mode=0o600)
    h.expect(".config/configstore/firebase-tools.json", "Firebase CLI's stored sign-in", STORED, "kept by the CLI for itself")
    h.json(".expo/state.json", {"auth": {"sessionSecret": '{"id":"' + h.chars(36) + '","version":1}', "username": "dev"}}, mode=0o600)
    h.expect(".expo/state.json", "Expo CLI's stored sign-in", STORED, "kept by the CLI for itself")
    h.plant("Library/Application Support/mkcert/rootCA-key.pem", h.pem("RSA"), "mkcert's local certificate authority key",
            DEBATABLE, "local only, but this Mac trusts what it signs", mode=0o400)


def shell(h):
    h.plant(".zsh_history",
            ": 1790000000:0;cd code/component-library\n"
            f": 1790000100:0;NPM_TOKEN={h.token('npm')} npm publish\n"
            f": 1790000200:0;vercel deploy --prod --token {h.chars(24)}\n"
            f": 1790000300:0;git clone https://{h.token('github')}@github.example.invalid/corp/private-ui.git\n"
            f": 1790000400:0;export OPENAI_API_KEY={h.token('openai')}\n"
            ": 1790000500:0;pnpm install\n: 1790000600:0;npm run build\n",
            "npm token given to 'npm publish'", WORTH, "a real token typed into the shell", mode=0o600)
    h.expect(".zsh_history", "Vercel token given to '--token'", WORTH, "a real token typed into the shell")
    h.expect(".zsh_history", "GitHub token in a clone URL", WORTH, "a real token typed into the shell")
    h.expect(".zsh_history", "OpenAI key exported in the shell", WORTH, "a real key typed into the shell")
    h.plant(".zshrc", 'export NVM_DIR="$HOME/.nvm"\nexport PNPM_HOME="$HOME/Library/pnpm"\n',
            "startup file with no secret", HIDDEN, "holds no credential")


def bulk(h):
    for name in PROJECTS:
        project = f"code/{name}"
        if name != "web-storefront":
            h.repo(project, f"git@github.com:corp/{name}.git")
        else:
            h.put(f"{project}/.gitignore", ".env*\nnode_modules/\n.next/\n")
        h.json(f"{project}/package.json", {"name": name, "private": True, "scripts": {"build": "build"}})
        h.put(f"{project}/package-lock.json", "".join(
            f'    "node_modules/pkg-{n}": {{ "integrity": "sha512-{h.chars(86)}==" }},\n' for n in range(400)))
        h.tree(f"{project}/src", 120, (".ts", ".tsx", ".css"), 4)
        h.tree(f"{project}/dist/assets", 60, (".js", ".map"), 2, 40)
        h.node_modules(project, 330)
    h.tree("code/web-storefront/.next/static/chunks", 250, (".js",), 2, 30)
    h.tree("code/web-storefront/.next/cache/webpack", 80, (".pack",), 2, 30)
    # A content-addressed package store keeps every file of every package
    # under a hash, test keys included, in a folder discovery does not skip.
    store = "Library/pnpm/store/v3/files"
    h.blobs(store, 9000)
    for _ in range(6):
        name = h.chars(62, "0123456789abcdef")
        h.plant(f"{store}/{name[:2]}/{name[2:]}", h.pem("RSA"), "test key of some package, in the pnpm store",
                HIDDEN, "published with a package; the developer never made or used it")
    h.tree(".nvm/versions/node/v20.11.1/include/node", 500, (".h",), 3, 6)
    h.node_modules(".nvm/versions/node/v20.11.1/lib", 150)
    h.tree(".vscode/extensions/dbaeumer.vscode-eslint-3.0.10/server/out", 600, (".js",), 3)
    h.tree("Library/Caches/Cypress/13.6.0", 1500, (".js",), 4, 4)
    h.tree("Library/Application Support/Code/CachedData", 800, (".code",), 2, 4)
