# Identity configuration

Existing installations use `postgoose` when `RABBIT_IDENTITY_MODE` is absent. That adapter reads application-owned `Team` and `postgoose_user_teams` tables. Rabbit does not migrate those tables.

For a new standalone installation:

```sh
export RABBIT_IDENTITY_MODE=standalone
export DATABASE_URL='postgres://...'
export REDIS_URL='redis://...'
rabbit.go database migrate internal/database/migrations.sql
rabbit.go database bootstrap-team analytics 'Analytics' first-owner
rabbit.go server
```

The bootstrap command creates one team and its owner. Existing IDs or names fail without changing permissions. It requires operator access to the metadata database.

Standalone identities live in `rabbit_teams` and `rabbit_team_memberships`. Membership roles are `OWNER`, `ADMIN` and `MEMBER`. Disable a membership with `is_active=false`. The management API still requires a service token and scoped user/team headers.

Set `RABBIT_IDENTITY_MODE=postgoose` explicitly when deploying against the existing application schema. Startup checks the selected schema. It does not fall back to a different authority.

Each metadata database binds to one identity mode in `rabbit_identity_binding`. Existing unbound tokens, sessions or audit rows bind it to `postgoose`. A conflicting mode fails before token operations. Use a separate metadata database to adopt another authority. Changing the environment variable does not migrate identities or tokens.
