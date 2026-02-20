# Release Checklist

1. Run validation:
   - `npm run build`
   - `npm run smoke:security`
   - `npm run repo:check`
   - `npm run release:notes -- vX.Y.Z`
2. Verify signed catalogs:
   - `config/policy-catalog.v1.json`
   - `config/capability-catalog.v1.json`
   - `config/approval-policy-catalog.v1.json`
3. Confirm `.env.example` includes all required vars.
4. Review `README.md` control endpoints and behavior notes.
5. Tag release and publish changelog notes.
   - `git tag vX.Y.Z`
   - `git push origin vX.Y.Z`

## First GitHub publish

1. `git init`
2. `git add .`
3. `git commit -m "Initial Claw-EE release"`
4. Create empty GitHub repo, then:
   - `git branch -M main`
   - `git remote add origin <repo-url>`
   - `git push -u origin main`
