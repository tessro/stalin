# Agents

## Commits

Use atomic, [Conventional Commits](https://www.conventionalcommits.org/). If a change is breaking, use the `!` suffix and describe the required migration in both the commit body and your response.

## Dependencies

Always use the latest versions of packages.

## Compatibility

Backward compatibility is rarely needed. Prefer clean APIs over compatibility shims.

## Code quality

Never disable cargo or clippy checks (`#[allow(...)]`, `--cap-lints`, etc.). If a check is failing and you can't resolve it, ask the user.

## Configuration

- Prefer TOML for most things
- The main file should usually be `config.toml`
- User configuration should be in `~/.config/<name>/*`
- System configuration should be in `/etc/<name>/*`
