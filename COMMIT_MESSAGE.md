## Commit Message Requirements

- A commit message consists of a **title** and an optional **body**.

### 1. Commit Title Format

- The commit title must follow this format:

  ```text
  [type] short summary of main change [BREAK]
  ```

- `type` is enclosed in square brackets (`[` `]`) and describes the nature of the change. For example:

    - `[feature]` : new feature
    - `[fix]` : bug fix
    - `[docs]` : documentation changes
    - `[refactor]` : refactoring without behavior change
    - `[test]` : tests added or updated
    - `[chore]` : build, config, or other maintenance tasks

- You may introduce additional types if needed, following the same `[type]` pattern.
- The text after the type is a **concise, one-line summary of the most important change**.
- Keep the title **under 72 characters**.
- Use **present tense** in the title.
    - e.g. `add`, `fix`, `update`, `refactor` (not `added`, `fixed`)

### 2. BREAK Suffix

- If the commit introduces a **breaking change** (for example, variable renames, API signature changes, or anything that breaks backward compatibility), add the `[BREAK]` suffix at the end of the title.

  ```text
  [feature] add new auth middleware [BREAK]
  [refactor] rename core config struct [BREAK]
  ```

- If there is no breaking change, do **not** add `[BREAK]`.

### 3. Commit Body

- The commit body should **briefly describe the key changes in the edited files**.
- A bullet list is recommended:

  ```text
  - describe change 1
  - describe change 2
  - summarize changes per file or module
  ```

- Focus on **what changed and why**, rather than low-level implementation details.
- If there are security or privacy-related changes, explicitly mention them.

### 4. Examples

- Without breaking changes:

  ```text
  [feature] add support for local proxy client

  - add CLI flags for local proxy configuration
  - implement basic request forwarding logic
  - update documentation with usage examples
  ```

- With breaking changes (e.g., renaming variables or structures):

  ```text
  [refactor] rename db config fields for clarity [BREAK]

  - rename DSN to DatabaseURL in the config struct
  - update all references in store and CLI packages
  - adjust environment variable parsing logic
  ```

This guideline preserves the original project’s requirements (present tense, short main-change summary, explicit BREAK marking) while adapting the format to use `[type]` commit prefixes.