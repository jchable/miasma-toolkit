@{
  # ============================================================================
  #  iocs.psd1 — single source of truth for Miasma / Shai-Hulud indicators.
  #  Pure data file: loaded with Import-PowerShellDataFile (no code execution).
  #  Edit IOCs HERE only; Scan-Miasma.ps1 imports this and falls back to inline
  #  defaults if the file is missing.
  # ============================================================================

  # Known SHA-256 of the obfuscated dropper payload across observed waves.
  PayloadShas = @(
    '7711CC635948D9C8F661FB91D5E226642F695AF3B82F44343F6821D8FE504668', # local variant
    'D630397DE8B01AF0F6F5CF4463DA91B17F28195A2C50C8F3F38AD9F7873FDB8E', # icflorescu/taxepfa
    '3A9DB5BA0C8CD4C91E91717DF6B1A141FC1E0FBC0558B5A78D7F5C23F5B2A150', # Azure/durabletask
    '633C8410EE0413CA4B090A19C30B20C03F31598C25247C484846FA34C1DF5B64', # payload _p
    'EF641E956F91D501B748085996303C96A64D67F63BFEEF0DDA175E5AA19CCA90'  # binding.gyp
  )

  # Bot identities the worm impersonates when forging the [skip ci] commit.
  # NOTE: only the github-actions bot addresses — never a real owner's email
  # (that produces false positives on legitimate commits).
  BadEmails = @(
    'github-actions@github.com',
    '41898282+github-actions@users.noreply.github.com'
  )

  # Literal content signatures of the worm body / loader (SimpleMatch).
  ContentSigs = @(
    '.github/setup.js',
    'getBunPath',
    'oven-sh/bun',
    'detectHardenRunner',
    '.sshu-setup',
    'createCommitOnBranch',
    'Runner.Worker',
    '169.254.169.254',
    'typeof Bun'
  )

  # Compromised npm packages (registry arm of the worm).
  BadNpm = @(
    '@vapi-ai/server-sdk',
    'ai-sdk-ollama',
    'autotel',
    'awaitly',
    'executable-stories',
    'node-env-resolver',
    'wrangler-deploy'
  )

  # AI-agent / IDE config files that, when referencing setup.js, are launchers.
  ConfigFiles = @(
    '.claude/settings.json',
    '.gemini/settings.json',
    '.cursor/rules/setup.mdc',
    '.vscode/tasks.json',
    'Gemfile'
  )

  # Regex matching an injected GitHub Actions workflow.
  WfSig = 'setup\.js|oven-sh|bun\.sh/install|node \.github|curl -fsSL https://bun|getBunPath'

  # Regex of worm IOCs expected inside a C:\ProgramData AI-tool config
  # (strong signal -> INFECTED). Generic "has a command" content alone is REVIEW.
  ProgramDataContentSig = 'setup\.js|\bbun\b|\.sshu|\\\.?b[-_]|\\Temp\\|fromCharCode|eval\('

  # CVE-2026-35603 — system AI-tool configs in C:\ProgramData.
  ProgramData = @(
    'C:\ProgramData\ClaudeCode\managed-settings.json',
    'C:\ProgramData\Cursor\hooks.json',
    'C:\ProgramData\openai\codex\config.toml',
    'C:\ProgramData\gemini-cli\system-defaults.json'
  )
}
