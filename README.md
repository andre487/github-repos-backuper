# GitHub repos backuper

Not only for GitHub. It supports BitBucket and GitLab as well.

This tool creates local mirrors of all repositories where you have a membership.

If you need more features or settings, you are welcome to send pull requests.

## Installation

### By Git

```shell
git clone git@github.com:andre487/github-repos-backuper.git
cd github-repos-backuper
pip3 install -r requirements.txt
```

### By curl

```shell
curl https://raw.githubusercontent.com/andre487/github-repos-backuper/main/github-repos-backup.py -o github-repos-backup.py
chmod +x github-repos-backup.py
curl https://raw.githubusercontent.com/andre487/github-repos-backuper/main/requirements.txt -o /tmp/github-repos-backup-requirements.txt
pip3 install -r /tmp/github-repos-backup-requirements.txt
```

## Usage

```
usage: github-repos-backup.py [-h] [--github] [--bitbucket] [--gitlab]
                              [--gh-token-file GH_TOKEN_FILE]
                              [--bb-auth-file BB_AUTH_FILE]
                              [--gl-token-file GL_TOKEN_FILE]
                              [--backup-dir BACKUP_DIR]
                              [--git-op-timeout GIT_OP_TIMEOUT]
                              [--logs-dir LOGS_DIR]

options:
  -h, --help            show this help message and exit
  --github              Backup GitHub (default: False)
  --bitbucket           Backup BitBucket (default: False)
  --gitlab              Backup GitLab (default: False)
  --gh-token-file GH_TOKEN_FILE
                        GitHub token file (default: ~/.tokens/github-repos-
                        list)
  --bb-auth-file BB_AUTH_FILE
                        ButBucket auth file. Format: "<login>\n<app_password>"
                        (default: ~/.tokens/bitbucket-repos-list)
  --gl-token-file GL_TOKEN_FILE
                        GitLab token file (default: ~/.tokens/gitlab-repos-
                        list)
  --backup-dir BACKUP_DIR
                        Directory where repos will be stored (default:
                        /tmp/gh-repos-backup)
  --git-op-timeout GIT_OP_TIMEOUT
                        Timeout for git calls (default: 300)
  --logs-dir LOGS_DIR   Optional directory for log files (default: None)
```

At least one of the services should be enabled: GitHub, BitBucket or GitLab.

The tool requires Git, Python 3.8 or higher and [requests](https://pypi.org/project/requests/) library.

## Credentials

### GitHub

The tool needs for GitHub token with permissions for repository list reading.

You can get this token in the settings, inside of [Personal access tokens](https://github.com/settings/tokens).

### BitBucket

The tool needs application password with permissions for repository list reading.

You can get this password in the settings, inside of [App passwords](https://bitbucket.org/account/settings/app-passwords/).

Resulting auth file should be like this:

```
MyLogin
MyAppPassword
```

### GitLab

The tool needs for GitHub token with permissions for repository list reading.

You can get this token in the settings, inside of [Access Tokens](https://gitlab.com/-/user_settings/personal_access_tokens).

### Common for Git operations

The tool uses SSH URLs for operations with repositories and relies on authentication by SSH keys.
So you should generate a key pair as described in the [documentation](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).

You should add a public key to services:

  * [GitHub](https://github.com/settings/keys)
  * [BitBucket](https://bitbucket.org/account/settings/ssh-keys/)
  * [GitLab](https://gitlab.com/-/profile/keys)
