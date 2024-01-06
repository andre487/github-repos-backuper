#!/usr/bin/env python3
import argparse
import logging
import logging.handlers
import os
import random
import re
import subprocess as sp
import time
import typing as tp
import urllib.parse

import requests

GH_API_BASE = 'https://api.github.com'
GIT_OP_TIMEOUT = 1800

next_page_re = re.compile(r'.*<(?P<next_url>[^>]+)>; rel="next".*')
git_suffix_re = re.compile(r'(.*)(?:\.git)?$')
non_path_symbols_re = re.compile(r'[:\\?"\'<>|+%!@]+|\.\.')


class Args(tp.NamedTuple):
    gh_token_file: str
    gh_token: str

    backup_dir: str
    include_private: bool

    logs_dir: tp.Optional[str]


def main() -> None:
    args = get_args()
    setup_logging(args)

    repos = get_gh_repos_list(args.gh_token, include_private=args.include_private)

    repos_count = len(repos)
    logging.info(f'Have {repos_count} repos to backup')

    last_repo = repos_count - 1
    for idx, git_url in enumerate(repos):
        try:
            backup_repo(git_url, args.backup_dir)
            if idx < last_repo:
                w_time = random.randint(1, 10)
                logging.info(f'Waiting for {w_time} seconds…')
                time.sleep(w_time)
        except Exception as e:
            logging.exception(f'Unexpected error when handling repo {git_url}: {e}')


def get_args() -> Args:
    parser = argparse.ArgumentParser()
    parser.add_argument('--gh-token-file', default='~/.tokens/github-repos-list')
    parser.add_argument('--backup-dir', default='/tmp/gh-repos-backup')
    parser.add_argument('--no-private', action='store_true')
    parser.add_argument('--logs-dir')
    raw_args = parser.parse_args()

    gh_token_file = os.path.expanduser(raw_args.gh_token_file)
    return Args(
        gh_token_file=gh_token_file,
        gh_token=read_text_file(gh_token_file),
        backup_dir=os.path.expanduser(raw_args.backup_dir),
        include_private=(not raw_args.no_private),
        logs_dir=raw_args.logs_dir,
    )


def setup_logging(args: Args) -> None:
    log_handlers = [logging.StreamHandler()]
    if args.logs_dir:
        log_handlers.append(logging.handlers.RotatingFileHandler(
            filename=os.path.join(args.logs_dir, 'github-repos-backup.log'),
            maxBytes=1024 * 1024,
            backupCount=1,
        ))

    logging.basicConfig(
        format='%(asctime)s\t%(levelname)s\t%(message)s',
        level=logging.INFO,
        handlers=log_handlers,
    )


def read_text_file(file_path: str) -> str:
    with open(file_path) as fp:
        return fp.read().strip()


def get_gh_repos_list(
    gh_token: str,
    include_private: bool = True,
    query_params: tp.Optional[tp.Dict] = None,
) -> tp.List[str]:
    query_params = query_params or {}
    query_params.setdefault('visibility', 'all' if include_private else 'public')
    query_params.setdefault('per_page', '100')
    query_params.setdefault('page', '1')

    resp = make_gh_api_request(gh_token, '/user/repos', query_params=query_params)
    result = [x['ssh_url'] for x in resp.json()]

    if next_matches := next_page_re.match(resp.headers.get('link', '')):
        next_url_data = urllib.parse.urlparse(next_matches.group('next_url'))
        next_url_params = urllib.parse.parse_qs(next_url_data.query)
        result.extend(
            get_gh_repos_list(gh_token, include_private=include_private, query_params={'page': next_url_params['page']})
        )

    return result


def make_gh_api_request(
    gh_token: str,
    handler: str,
    http_method: str = 'GET',
    query_params: tp.Optional[tp.Dict] = None,
    data: tp.Optional[tp.Dict] = None,
) -> requests.Response:
    url_query = urllib.parse.urlencode(query_params or {}, doseq=True)
    api_url = f'{GH_API_BASE}{handler}?{url_query}'
    resp = requests.request(
        method=http_method,
        url=api_url,
        headers={
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {gh_token}',
            'X-GitHub-Api-Version': '2022-11-28',
        },
        data=data,
    )
    resp.raise_for_status()
    return resp


def backup_repo(git_url: str, backup_dir: str) -> None:
    logging.info(f'Backing up {git_url}…')
    start_time = time.perf_counter()

    url_data = urllib.parse.urlparse(f'ssh://{git_url}')
    repo_dir = non_path_symbols_re.sub(
        '_',
        os.path.join(
            backup_dir,
            url_data.netloc,
            git_suffix_re.sub(r'\1', url_data.path)[1:]
        )
    )
    logging.info(f'Using dir {repo_dir}')

    is_new_repo = not os.path.exists(repo_dir)
    os.makedirs(repo_dir, exist_ok=True)
    if is_new_repo:
        sp.check_call(('git', 'clone', '--recurse-submodules', '--mirror', git_url, repo_dir), timeout=GIT_OP_TIMEOUT)
    sp.check_call(('git', 'fetch', '--all', '--recurse-submodules', '--tags'), cwd=repo_dir, timeout=GIT_OP_TIMEOUT)

    backup_time = time.perf_counter() - start_time
    logging.info(f'Backup time: {backup_time}')


if __name__ == '__main__':
    main()
