#!/usr/bin/env python3
import argparse
import logging
import logging.handlers
import os
import random
import re
import subprocess as sp
import sys
import time
import typing as tp
import urllib.parse

from requests import Response, Session
from requests.adapters import HTTPAdapter, Retry

GH_API_BASE = 'https://api.github.com'
BB_API_BASE = 'https://api.bitbucket.org/2.0'
GL_API_BASE = 'https://gitlab.com/api/v4'
DEFAULT_GIT_OP_TIMEOUT = 3600

next_page_re = re.compile(r'.*<(?P<next_url>[^>]+)>; rel="next".*')
last_page_re = re.compile(r'.*<(?P<next_url>[^>]+)>; rel="last".*')

git_suffix_re = re.compile(r'(.*?)(?:\.git)?$')
git_prefix_re = re.compile(r'^git@')
non_path_symbols_re = re.compile(r'[:\\?"\'<>|+%!@]+|\.\.')

git_op_timeout = DEFAULT_GIT_OP_TIMEOUT

http_session = Session()
http_session.mount(
    'https://',
    HTTPAdapter(max_retries=Retry(
        total=5,
        backoff_factor=0.1,
        status_forcelist=(429, 500, 501, 502, 503, 504),
        raise_on_redirect=False,
    ))
)


class Args(tp.NamedTuple):
    github: bool
    bitbucket: bool
    gitlab: bool

    gh_token: tp.Optional[str]
    bb_user: tp.Optional[str]
    bb_password: tp.Optional[str]
    gl_token: tp.Optional[str]

    backup_dir: str
    logs_dir: tp.Optional[str]


def main() -> None:
    args = get_args()
    setup_logging(args)

    were_errors = False
    repos = []
    if args.github:
        try:
            repos.extend(get_gh_repos_list(args.gh_token))
        except Exception as e:
            were_errors = True
            logging.exception(f'Error when requesting GitHub repos: {e}')

    if args.bitbucket:
        try:
            repos.extend(get_bb_repos_list(args.bb_user, args.bb_password))
        except Exception as e:
            were_errors = True
            logging.exception(f'Error when requesting BitBucket repos: {e}')

    if args.gitlab:
        try:
            repos.extend(get_gl_repos_list(args.gl_token))
        except Exception as e:
            were_errors = True
            logging.exception(f'Error when requesting GitLab repos: {e}')

    random.shuffle(repos)
    repos_count = len(repos)
    logging.info(f'Have {repos_count} repos to backup')

    for idx, git_url in enumerate(repos):
        cnt = idx + 1
        logging.info(f'Backing up [{cnt}/{repos_count}]: {git_url}')
        try:
            backup_repo(git_url, args.backup_dir)
            if cnt < repos_count:
                w_time = random.randint(1, 10)
                logging.info(f'Waiting for {w_time} seconds')
                time.sleep(w_time)
        except Exception as e:
            were_errors = True
            logging.exception(f'Unexpected error when handling repo {git_url}: {e}')

    if were_errors:
        sys.exit(1)


def get_args() -> Args:
    global git_op_timeout

    parser = argparse.ArgumentParser()
    parser.add_argument('--github', action='store_true')
    parser.add_argument('--bitbucket', action='store_true')
    parser.add_argument('--gitlab', action='store_true')
    parser.add_argument('--gh-token-file', default='~/.tokens/github-repos-list')
    parser.add_argument('--bb-auth-file', default='~/.tokens/bitbucket-repos-list')
    parser.add_argument('--gl-token-file', default='~/.tokens/gitlab-repos-list')
    parser.add_argument('--backup-dir', default='/tmp/gh-repos-backup')
    parser.add_argument('--git-op-timeout', type=int, default=DEFAULT_GIT_OP_TIMEOUT)
    parser.add_argument('--logs-dir')
    raw_args = parser.parse_args()

    if not (raw_args.github or raw_args.bitbucket or raw_args.gitlab):
        parser.error('At least one service should be selected')

    git_op_timeout = raw_args.git_op_timeout

    gh_token = None
    if raw_args.github:
        gh_token_file = os.path.expanduser(raw_args.gh_token_file)
        gh_token = read_text_file(gh_token_file)

    bb_user = bb_password = None
    if raw_args.bitbucket:
        bb_auth_file = os.path.expanduser(raw_args.bb_auth_file)
        bb_auth_data = read_text_file(bb_auth_file).splitlines()
        if len(bb_auth_data) < 2:
            raise Exception('BitBucket auth file should contain lines: <login>\\n<app_password>')
        bb_user = bb_auth_data[0].strip()
        bb_password = bb_auth_data[1].strip()

    gl_token = None
    if raw_args.gitlab:
        gl_token_file = os.path.expanduser(raw_args.gl_token_file)
        gl_token = read_text_file(gl_token_file)

    return Args(
        github=raw_args.github,
        bitbucket=raw_args.bitbucket,
        gitlab=raw_args.gitlab,

        gh_token=gh_token,
        bb_user=bb_user,
        bb_password=bb_password,
        gl_token=gl_token,

        backup_dir=os.path.expanduser(raw_args.backup_dir),
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


def read_text_file(file_path: str, error_message: str = 'File is required: {file}') -> str:
    if not os.path.exists(file_path):
        raise Exception(error_message.format(file=file_path))

    with open(file_path) as fp:
        return fp.read().strip()


def get_gh_repos_list(
    gh_token: str,
    query_params: tp.Optional[tp.Dict] = None,
) -> tp.List[str]:
    query_params = query_params or {}
    cur_page = unwrap_query_param(query_params.setdefault('page', '1'))

    query_params.setdefault('visibility', 'all')
    query_params.setdefault('per_page', '100')

    resp = make_gh_api_request(gh_token, '/user/repos', query_params=query_params)
    result = [x['ssh_url'] for x in resp.json()]

    if next_url_params := get_next_url_params_from_link(resp.headers.get('link')):
        if check_cur_page_is_last(next_url_params, cur_page):
            return result

        result.extend(get_gh_repos_list(gh_token, query_params={**query_params, **next_url_params}))

    return result


def unwrap_query_param(val: tp.Union[str, tp.List[str], None]) -> tp.Optional[str]:
    if val is None:
        return None

    if isinstance(val, (list, tuple)) and val:
        return val[0]

    return str(val)


def get_next_url_params_from_link(link_header: tp.Optional[str]) -> tp.Optional[tp.Dict]:
    if not link_header:
        return None

    next_url = None
    if matches := next_page_re.match(link_header):
        next_url = matches.group('next_url')
    elif matches := last_page_re.match(link_header):
        next_url = matches.group('next_url')

    if not next_url:
        return None

    next_url_data = urllib.parse.urlparse(next_url)
    return urllib.parse.parse_qs(next_url_data.query)


def check_cur_page_is_last(next_url_params: tp.Dict, cur_page: str) -> bool:
    return next_url_params.get('page', (cur_page,))[0] == cur_page


def make_gh_api_request(
    gh_token: str,
    handler: str,
    http_method: str = 'GET',
    query_params: tp.Optional[tp.Dict] = None,
    data: tp.Optional[tp.Dict] = None,
) -> Response:
    url_query = urllib.parse.urlencode(query_params or {}, doseq=True)
    resp = http_session.request(
        method=http_method,
        url=f'{GH_API_BASE}{handler}?{url_query}',
        headers={
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {gh_token}',
            'X-GitHub-Api-Version': '2022-11-28',
        },
        data=data,
    )
    resp.raise_for_status()
    return resp


def get_bb_repos_list(
    bb_user: str,
    bb_password: str,
    query_params: tp.Optional[tp.Dict] = None,
) -> tp.List[str]:
    query_params = query_params or {}
    query_params.setdefault('role', 'member')

    resp = make_bb_api_request(bb_user, bb_password, '/repositories', query_params=query_params)
    resp_json = resp.json()

    result = []
    for item in resp_json['values']:
        ssh_clone_link = None
        for link_data in item['links']['clone']:
            if link_data['name'] == 'ssh':
                ssh_clone_link = link_data['href']
                break

        if ssh_clone_link:
            result.append(ssh_clone_link)

    if next_link := resp_json.get('next'):
        next_url_data = urllib.parse.urlparse(next_link)
        next_url_params = urllib.parse.parse_qs(next_url_data.query)
        result.extend(get_bb_repos_list(
            bb_user,
            bb_password,
            query_params=next_url_params,
        ))

    return result


def make_bb_api_request(
    bb_user: str,
    bb_password: str,
    handler: str,
    http_method: str = 'GET',
    query_params: tp.Optional[tp.Dict] = None,
    data: tp.Optional[tp.Dict] = None,
) -> Response:
    url_query = urllib.parse.urlencode(query_params or {}, doseq=True)
    resp = http_session.request(
        method=http_method,
        url=f'{BB_API_BASE}{handler}?{url_query}',
        auth=(bb_user, bb_password),
        data=data,
    )
    resp.raise_for_status()
    return resp


def get_gl_repos_list(
    gl_token: str,
    query_params: tp.Optional[tp.Dict] = None,
) -> tp.List[str]:
    query_params = query_params or {}
    cur_page = unwrap_query_param(query_params.setdefault('page', '1'))

    query_params.setdefault('membership', 'true')
    query_params.setdefault('simple', 'true')
    query_params.setdefault('per_page', '100')
    query_params.setdefault('order_by', 'created_at')
    query_params.setdefault('sort', 'desc')

    resp = make_gl_api_request(gl_token, '/projects', query_params=query_params)
    result = [x['ssh_url_to_repo'] for x in resp.json()]

    if next_url_params := get_next_url_params_from_link(resp.headers.get('link')):
        if check_cur_page_is_last(next_url_params, cur_page):
            return result

        result.extend(get_gl_repos_list(gl_token, query_params={**query_params, **next_url_params}))

    return result


def make_gl_api_request(
    gl_token: str,
    handler: str,
    http_method: str = 'GET',
    query_params: tp.Optional[tp.Dict] = None,
    data: tp.Optional[tp.Dict] = None,
) -> Response:
    url_query = urllib.parse.urlencode(query_params or {}, doseq=True)
    resp = http_session.request(
        method=http_method,
        url=f'{GL_API_BASE}{handler}?{url_query}',
        headers={'PRIVATE-TOKEN': gl_token},
        data=data,
    )
    resp.raise_for_status()
    return resp


def backup_repo(git_url: str, backup_dir: str) -> None:
    start_time = time.perf_counter()

    url_data = urllib.parse.urlparse(f'ssh://{git_url}')
    host_data = git_prefix_re.sub('', url_data.netloc).split(':', 1)

    host, user_name = host_data[0], 'unknown'
    if len(host_data) > 1:
        host, user_name = host_data[0], host_data[1]
    last_path_part = git_suffix_re.sub(r'\1', url_data.path)[1:]

    repo_dir = non_path_symbols_re.sub('_', os.path.join(backup_dir, host, user_name, last_path_part))
    logging.info(f'Using dir: {repo_dir}')

    is_new_repo = not os.path.exists(repo_dir)
    os.makedirs(repo_dir, exist_ok=True)
    if is_new_repo:
        sp.check_call(('git', 'clone', '--recurse-submodules', '--mirror', git_url, repo_dir), timeout=git_op_timeout)
    sp.check_call(('git', 'fetch', '--all', '--recurse-submodules', '--tags'), cwd=repo_dir, timeout=git_op_timeout)

    backup_time = time.perf_counter() - start_time
    logging.info(f'Backup time: {backup_time}')


if __name__ == '__main__':
    main()
