import getpass
import json
import os
import sys

import nox

nox.options.envdir = f'./.nox-{getpass.getuser()}'
nox.options.reuse_existing_virtualenvs = False
nox.options.sessions = ['linter']


def load_global_config():
    if sys.argv[-2] == '--' and len(sys.argv[-1]):
        return json.loads(sys.argv[-1])
    return {}


global_config = load_global_config()
if global_config.get('fast'):
    nox.options.reuse_venv = 'yes'
    nox.options.no_install = True


def add_session_config(func):
    '''Decorator to load the session config.

    Usage::

        @nox.session
        @load_session_config
        def my_session_func(session, config):
            pass

    Command line usage::

        nox -e my_session_name -- '{"option": value}'

    The session config must be a valid JSON dictionary of options.
    '''

    def wrapper(session):
        return func(session, global_config)

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    wrapper.__has_user_config__ = True
    return wrapper


def options(module, config):
    '''Return pytest options set.'''
    ret = [
        'python',
        '-m',
        'pytest',
        f'-r{config.get("summary", "x")}',
        f'--timeout={config.get("timeout", 60)}',
        '--basetemp',
        './log',
    ]
    if config.get('exitfirst', True):
        ret.append('--exitfirst')
    if config.get('verbose', True):
        ret.append('--verbose')
    if config.get('fail_on_warnings'):
        ret.insert(1, 'error')
        ret.insert(1, '-W')
    if config.get('pdb'):
        ret.append('--pdb')
    if config.get('tests_prefix'):
        module = f'{config["tests_prefix"]}/{module}'
    if config.get('sub'):
        module = f'{module}/{config["sub"]}'
    ret.append(module)
    return ret


def setup_venv_common(session, flavour='dev', config=None):
    if config is None:
        config = {}
    if not config.get('fast'):
        session.install('--upgrade', 'pip')
        session.install('-r', f'requirements.{flavour}.txt')
    return os.path.abspath(session.create_tmp())


def setup_venv_docs(session, config=None):
    tmpdir = setup_venv_common(session, flavour='docs', config=config)
    session.run('cp', '-a', 'docs', tmpdir, external=True)
    session.run('cp', '-a', 'examples', tmpdir, external=True)
    [
        session.run('cp', src, dst, external=True)
        for (src, dst) in (
            ('README.rst', f'{tmpdir}/docs/general.rst'),
            ('README.report.rst', f'{tmpdir}/docs/report.rst'),
            ('README.contribute.rst', f'{tmpdir}/docs/devcontribute.rst'),
            ('CHANGELOG.rst', f'{tmpdir}/docs/changelog.rst'),
        )
    ]
    return tmpdir


@nox.session
@add_session_config
def docs(session, config):
    '''Generate project docs.'''
    tmpdir = setup_venv_docs(session, config)
    cwd = os.path.abspath(os.getcwd())
    # man pages
    session.chdir(f'{tmpdir}/docs/')
    session.run('make', 'man', 'SPHINXOPTS="-W"', external=True)
    session.run('cp', '-a', 'man', f'{cwd}/docs/', external=True)
    # html
    session.chdir(f'{tmpdir}/docs/')
    session.run('make', 'html', 'SPHINXOPTS="-W"', external=True)
    session.run('cp', '-a', 'html', f'{cwd}/docs/', external=True)
    session.run('make', 'doctest', external=True)
    session.chdir(cwd)
    session.run('bash', 'util/aafigure_mapper.sh', external=True)
    #
    session.log('8<---------------------------------------------------------')
    session.log('compiled docs:')
    session.log(f'html pages -> {cwd}/docs/html')
    session.log(f'man pages -> {cwd}/docs/man')


@nox.session
@add_session_config
def linter(session, config):
    '''Run code checks and linters.'''
    setup_venv_common(session, config=config)
    if not config.get('fast'):
        session.install('pre-commit')
    session.run('pre-commit', 'run', '-a')
    with open('.mypy-check-paths', 'r') as f:
        session.run(
            'python',
            '-m',
            'mypy',
            *f.read().split(),
            env={'PYTHONPATH': os.getcwd()},
        )


@nox.session
def build(session):
    '''Run package build.'''
    session.install('build')
    session.install('twine')
    session.run('python', '-m', 'build')
    session.run('python', '-m', 'twine', 'check', 'dist/*')
