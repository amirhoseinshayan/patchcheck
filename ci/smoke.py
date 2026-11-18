"""Framework acceptance runner; preserve every real CLI code in a manifest.

Exit 0 means every step returned its expected code: fixture targets must stay
INCONCLUSIVE (40), and each real patch scenario must get its expected verdict.
"""
import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Real targets: patch (Git tag) -> expected verdict exit code.
SCENARIO_CONFIGS = {'tlvparse-file': {'correct': 0, 'incomplete': 10, 'regression': 20, 'new-issue': 10},
                    'giflib-file': {'correct': 0, 'incomplete': 10, 'regression': 20},
                    'libpng-file': {'correct': 0, 'incomplete': 10, 'regression': 20}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default='artifacts/smoke')
    parser.add_argument('--skip-tests', action='store_true')
    parser.add_argument('--include-image', action='store_true')
    args = parser.parse_args()
    root = Path(args.out).resolve()
    if root.exists() and any(root.iterdir()):
        raise SystemExit('Smoke output must be empty: ' + str(root))
    root.mkdir(parents=True, exist_ok=True)
    manifest = {'framework_smoke': 'running', 'steps': []}
    environment = {**os.environ, 'PATCHCHECK_INTEGRATION': '1', 'PYTHONPATH': str(ROOT / 'src')}

    def command(name, argv, expected=0):
        log = root / (name + '.log')
        with log.open('wb') as stream:
            process = subprocess.run(argv, cwd=ROOT, env=environment, stdout=stream, stderr=subprocess.STDOUT)
        result = {'name': name, 'command': argv, 'actual_exit_code': process.returncode,
                  'expected_exit_code': expected, 'log': log.name, 'passed': process.returncode == expected}
        manifest['steps'].append(result)
        (root / 'smoke-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        print(f'{name}: actual={process.returncode}, expected={expected}', flush=True)
        if not result['passed']:
            raise RuntimeError(f'{name} failed; see {log}')

    try:
        command('fixture-setup', [sys.executable, 'tools/setup_fixtures.py'])
        if not args.skip_tests:
            command('unit-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/unit', '-v'])
            command('integration-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/integration', '-v'])
        configs = {}
        for name in ('bytecount-stdin', 'bytecount-file', 'lineparse-argv', *SCENARIO_CONFIGS):
            value = json.loads((ROOT / 'configs' / (name + '.json')).read_text())
            value['source']['repo'] = str((ROOT / 'configs' / value['source']['repo']).resolve())
            value['corpus_dir'] = str(root / 'regressions' / name)
            for test in value['tests']:
                for field in ('input', 'oracle'):
                    test[field] = str((ROOT / 'configs' / test[field]).resolve())
            config = root / (name + '.json')
            config.write_text(json.dumps(value, indent=2) + '\n')
            configs[name] = config
            command(name + '-validate', [sys.executable, '-m', 'patchcheck', 'validate-config', str(config)])
            if name in SCENARIO_CONFIGS:
                continue
            command(name + '-run', [sys.executable, '-m', 'patchcheck', 'run', str(config), '--out', str(root / name)], 40)
        for name, scenarios in SCENARIO_CONFIGS.items():
            for candidate, expected in scenarios.items():
                command(f'{name}-{candidate}', [sys.executable, '-m', 'patchcheck', 'run', str(configs[name]),
                                                '--candidate', candidate, '--out', str(root / f'{name}-{candidate}')], expected)
        from patchcheck.bundle import make_bundle, reproduce
        from patchcheck.report import load_report

        # Known-patch-via-diff (CLI --patch flow): `git diff base correct` of the
        # giflib fixture is the *known* upstream fix for CVE-2016-3977, applied to
        # base through a diff file rather than a named tag. It must PASS (0). The
        # step name is honest: this is not a never-before-seen patch.
        known = root / 'known-patch-via-diff.diff'
        with known.open('wb') as stream:
            subprocess.run(['git', '-C', str(ROOT / '.fixture-repos/giflib'), 'diff', 'base', 'correct'],
                           check=True, stdout=stream)
        command('known-patch-via-diff', [sys.executable, '-m', 'patchcheck', 'run', str(configs['giflib-file']),
                                         '--patch', str(known), '--out', str(root / 'known-patch-via-diff')], 0)

        # An independent harmless --patch scenario on a *different* target: a fresh
        # diff on the bytecount fixture that changes the output of a valid input,
        # synthesized here rather than read from a known tag. The functional
        # regression must be detected through the independent oracle and yield 20;
        # the CLI keys on the diff *content*, never its file name.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(tmp)], check=True)
            subprocess.run(['git', '-C', str(tmp), 'config', 'user.email', 'smoke@example.invalid'], check=True)
            subprocess.run(['git', '-C', str(tmp), 'config', 'user.name', 'Smoke'], check=True)
            shutil.copytree(ROOT / 'targets/bytecount/base', tmp, dirs_exist_ok=True)
            subprocess.run(['git', '-C', str(tmp), 'add', '-A'], check=True)
            subprocess.run(['git', '-C', str(tmp), 'commit', '-qm', 'base'], check=True)
            source = tmp / 'main.c'
            source.write_text(source.read_text().replace('fputs("OK\\n", stdout); return 0;',
                                                         'fputs("CHANGED\\n", stdout); return 0;'))
            harmless = root / 'harmless-regression.diff'
            with harmless.open('wb') as stream:
                subprocess.run(['git', '-C', str(tmp), 'diff'], check=True, stdout=stream)
        command('patch-harmless-diff', [sys.executable, '-m', 'patchcheck', 'run', str(configs['bytecount-stdin']),
                                        '--patch', str(harmless), '--out', str(root / 'patch-harmless-diff')], 20)
        harmless_report = load_report(root / 'patch-harmless-diff' / 'report.json')
        if not any(f['status'] == 'Functional Regression' for f in harmless_report['findings']):
            raise RuntimeError('patch-harmless-diff did not detect the functional regression on a valid input')

        # A *fresh* functional-regression diff, synthesized at test time rather than
        # read from a known tag: add an off-by-one length check that blocks the
        # overflow but rejects the 32-byte boundary, so valid inputs regress.
        # The verdict must be 20 and must not depend on any file name or tag.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(tmp)], check=True)
            subprocess.run(['git', '-C', str(tmp), 'config', 'user.email', 'smoke@example.invalid'], check=True)
            subprocess.run(['git', '-C', str(tmp), 'config', 'user.name', 'Smoke'], check=True)
            shutil.copytree(ROOT / 'targets/tlvparse/base', tmp, dirs_exist_ok=True)
            subprocess.run(['git', '-C', str(tmp), 'add', '-A'], check=True)
            subprocess.run(['git', '-C', str(tmp), 'commit', '-qm', 'base'], check=True)
            source = tmp / 'tlvparse.c'
            text = source.read_text()
            text = text.replace('    memcpy(r->value, src, len);',
                                '    if (len >= MAX_VALUE)\n        return "value too long";\n'
                                '    memcpy(r->value, src, len);')
            source.write_text(text)
            fresh = root / 'fresh-regression.diff'
            with fresh.open('wb') as stream:
                subprocess.run(['git', '-C', str(tmp), 'diff'], check=True, stdout=stream)
        command('patch-fresh-regression', [sys.executable, '-m', 'patchcheck', 'run', str(configs['tlvparse-file']),
                                           '--patch', str(fresh), '--out', str(root / 'patch-fresh-regression')], 20)

        # Every real patch scenario must have auto-replayed its confirmed findings
        # (>=3 per cell) with a stable result, and auto-written a reproduction bundle.
        for name, scenarios in SCENARIO_CONFIGS.items():
            for candidate in scenarios:
                rep = load_report(root / f'{name}-{candidate}' / 'report.json')
                confirmed = [f for f in rep['findings'] if f['confirmation'] == 'confirmed']
                if confirmed:
                    if not rep['replays']:
                        raise RuntimeError(f'{name}-{candidate} did not auto-replay its confirmed findings')
                    if any(f['replay_stability'] != 'stable' for f in confirmed):
                        raise RuntimeError(f'{name}-{candidate} confirmed findings unstable after auto-replay')
                    if not rep['bundles']:
                        raise RuntimeError(f'{name}-{candidate} did not auto-write a reproduction bundle')

        # Fixture mechanism check: explicit replay, minimize and a portable bundle
        # round-trip (fixtures do not auto-replay, so this exercises those paths).
        fixture_report = root / 'bytecount-stdin/report.json'
        command('fixture-replay', [sys.executable, '-m', 'patchcheck', 'replay', str(fixture_report), '--test', 'marker', '--count', '3'], 40)
        command('fixture-minimize', [sys.executable, '-m', 'patchcheck', 'minimize', str(fixture_report), '--test', 'marker'], 40)
        command('fixture-regression-reload', [sys.executable, '-m', 'patchcheck', 'run', str(configs['bytecount-stdin']), '--out', str(root / 'regression-reload')], 40)
        fixture_latest = load_report(fixture_report)
        if not fixture_latest['minimized'] or not fixture_latest['minimized'][-1]['registered']:
            raise RuntimeError('fixture minimization did not register a validated regression')
        reloaded = load_report(root / 'regression-reload/report.json')
        generated = [p['generated_regression'] for p in reloaded['axes']['functional']['comparisons'] if 'generated_regression' in p]
        if len(generated) != 2 or any(r['status'] != 'pass' for r in generated):
            raise RuntimeError('fixture generated regression did not run in both build kinds')
        fixture_archive = make_bundle(fixture_report, root / 'reproduction.tar.gz', include_image=args.include_image)
        fixture_rebuilt = reproduce(fixture_archive, root / 'reproduced')
        if fixture_rebuilt['exit_code'] != 40 or fixture_rebuilt['technical_errors']:
            raise RuntimeError('portable fixture rebuild did not reproduce 40')

        # The same minimize -> register -> reload cycle on real targets.
        for name, test_id in (('tlvparse-file', 'poc-long-blob'), ('giflib-file', 'poc-bg-oob')):
            real_report = root / f'{name}-correct' / 'report.json'
            command(f'{name}-minimize', [sys.executable, '-m', 'patchcheck', 'minimize', str(real_report), '--test', test_id], 0)
            command(f'{name}-regression-reload', [sys.executable, '-m', 'patchcheck', 'run', str(configs[name]),
                                                  '--candidate', 'correct', '--out', str(root / f'{name}-regression-reload')], 0)
            if not load_report(real_report)['minimized'][-1]['registered']:
                raise RuntimeError(f'{name} minimization did not register a validated regression')
            real_generated = [p['generated_regression'] for p in
                              load_report(root / f'{name}-regression-reload/report.json')['axes']['functional']['comparisons']
                              if 'generated_regression' in p]
            if len(real_generated) != 2 or any(r['status'] != 'pass' for r in real_generated):
                raise RuntimeError(f'{name} generated regression did not run in both build kinds')

        # A real target's automatic bundle rebuilds and re-verifies offline. The
        # tlvparse incomplete-fix case (verdict 10) is the vulnerability-remains one.
        incomplete = load_report(root / 'tlvparse-file-incomplete/report.json')
        real_bundle = root / 'tlvparse-file-incomplete' / incomplete['bundles'][0]
        real_rebuilt = reproduce(real_bundle, root / 'real-reproduced')
        if real_rebuilt['exit_code'] != 10 or real_rebuilt['technical_errors']:
            raise RuntimeError('portable real-target rebuild did not reproduce the VULN_REMAINS result (10)')
        manifest['bundles'] = {'fixture_exit': fixture_rebuilt['exit_code'],
                               'real_target_exit': real_rebuilt['exit_code']}
        manifest['framework_smoke'] = 'passed'
        return 0
    except Exception as exc:
        manifest['framework_smoke'] = 'failed'
        manifest['error'] = str(exc)
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        (root / 'smoke-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
